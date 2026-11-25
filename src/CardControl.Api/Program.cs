using CardControl.Api.Cards;
using CardControl.Api.Downstream;
using CardControl.Api.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Logging.Console;
using Microsoft.IdentityModel.Tokens;
using Polly;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

builder.WebHost.ConfigureKestrel(o =>
{
    o.AddServerHeader = false;
    o.Limits.MaxRequestBodySize = 16 * 1024;
});

// The redacting console is the only log sink: the default debug/event log providers would bypass it.
builder.Logging.ClearProviders();
builder.Logging.AddConsole(o => o.FormatterName = RedactingJsonConsoleFormatter.FormatterName);
builder.Logging.AddConsoleFormatter<RedactingJsonConsoleFormatter, JsonConsoleFormatterOptions>(o =>
{
    o.IncludeScopes = true; // trace ID, as returned to the partner in error responses
    o.UseUtcTimestamp = true;
    o.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
});

// ---- Authentication and authorisation ----

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.Authority = Required("Auth:Authority");
        o.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        o.MapInboundClaims = false;
        o.IncludeErrorDetails = false;
        // Issuer and signing keys come from the authority's discovery document.
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = Required("Auth:Audience"),
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ClockSkew = TimeSpan.FromSeconds(30),
            RoleClaimType = "roles",
            NameClaimType = "azp",
        };
        o.Events = new JwtBearerEvents
        {
            // Type only: validation messages can quote the token. Distinguishes a bad token from an unreachable provider.
            OnAuthenticationFailed = ctx =>
            {
                ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>()
                    .LogWarning("Access token rejected: {Reason}", ctx.Exception.GetType().Name);
                return Task.CompletedTask;
            },
        };
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(Policies.CardControlWrite, p => p
        .RequireAuthenticatedUser()
        .RequireRole("CardControl.Write")
        .RequireAssertion(c => c.User.FindAll("azp").ToArray() is [{ Value.Length: > 0 }]))
    // Anything without its own policy needs the role as well, so a new endpoint is closed by default.
    .SetFallbackPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireRole("CardControl.Write").Build());

// ---- Application ----

builder.Services.Configure<Dictionary<string, PartnerOptions>>(config.GetSection("Partners"));
builder.Services.AddSingleton<PartnerEntitlements>();
builder.Services.AddSingleton(sp => new PanDecryptor(
    sp.GetRequiredService<IConfiguration>().GetSection(PanDecryptionOptions.Section).Get<PanDecryptionOptions>() ?? new(),
    builder.Environment.ContentRootPath));
builder.Services.AddScoped<CardControlService>();
builder.Services.AddScoped<TokenisationClient>();
builder.Services.AddScoped<CardPlatformClient>();

AddDownstream(TokenisationClient.ClientName, "Downstream:TokenisationUrl").AddResilienceHandler("read", RetryReads);
AddDownstream(CardPlatformClient.ReadClientName, "Downstream:CardPlatformUrl").AddResilienceHandler("read", RetryReads);
AddDownstream(CardPlatformClient.WriteClientName, "Downstream:CardPlatformUrl");

builder.Services.AddHealthChecks();
builder.Services.AddProblemDetails(o => o.CustomizeProblemDetails = ctx =>
{
    var status = ctx.ProblemDetails.Status ?? ctx.HttpContext.Response.StatusCode;
    ctx.ProblemDetails.Extensions.TryAdd("code", ReasonPhrases.GetReasonPhrase(status).Replace(" ", ""));
    ctx.ProblemDetails.Extensions.Remove("exception"); // never, even in Development
});

var app = builder.Build();

// Fail at start-up, not on the first request, if the keys or URLs are missing.
app.Services.GetRequiredService<PanDecryptor>();
app.Services.GetRequiredService<PartnerEntitlements>();
Required("Downstream:TokenisationUrl");
Required("Downstream:CardPlatformUrl");

app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/healthz").AllowAnonymous();
app.MapCardEndpoints();

app.Run();

string Required(string key) =>
    config[key] is { Length: > 0 } value ? value : throw new InvalidOperationException($"Configuration '{key}' is required.");

IHttpClientBuilder AddDownstream(string name, string urlKey) => builder.Services
    .AddHttpClient(name, client =>
    {
        client.BaseAddress = new Uri(Required(urlKey).TrimEnd('/') + "/");
        client.Timeout = TimeSpan.FromSeconds(10);
        client.MaxResponseContentBufferSize = 64 * 1024;
    })
    // A redirect must never take a PAN somewhere we didn't configure.
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(2),
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
    })
    .RemoveAllLoggers();

static void RetryReads(ResiliencePipelineBuilder<HttpResponseMessage> pipeline) => pipeline
    .AddTimeout(TimeSpan.FromSeconds(8))
    .AddRetry(new HttpRetryStrategyOptions
    {
        MaxRetryAttempts = 2,
        Delay = TimeSpan.FromMilliseconds(200),
        BackoffType = DelayBackoffType.Exponential,
        UseJitter = true,
    })
    .AddTimeout(TimeSpan.FromSeconds(3));
