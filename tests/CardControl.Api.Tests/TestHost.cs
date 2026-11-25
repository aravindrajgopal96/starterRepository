using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CardControl.Api.Tests;

[CollectionDefinition("starter kit")]
public sealed class StarterKitCollection : ICollectionFixture<StarterKit>;

/// <summary>Runs the real, unmodified starter kit services as child processes on free ports, plus a fresh bank key.</summary>
public sealed class StarterKit : IAsyncLifetime
{
    public const string Kid = "test-key-1";

    private readonly List<Process> _processes = [];
    private readonly string _keyDir = Directory.CreateTempSubdirectory("card-control-tests-").FullName;

    public RSA BankKey { get; } = RSA.Create(3072);
    public string KeyPath => Path.Combine(_keyDir, $"{Kid}.private.pem");
    public string IdpUrl { get; } = FreeUrl();
    public string TokenisationUrl { get; } = FreeUrl();
    public string CardPlatformUrl { get; } = FreeUrl();
    public HttpClient Http { get; } = new();

    public async Task InitializeAsync()
    {
        await File.WriteAllTextAsync(KeyPath, BankKey.ExportPkcs8PrivateKeyPem());
        Start("mock-identity-provider", "MockIdentityProvider", IdpUrl, "--Issuer", IdpUrl);
        Start("tokenisation-stub", "TokenisationStub", TokenisationUrl);
        Start("card-platform-stub", "CardPlatformStub", CardPlatformUrl);
        foreach (var url in new[] { IdpUrl, TokenisationUrl, CardPlatformUrl })
            await WaitUntilHealthy(url);
    }

    public Task DisposeAsync()
    {
        foreach (var process in _processes)
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
            process.Dispose();
        }
        Directory.Delete(_keyDir, recursive: true);
        return Task.CompletedTask;
    }

    public async Task<string> GetTokenAsync(
        string clientId = "partner-app", string audience = "api://card-control", int? lifetime = null)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = $"dev-only-{clientId}-secret",
            ["scope"] = $"{audience}/.default",
        };
        if (lifetime is not null)
            form["lifetime_seconds"] = lifetime.Value.ToString();

        using var response = await Http.PostAsync($"{IdpUrl}/oauth2/token", new FormUrlEncodedContent(form));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("access_token").GetString()!;
    }

    public async Task<JsonElement[]> AuditAsync() =>
        (await Http.GetFromJsonAsync<JsonElement[]>($"{CardPlatformUrl}/admin/audit"))!;

    public async Task SetFaultsAsync(int latencyMs, double errorRate) =>
        (await Http.PutAsJsonAsync($"{CardPlatformUrl}/admin/faults", new { latencyMs, errorRate })).EnsureSuccessStatusCode();

    public async Task ResetAsync()
    {
        (await Http.PostAsync($"{CardPlatformUrl}/admin/reset", null)).EnsureSuccessStatusCode();
        (await Http.PostAsync($"{TokenisationUrl}/admin/reset", null)).EnsureSuccessStatusCode();
    }

    private void Start(string folder, string assembly, string url, params string[] extraArgs)
    {
        // This assembly is in <root>/tests/<project>/bin/<configuration>/net10.0; the stubs are built alongside it.
        var output = new DirectoryInfo(AppContext.BaseDirectory);
        var root = output.Parent!.Parent!.Parent!.Parent!.Parent!.FullName;
        var directory = Path.Combine(root, folder, "bin", output.Parent!.Name, output.Name);
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = directory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in (string[])[Path.Combine(directory, $"{assembly}.dll"), "--urls", url, .. extraArgs])
            start.ArgumentList.Add(arg);

        var process = Process.Start(start)!;
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        _processes.Add(process);
    }

    private async Task WaitUntilHealthy(string url)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            try
            {
                if ((await Http.GetAsync($"{url}/healthz")).IsSuccessStatusCode)
                    return;
            }
            catch (HttpRequestException)
            {
            }
            await Task.Delay(100);
        }
        throw new TimeoutException($"{url} did not start.");
    }

    public static string FreeUrl()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}";
    }
}

/// <summary>The real API, wired to the starter kit, with every log at Trace captured before redaction.</summary>
public sealed class ApiFactory(
    StarterKit kit,
    Action<IServiceCollection>? services = null,
    Dictionary<string, string>? settings = null) : WebApplicationFactory<Program>
{
    public CapturedLogs Logs { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.UseSetting("Auth:Authority", kit.IdpUrl);
        builder.UseSetting("Downstream:TokenisationUrl", kit.TokenisationUrl);
        builder.UseSetting("Downstream:CardPlatformUrl", kit.CardPlatformUrl);
        builder.UseSetting("PanDecryption:Keys:0:Kid", StarterKit.Kid);
        builder.UseSetting("PanDecryption:Keys:0:PrivateKeyPath", kit.KeyPath);
        foreach (var category in new[] { "Default", "Microsoft.AspNetCore", "System.Net.Http", "Polly" })
            builder.UseSetting($"Logging:LogLevel:{category}", "Trace");
        foreach (var (key, value) in settings ?? [])
            builder.UseSetting(key, value);

        builder.ConfigureTestServices(s =>
        {
            // ClearProviders in Program runs before this, so the capture survives.
            s.AddSingleton<ILoggerProvider>(Logs);
            services?.Invoke(s);
        });
    }
}

public sealed class CapturedLogs : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _lines = new();

    public string Text => string.Join('\n', _lines);

    public ILogger CreateLogger(string categoryName) => new Logger(categoryName, _lines);

    public void Dispose()
    {
    }

    private sealed class Logger(string category, ConcurrentQueue<string> lines) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            lines.Enqueue($"{logLevel} {category} {formatter(state, exception)} {exception}");
    }
}

public sealed class FakeHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    private int _calls;

    public int Calls => _calls;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);
        return respond(request);
    }
}

[Collection("starter kit")]
public abstract class ApiTest(StarterKit kit) : IAsyncLifetime
{
    protected const string ActivePan = "4111111111111111"; // CORP-1001
    protected const string LockedPan = "4242424242424242"; // CORP-1001
    protected const string ActivePan2 = "4012888888881881"; // CORP-2002
    protected const string CancelledPan = "4000056655665556"; // CORP-2002
    protected const string OtherCorporatePan = "4000002500003155"; // CORP-3003
    protected const string NoCorporatePan = "4000000000003220";
    protected const string UnknownPan = "5555555555554444";
    protected const string User = "jane.smith@acme.example";

    protected StarterKit Kit => kit;

    public Task InitializeAsync() => kit.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    protected string Encrypt(string pan) => TestJwe.Encrypt(pan, kit.BankKey, StarterKit.Kid);

    protected async Task<ApiResult> CallAsync(
        ApiFactory api, string action = "lock", string pan = ActivePan, string corporateId = "CORP-1001",
        string? token = null, string[]? users = null, string? jwe = null, HttpContent? content = null)
    {
        using var client = api.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/v1/cards/{action}")
        {
            Content = content ?? JsonContent.Create(new { encryptedPan = jwe ?? Encrypt(pan), corporateId }),
        };
        token ??= await kit.GetTokenAsync();
        if (token.Length > 0)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        foreach (var user in users ?? [User])
            request.Headers.TryAddWithoutValidation("X-Initiating-User", user);

        using var response = await client.SendAsync(request);
        return new ApiResult(response.StatusCode, await response.Content.ReadAsStringAsync(),
            response.Content.Headers.ContentType?.MediaType);
    }

    protected static void AssertError(ApiResult result, int status, string code)
    {
        Assert.Equal((status, code), ((int)result.Status, result.Code));
        Assert.Equal("application/problem+json", result.MediaType);
    }
}

public sealed record ApiResult(HttpStatusCode Status, string Body, string? MediaType)
{
    public JsonElement Json => JsonDocument.Parse(Body).RootElement;
    public string? Code => Body.Length > 0 && Json.TryGetProperty("code", out var code) ? code.GetString() : null;
}
