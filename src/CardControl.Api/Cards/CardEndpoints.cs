using System.Globalization;
using System.Text.Json;
using CardControl.Api.Downstream;
using CardControl.Api.Security;

namespace CardControl.Api.Cards;

public enum CardAction { Lock, Unlock }

public sealed record CardActionRequest(string? EncryptedPan, string? CorporateId);

public sealed record CardActionResponse(string CorporateId, string Status, DateTimeOffset UpdatedAt);

public static class CardEndpoints
{
    private const int MaxInitiatingUserLength = 128; // card platform limit
    private const int MaxCorporateIdLength = 64;

    private static readonly JsonSerializerOptions RequestJson = new(JsonSerializerDefaults.Web)
    {
        AllowDuplicateProperties = false,
    };

    public static void MapCardEndpoints(this IEndpointRouteBuilder app)
    {
        var cards = app.MapGroup("/v1/cards").RequireAuthorization(Policies.CardControlWrite);
        cards.MapPost("/lock", (HttpContext ctx, CardControlService service) => HandleAsync(ctx, service, CardAction.Lock));
        cards.MapPost("/unlock", (HttpContext ctx, CardControlService service) => HandleAsync(ctx, service, CardAction.Unlock));
    }

    private static async Task<IResult> HandleAsync(HttpContext ctx, CardControlService service, CardAction action)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        try
        {
            // The policy guarantees exactly one non-empty azp.
            var clientId = ctx.User.FindFirst("azp")!.Value;
            var initiatingUser = ReadInitiatingUser(ctx.Request);
            var body = await ReadBodyAsync(ctx);

            if (string.IsNullOrWhiteSpace(body.EncryptedPan))
                throw ApiException.InvalidRequest("'encryptedPan' is required.");
            if (string.IsNullOrWhiteSpace(body.CorporateId) || body.CorporateId.Length > MaxCorporateIdLength)
                throw ApiException.InvalidRequest($"'corporateId' is required (max {MaxCorporateIdLength} characters).");

            return Results.Ok(await service.ChangeAsync(
                new CardChange(clientId, initiatingUser, body.CorporateId, body.EncryptedPan, action),
                ctx.RequestAborted));
        }
        catch (ApiException ex)
        {
            if (ex.Status == StatusCodes.Status503ServiceUnavailable)
                ctx.Response.Headers.RetryAfter = "5";

            return Results.Problem(
                title: ex.Code,
                detail: ex.Detail,
                statusCode: ex.Status,
                extensions: new Dictionary<string, object?> { ["code"] = ex.Code });
        }
    }

    private static string ReadInitiatingUser(HttpRequest request)
    {
        var values = request.Headers["X-Initiating-User"];
        var user = values.Count == 1 ? values[0]?.Trim() : null;

        // Control and format characters (newlines, bidi overrides) would let an ID forge or disguise an audit entry.
        // A PAN here would end up in the audit trail, so it is refused too.
        if (string.IsNullOrEmpty(user)
            || user.Length > MaxInitiatingUserLength
            || user.Any(c => char.GetUnicodeCategory(c) is UnicodeCategory.Control or UnicodeCategory.Format
                or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
            || PanRedactor.Redact(user) != user)
        {
            throw ApiException.InvalidRequest(
                $"Exactly one valid 'X-Initiating-User' header is required (max {MaxInitiatingUserLength} characters).");
        }

        return user;
    }

    // Read by hand rather than through model binding: binding failures are logged and described by the framework
    // using request content, and a request body could contain a PAN if the partner gets it wrong.
    private static async Task<CardActionRequest> ReadBodyAsync(HttpContext ctx)
    {
        if (!ctx.Request.HasJsonContentType())
            throw new ApiException(415, "UnsupportedMediaType", "Content-Type must be application/json.");

        try
        {
            return await JsonSerializer.DeserializeAsync<CardActionRequest>(ctx.Request.Body, RequestJson, ctx.RequestAborted)
                ?? throw ApiException.InvalidRequest("The request body is required.");
        }
        catch (JsonException)
        {
            throw ApiException.InvalidRequest("The request body is not valid JSON for this operation.");
        }
        catch (BadHttpRequestException ex) when (ex.StatusCode == StatusCodes.Status413PayloadTooLarge)
        {
            throw new ApiException(413, "PayloadTooLarge", "The request body is too large.");
        }
        catch (BadHttpRequestException)
        {
            throw ApiException.InvalidRequest("The request body could not be read.");
        }
    }
}

public static class Policies
{
    public const string CardControlWrite = "CardControl.Write";
}
