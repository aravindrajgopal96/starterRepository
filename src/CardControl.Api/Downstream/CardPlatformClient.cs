using System.Net;
using CardControl.Api.Cards;

namespace CardControl.Api.Downstream;

public sealed record PlatformCard(string? CorporateId, string Status, DateTimeOffset UpdatedAt);

public sealed class CardPlatformClient(IHttpClientFactory clients, ILogger<CardPlatformClient> logger)
{
    /// <summary>Retried: reads are idempotent.</summary>
    public const string ReadClientName = "card-platform-read";

    /// <summary>Never retried: a lock or unlock that timed out may have been applied and audited.</summary>
    public const string WriteClientName = "card-platform-write";

    private sealed record ChangeBody(string InitiatingUser, string Channel);

    public async Task<PlatformCard> GetCardAsync(string cardToken, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"cards/{Uri.EscapeDataString(cardToken)}");
        using var response = await DownstreamHttp.SendReadAsync(clients.CreateClient(ReadClientName), request, logger, ct);

        if (response.StatusCode == HttpStatusCode.OK && await DownstreamHttp.TryReadAsync<PlatformCard>(response) is { } card)
            return card;

        // Requires the code too, so a misrouted 404 isn't reported as a missing card.
        if (response.StatusCode == HttpStatusCode.NotFound && await DownstreamHttp.ReadErrorCodeAsync(response) == "CardNotFound")
            throw ApiException.CardNotFound();

        throw DownstreamHttp.UnexpectedRead(response.StatusCode, logger);
    }

    /// <summary>No cancellation token: once sent, a change is followed to its result or to the client timeout.</summary>
    public async Task<PlatformCard> ChangeAsync(string cardToken, CardAction action, string initiatingUser, string channel)
    {
        var verb = action == CardAction.Lock ? "lock" : "unlock";
        using var request = new HttpRequestMessage(HttpMethod.Post, $"cards/{Uri.EscapeDataString(cardToken)}/{verb}")
        {
            Content = JsonContent.Create(new ChangeBody(initiatingUser, channel)),
        };

        HttpResponseMessage response;
        try
        {
            response = await clients.CreateClient(WriteClientName).SendAsync(request);
        }
        catch (Exception ex) when (DownstreamHttp.IsTimeout(ex))
        {
            throw ApiException.OutcomeUnknown(504);
        }
        catch (HttpRequestException ex) when (ex.HttpRequestError is HttpRequestError.ConnectionError
            or HttpRequestError.NameResolutionError or HttpRequestError.SecureConnectionError)
        {
            throw ApiException.DownstreamUnavailable(); // never connected, so nothing was sent
        }
        catch (HttpRequestException)
        {
            throw ApiException.OutcomeUnknown(502);
        }

        using (response)
        {
            if (response.StatusCode == HttpStatusCode.OK)
            {
                var expected = action == CardAction.Lock ? "Locked" : "Active";
                return await DownstreamHttp.TryReadAsync<PlatformCard>(response) is { } card && card.Status == expected
                    ? card
                    : throw ApiException.OutcomeUnknown(502);
            }

            var code = await DownstreamHttp.ReadErrorCodeAsync(response);
            throw (response.StatusCode, code, action) switch
            {
                (HttpStatusCode.NotFound, "CardNotFound", _) => ApiException.CardNotFound(),
                (HttpStatusCode.Conflict, "CardAlreadyLocked", CardAction.Lock) => ApiException.CardAlreadyLocked(),
                (HttpStatusCode.Conflict, "CardNotLocked", CardAction.Unlock) => ApiException.CardNotLocked(),
                (HttpStatusCode.UnprocessableEntity, "CardCancelled", _) => ApiException.CardCancelled(),
                (HttpStatusCode.ServiceUnavailable, "ServiceUnavailable", _) => ApiException.DownstreamUnavailable(),
                ( >= HttpStatusCode.InternalServerError, _, _) => ApiException.OutcomeUnknown(502),
                _ => ApiException.DownstreamError(),
            };
        }
    }
}
