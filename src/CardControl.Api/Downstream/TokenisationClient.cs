using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using CardControl.Api.Cards;
using CardControl.Api.Security;

namespace CardControl.Api.Downstream;

public sealed class TokenisationClient(IHttpClientFactory clients, ILogger<TokenisationClient> logger)
{
    public const string ClientName = "tokenisation";

    private sealed record TokenBody(string? CardToken);

    public async Task<string> TokeniseAsync(Pan pan, CancellationToken ct)
    {
        // Built as bytes so the PAN never becomes an immutable string. Pan guarantees ASCII digits, so no escaping is needed.
        byte[] json = [.. "{\"pan\":\""u8, .. pan.Digits, .. "\"}"u8];
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "tokens") { Content = new ByteArrayContent(json) };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            using var response = await DownstreamHttp.SendReadAsync(clients.CreateClient(ClientName), request, logger, ct);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                return await DownstreamHttp.TryReadAsync<TokenBody>(response) is { CardToken: { Length: > 0 } token }
                    ? token
                    : throw DownstreamHttp.UnexpectedRead(response.StatusCode, logger);
            }

            if (response.StatusCode == HttpStatusCode.BadRequest && await DownstreamHttp.ReadErrorCodeAsync(response) == "InvalidPan")
                throw ApiException.InvalidPan();

            throw DownstreamHttp.UnexpectedRead(response.StatusCode, logger);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
        }
    }
}
