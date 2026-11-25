using System.Net;
using System.Text.Json;
using CardControl.Api.Cards;
using Polly.Timeout;

namespace CardControl.Api.Downstream;

internal static class DownstreamHttp
{
    private sealed record ErrorBody(string? Code);

    /// <summary>
    /// Sends a request that does not change a card. Nothing from the exchange is logged except the status or
    /// exception type: error text from a service that receives PANs may contain one.
    /// </summary>
    public static async Task<HttpResponseMessage> SendReadAsync(
        HttpClient client, HttpRequestMessage request, ILogger logger, CancellationToken ct)
    {
        try
        {
            return await client.SendAsync(request, ct);
        }
        catch (Exception ex) when (IsTimeout(ex) && !ct.IsCancellationRequested)
        {
            logger.LogWarning("Downstream read timed out");
            throw ApiException.DownstreamTimeout();
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning("Downstream read failed: {Error}", ex.HttpRequestError);
            throw ApiException.DownstreamUnavailable();
        }
    }

    public static bool IsTimeout(Exception ex) => ex is TimeoutRejectedException or OperationCanceledException;

    /// <summary>A read that came back with a status we have no specific meaning for.</summary>
    public static ApiException UnexpectedRead(HttpStatusCode status, ILogger logger)
    {
        logger.LogError("Downstream read returned unexpected status {Status}", (int)status);
        return status == HttpStatusCode.ServiceUnavailable ? ApiException.DownstreamUnavailable() : ApiException.DownstreamError();
    }

    public static async Task<T?> TryReadAsync<T>(HttpResponseMessage response) where T : class
    {
        try
        {
            return await response.Content.ReadFromJsonAsync<T>(CancellationToken.None);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or NotSupportedException)
        {
            return null;
        }
    }

    public static async Task<string?> ReadErrorCodeAsync(HttpResponseMessage response) =>
        (await TryReadAsync<ErrorBody>(response))?.Code;
}
