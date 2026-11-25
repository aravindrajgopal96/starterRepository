namespace CardControl.Api.Cards;

/// <summary>
/// An expected failure with a response the partner may see. Messages are fixed text chosen here:
/// never request content and never anything a downstream service returned.
/// </summary>
public sealed class ApiException(int status, string code, string detail) : Exception(code)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
    public string Detail { get; } = detail;

    public static ApiException InvalidRequest(string detail) => new(400, "InvalidRequest", detail);

    public static ApiException InvalidEncryptedPan() =>
        new(400, "InvalidEncryptedPan", "'encryptedPan' could not be decrypted. Expected a compact JWE using RSA-OAEP-256 and A256GCM with a current key.");

    public static ApiException InvalidPan() => new(400, "InvalidPan", "The decrypted value is not a valid card number.");

    public static ApiException CorporateNotEnabled() =>
        new(403, "CorporateNotEnabled", "The caller is not enabled for this corporate.");

    /// <summary>Also used when the card exists but is not the caller's, so card existence cannot be probed.</summary>
    public static ApiException CardNotFound() =>
        new(404, "CardNotFound", "No such card for this corporate.");

    public static ApiException CardAlreadyLocked() => new(409, "CardAlreadyLocked", "The card is already locked.");

    public static ApiException CardNotLocked() => new(409, "CardNotLocked", "The card is not locked.");

    public static ApiException CardCancelled() => new(422, "CardCancelled", "The card is cancelled; no changes are permitted.");

    public static ApiException DownstreamUnavailable() =>
        new(503, "ServiceUnavailable", "A required service is unavailable. The card was not changed. Retry later.");

    public static ApiException DownstreamTimeout() =>
        new(504, "UpstreamTimeout", "A required service did not respond in time. The card was not changed. Retry later.");

    public static ApiException DownstreamError() =>
        new(502, "UpstreamError", "A required service returned an unexpected response. The card was not changed.");

    /// <summary>The change was sent but its result is unknown.</summary>
    public static ApiException OutcomeUnknown(int status) =>
        new(status, "OutcomeUnknown", "The change may or may not have been applied. Retrying is safe: a 409 means the card is already in the requested state.");
}
