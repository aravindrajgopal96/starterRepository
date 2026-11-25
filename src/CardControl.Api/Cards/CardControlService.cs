using CardControl.Api.Downstream;
using CardControl.Api.Security;

namespace CardControl.Api.Cards;

public sealed record CardChange(string ClientId, string InitiatingUser, string CorporateId, string EncryptedPan, CardAction Action);

public sealed class CardControlService(
    PartnerEntitlements entitlements,
    PanDecryptor decryptor,
    TokenisationClient tokenisation,
    CardPlatformClient cardPlatform,
    ILogger<CardControlService> logger)
{
    public async Task<CardActionResponse> ChangeAsync(CardChange change, CancellationToken ct)
    {
        // Cheapest check first: the PAN is not even decrypted for a corporate the partner isn't enabled for.
        if (!entitlements.IsEnabled(change.ClientId, change.CorporateId))
        {
            LogDenied(change, "CorporateNotEnabled", cardToken: null);
            throw ApiException.CorporateNotEnabled();
        }

        string cardToken;
        using (var pan = decryptor.Decrypt(change.EncryptedPan))
            cardToken = await tokenisation.TokeniseAsync(pan, ct);

        // The partner's corporateId is only a claim. The card platform's record decides, and it must match:
        // being enabled for both corporates doesn't make a CORP-2002 card a CORP-1001 card.
        // A card with no corporate never matches.
        var card = await cardPlatform.GetCardAsync(cardToken, ct);
        if (!string.Equals(card.CorporateId, change.CorporateId, StringComparison.Ordinal))
        {
            LogDenied(change, "CardNotInCorporate", cardToken);
            throw ApiException.CardNotFound();
        }

        // The card's status is deliberately not checked here: the platform must see (and audit) every attempt
        // on an entitled card, and it is the only place that can check the status without a race.
        try
        {
            // Last point at which to give up if the partner has gone away. After this, always see it through.
            ct.ThrowIfCancellationRequested();
            var updated = await cardPlatform.ChangeAsync(cardToken, change.Action, change.InitiatingUser, change.ClientId);

            logger.LogInformation("{Action} succeeded for {CardToken} in {CorporateId} by {ClientId}",
                change.Action, cardToken, change.CorporateId, change.ClientId);
            return new CardActionResponse(change.CorporateId, updated.Status, updated.UpdatedAt);
        }
        catch (ApiException ex)
        {
            logger.LogWarning("{Action} failed for {CardToken} in {CorporateId} by {ClientId}: {Code}",
                change.Action, cardToken, change.CorporateId, change.ClientId, ex.Code);
            throw;
        }
    }

    // Denied attempts never reach the card platform, so this log is the only record of who tried.
    private void LogDenied(CardChange change, string reason, string? cardToken) =>
        logger.LogWarning(
            "{Action} denied ({Reason}) for {CardToken} in {CorporateId} by {ClientId}, initiating user {InitiatingUser}",
            change.Action, reason, cardToken, PanRedactor.Redact(change.CorporateId), change.ClientId, change.InitiatingUser);
}
