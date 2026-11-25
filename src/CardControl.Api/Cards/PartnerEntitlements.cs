using Microsoft.Extensions.Options;

namespace CardControl.Api.Cards;

public sealed class PartnerOptions
{
    public string[] Corporates { get; set; } = [];
}

/// <summary>Which corporates each partner is enabled for, keyed by the token's client ID (azp). Unknown partners get nothing.</summary>
public sealed class PartnerEntitlements(IOptions<Dictionary<string, PartnerOptions>> partners)
{
    private readonly Dictionary<string, HashSet<string>> _corporates = partners.Value.ToDictionary(
        p => p.Key,
        p => p.Value.Corporates.ToHashSet(StringComparer.Ordinal),
        StringComparer.Ordinal);

    public bool IsEnabled(string clientId, string corporateId) =>
        _corporates.TryGetValue(clientId, out var corporates) && corporates.Contains(corporateId);
}
