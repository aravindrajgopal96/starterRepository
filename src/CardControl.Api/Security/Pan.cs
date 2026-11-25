using System.Security.Cryptography;

namespace CardControl.Api.Security;

/// <summary>
/// A card number. Deliberately not a string: it has no public state to serialise or destructure,
/// prints as a placeholder, and is wiped from memory when disposed.
/// </summary>
public sealed class Pan : IDisposable
{
    private readonly byte[] _digits;

    private Pan(byte[] digits) => _digits = digits;

    /// <summary>ASCII digits. Only the tokenisation client should need these.</summary>
    internal ReadOnlySpan<byte> Digits => _digits;

    public static Pan? TryCreate(ReadOnlySpan<byte> utf8) => Luhn.IsPan(utf8) ? new Pan(utf8.ToArray()) : null;

    public override string ToString() => "[REDACTED PAN]";

    public void Dispose() => CryptographicOperations.ZeroMemory(_digits);
}

internal static class Luhn
{
    public static bool IsPan(ReadOnlySpan<byte> digits)
    {
        if (digits.Length is < 12 or > 19)
            return false;

        var sum = 0;
        for (var i = 0; i < digits.Length; i++)
        {
            var digit = digits[^(i + 1)] - '0';
            if (digit is < 0 or > 9)
                return false;
            if (i % 2 == 1 && (digit *= 2) > 9)
                digit -= 9;
            sum += digit;
        }
        return sum % 10 == 0;
    }
}
