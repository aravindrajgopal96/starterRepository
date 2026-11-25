using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CardControl.Api.Cards;

namespace CardControl.Api.Security;

public sealed class PanDecryptionOptions
{
    public const string Section = "PanDecryption";

    /// <summary>All currently accepted keys. More than one allows rotation.</summary>
    public KeyEntry[] Keys { get; set; } = [];

    public sealed class KeyEntry
    {
        public string Kid { get; set; } = "";

        /// <summary>PKCS#8 PEM, absolute or relative to the content root.</summary>
        public string PrivateKeyPath { get; set; } = "";
    }
}

/// <summary>
/// Decrypts the one JWE profile the partner uses: compact, RSA-OAEP-256, A256GCM, known kid.
/// The algorithms are fixed here and never negotiated from the header; anything else is rejected.
/// Every failure looks the same to the caller, and no exception detail escapes.
/// </summary>
public sealed class PanDecryptor : IDisposable
{
    private const int MaxLength = 4096;
    private const int IvLength = 12;
    private const int TagLength = 16;
    private const int CekLength = 32;

    private readonly Dictionary<string, RSA> _keys = new(StringComparer.Ordinal);

    public PanDecryptor(PanDecryptionOptions options, string contentRoot)
    {
        if (options.Keys.Length == 0)
            throw new InvalidOperationException("PanDecryption:Keys must contain at least one key.");

        foreach (var entry in options.Keys)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(Path.Combine(contentRoot, entry.PrivateKeyPath)));
            if (rsa.KeySize < 2048)
                throw new InvalidOperationException($"PAN decryption key '{entry.Kid}' is smaller than 2048 bits.");
            _keys.Add(entry.Kid, rsa);
        }
    }

    public Pan Decrypt(string jwe)
    {
        byte[]? cek = null, plaintext = null;
        try
        {
            if (jwe.Length > MaxLength || jwe.Split('.') is not [var header, var key, var ivPart, var body, var tagPart])
                throw ApiException.InvalidEncryptedPan();

            var rsa = SelectKey(header);
            var encryptedKey = Base64Url.DecodeFromChars(key);
            var iv = Base64Url.DecodeFromChars(ivPart);
            var ciphertext = Base64Url.DecodeFromChars(body);
            var tag = Base64Url.DecodeFromChars(tagPart);

            // Exact lengths matter: AES-GCM must not be allowed to accept a truncated tag.
            if (iv.Length != IvLength || tag.Length != TagLength || encryptedKey.Length != rsa.KeySize / 8)
                throw ApiException.InvalidEncryptedPan();

            // RSA instances are not documented as thread-safe.
            lock (rsa)
                cek = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
            if (cek.Length != CekLength)
                throw ApiException.InvalidEncryptedPan();

            plaintext = new byte[ciphertext.Length];
            using (var aes = new AesGcm(cek, TagLength))
                aes.Decrypt(iv, ciphertext, tag, plaintext, associatedData: Encoding.ASCII.GetBytes(header));

            return Pan.TryCreate(plaintext) ?? throw ApiException.InvalidPan();
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or JsonException)
        {
            throw ApiException.InvalidEncryptedPan();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private RSA SelectKey(string encodedHeader)
    {
        using var header = JsonDocument.Parse(
            Base64Url.DecodeFromChars(encodedHeader),
            new JsonDocumentOptions { AllowDuplicateProperties = false });

        if (header.RootElement.ValueKind != JsonValueKind.Object)
            throw ApiException.InvalidEncryptedPan();

        string? alg = null, enc = null, kid = null;
        foreach (var parameter in header.RootElement.EnumerateObject())
        {
            if (parameter.Value.ValueKind != JsonValueKind.String)
                throw ApiException.InvalidEncryptedPan();
            switch (parameter.Name)
            {
                case "alg": alg = parameter.Value.GetString(); break;
                case "enc": enc = parameter.Value.GetString(); break;
                case "kid": kid = parameter.Value.GetString(); break;
                case "typ" or "cty": break;
                // zip, crit, jwk, jku, epk... are all outside the agreed profile.
                default: throw ApiException.InvalidEncryptedPan();
            }
        }

        return alg == "RSA-OAEP-256" && enc == "A256GCM" && kid is not null && _keys.TryGetValue(kid, out var rsa)
            ? rsa
            : throw ApiException.InvalidEncryptedPan();
    }

    public void Dispose()
    {
        foreach (var rsa in _keys.Values)
            rsa.Dispose();
    }
}
