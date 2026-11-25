using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace CardControl.Api.Tests;

/// <summary>The partner's side of the encryption, with knobs for producing bad input.</summary>
internal static class TestJwe
{
    public static string Header(string kid) => $$"""{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"{{kid}}"}""";

    public static string Encrypt(
        string plaintext, RSA key, string kid, string? header = null, RSAEncryptionPadding? padding = null)
    {
        var encodedHeader = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header ?? Header(kid)));
        var cek = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(12);
        var plain = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plain.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(cek, 16);
        aes.Encrypt(iv, plain, ciphertext, tag, Encoding.ASCII.GetBytes(encodedHeader));

        return string.Join('.', encodedHeader,
            Base64Url.EncodeToString(key.Encrypt(cek, padding ?? RSAEncryptionPadding.OaepSHA256)),
            Base64Url.EncodeToString(iv),
            Base64Url.EncodeToString(ciphertext),
            Base64Url.EncodeToString(tag));
    }

    public static string EditSegment(string jwe, int index, Func<byte[], byte[]> edit)
    {
        var parts = jwe.Split('.');
        parts[index] = Base64Url.EncodeToString(edit(Base64Url.DecodeFromChars(parts[index])));
        return string.Join('.', parts);
    }

    public static byte[] FlipBit(byte[] bytes)
    {
        bytes[0] ^= 1;
        return bytes;
    }
}
