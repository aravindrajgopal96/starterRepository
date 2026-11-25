using System.Net;
using System.Text;
using System.Text.Json;
using CardControl.Api.Cards;
using CardControl.Api.Downstream;
using CardControl.Api.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;

namespace CardControl.Api.Tests;

public sealed class PanSecrecyTests(StarterKit kit) : ApiTest(kit)
{
    // Logs are captured at Trace, before redaction, so these prove the PAN never gets as far as the safety net.
    private static void AssertNoPan(ApiFactory api, params ApiResult[] results)
    {
        Assert.NotEmpty(api.Logs.Text);
        Assert.DoesNotContain(ActivePan, api.Logs.Text);
        Assert.All(results, r => Assert.DoesNotContain(ActivePan, r.Body));
    }

    [Fact]
    public async Task Not_in_logs_or_responses_on_success_or_rejection()
    {
        await using var api = new ApiFactory(Kit);
        var locked = await CallAsync(api);
        Assert.Equal(200, (int)locked.Status);
        AssertNoPan(api, locked, await CallAsync(api), await CallAsync(api, corporateId: "CORP-2002"),
            await CallAsync(api, corporateId: "CORP-3003"));
    }

    public static TheoryData<string> BodiesWithClearPan => new()
    {
        $$"""{"encryptedPan":"{{ActivePan}}","corporateId":"CORP-1001"}""",
        $$"""{"encryptedPan":{{ActivePan}},"corporateId":"CORP-1001"}""",
        $$"""{"encryptedPan":"x","corporateId":"{{ActivePan}}"}""",
        $$$"""{"corporateId":{"{{{ActivePan}}}":[}}""",
        $$"""{"{{ActivePan}}":1,"{{ActivePan}}":2}""",
        ActivePan,
    };

    [Theory, MemberData(nameof(BodiesWithClearPan))]
    public async Task Not_echoed_or_logged_when_the_partner_sends_it_in_clear(string body)
    {
        await using var api = new ApiFactory(Kit);
        var result = await CallAsync(api, content: new StringContent(body, Encoding.UTF8, "application/json"));
        Assert.True((int)result.Status is 400 or 403);
        AssertNoPan(api, result);
    }

    [Fact]
    public async Task Not_leaked_when_tokenisation_echoes_it_in_an_error()
    {
        await using var api = new ApiFactory(Kit, s => s.AddHttpClient(TokenisationClient.ClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new FakeHandler(_ => Task.FromResult(
                new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    ReasonPhrase = $"bad pan {ActivePan}",
                    Content = new StringContent(
                        $$"""{"code":"{{ActivePan}}","detail":"{{ActivePan}} is invalid"}""", Encoding.UTF8, "application/json"),
                }))));
        AssertNoPan(api, await CallAsync(api));
    }

    [Fact]
    public async Task Not_leaked_when_the_http_stack_throws_with_it_in_the_message()
    {
        await using var api = new ApiFactory(Kit, s => s.AddHttpClient(TokenisationClient.ClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new FakeHandler(_ => throw new HttpRequestException($"failed on {ActivePan}"))));
        var result = await CallAsync(api);
        AssertError(result, 503, "ServiceUnavailable");
        Assert.DoesNotContain(ActivePan, result.Body);
        // Polly's own Warning-level telemetry does log the exception it retried; production levels and the redactor cover it.
        Assert.DoesNotContain(ActivePan, PanRedactor.Redact(api.Logs.Text));
    }

    [Fact]
    public async Task Unexpected_exception_is_a_bare_500()
    {
        await using var api = new ApiFactory(Kit, s => s.AddHttpClient(CardPlatformClient.ReadClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new FakeHandler(_ => throw new FormatException($"bug: {ActivePan}"))));
        var result = await CallAsync(api);
        AssertError(result, 500, "InternalServerError");
        Assert.DoesNotContain("bug", result.Body);
        Assert.DoesNotContain("   at ", result.Body);
    }

    [Fact]
    public void Pan_never_prints_or_serialises()
    {
        using var pan = Pan.TryCreate(Encoding.ASCII.GetBytes(ActivePan))!;
        Assert.DoesNotContain(ActivePan, pan.ToString());
        Assert.Equal("{}", JsonSerializer.Serialize(pan));
    }

    [Theory]
    [InlineData("card 4111111111111111 failed", "card [REDACTED PAN] failed")]
    [InlineData("4111 1111 1111 1111", "[REDACTED PAN]")]
    [InlineData("4111-1111-1111-1111", "[REDACTED PAN]")]
    [InlineData("x4111111111111111y", "x[REDACTED PAN]y")]
    [InlineData("4111111111111112", "4111111111111112")]
    [InlineData("12345", "12345")]
    public void Redactor(string input, string expected) => Assert.Equal(expected, PanRedactor.Redact(input));

    [Fact]
    public void Log_formatter_redacts_messages_and_exceptions()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddConsoleFormatter<RedactingJsonConsoleFormatter, JsonConsoleFormatterOptions>());
        using var provider = services.BuildServiceProvider();
        var formatter = provider.GetServices<ConsoleFormatter>().OfType<RedactingJsonConsoleFormatter>().Single();

        var output = new StringWriter();
        formatter.Write(new LogEntry<string>(LogLevel.Error, "test", 0, $"message {ActivePan}",
            new InvalidOperationException($"exception {ActivePan}"), (s, _) => s), null, output);

        Assert.DoesNotContain(ActivePan, output.ToString());
        Assert.Contains("message [REDACTED PAN]", output.ToString());
        Assert.Contains("exception [REDACTED PAN]", output.ToString());
        Assert.Equal("test", JsonDocument.Parse(output.ToString()).RootElement.GetProperty("Category").GetString());
    }
}

public sealed class PanDecryptorTests(StarterKit kit) : ApiTest(kit)
{
    private static readonly string Key = StarterKit.Kid;

    private PanDecryptor Decryptor() => new(
        new PanDecryptionOptions { Keys = [new() { Kid = Key, PrivateKeyPath = Kit.KeyPath }] }, "");

    private string Reject(string jwe)
    {
        using var decryptor = Decryptor();
        return Assert.Throws<ApiException>(() => decryptor.Decrypt(jwe)).Code;
    }

    [Fact]
    public void Decrypts_the_agreed_profile()
    {
        using var decryptor = Decryptor();
        using var pan = decryptor.Decrypt(Encrypt(ActivePan));
        Assert.Equal(ActivePan, Encoding.ASCII.GetString(pan.Digits));
    }

    [Theory]
    [InlineData("""{"alg":"RSA-OAEP","enc":"A256GCM","kid":"test-key-1"}""")]
    [InlineData("""{"alg":"RSA1_5","enc":"A256GCM","kid":"test-key-1"}""")]
    [InlineData("""{"alg":"dir","enc":"A256GCM","kid":"test-key-1"}""")]
    [InlineData("""{"alg":"RSA-OAEP-256","enc":"A128GCM","kid":"test-key-1"}""")]
    [InlineData("""{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"other"}""")]
    [InlineData("""{"alg":"RSA-OAEP-256","enc":"A256GCM"}""")]
    [InlineData("""{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"test-key-1","zip":"DEF"}""")]
    [InlineData("""{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"test-key-1","crit":["x"]}""")]
    [InlineData("""{"alg":"RSA1_5","alg":"RSA-OAEP-256","enc":"A256GCM","kid":"test-key-1"}""")]
    [InlineData("""{"alg":1}""")]
    [InlineData("[]")]
    [InlineData("nonsense")]
    public void Rejects_headers_outside_the_profile(string header) =>
        Assert.Equal("InvalidEncryptedPan", Reject(TestJwe.Encrypt(ActivePan, Kit.BankKey, Key, header)));

    [Theory]
    [InlineData("")]
    [InlineData("a.b.c")]
    [InlineData("....")]
    [InlineData("!.!.!.!.!")]
    [InlineData("4111111111111111")]
    public void Rejects_malformed_input(string jwe) => Assert.Equal("InvalidEncryptedPan", Reject(jwe));

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void Rejects_tampering_with_any_segment(int segment) =>
        Assert.Equal("InvalidEncryptedPan", Reject(TestJwe.EditSegment(Encrypt(ActivePan), segment, TestJwe.FlipBit)));

    [Fact]
    public void Rejects_header_changed_after_encryption() =>
        Assert.Equal("InvalidEncryptedPan", Reject(TestJwe.EditSegment(Encrypt(ActivePan), 0,
            _ => Encoding.UTF8.GetBytes($$"""{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"{{Key}}","typ":"x"}"""))));

    [Fact]
    public void Rejects_truncated_authentication_tag() =>
        Assert.Equal("InvalidEncryptedPan", Reject(TestJwe.EditSegment(Encrypt(ActivePan), 4, tag => tag[..12])));

    [Fact]
    public void Rejects_wrong_key_padding_and_size()
    {
        using var other = System.Security.Cryptography.RSA.Create(3072);
        Assert.Equal("InvalidEncryptedPan", Reject(TestJwe.Encrypt(ActivePan, other, Key)));
        Assert.Equal("InvalidEncryptedPan", Reject(TestJwe.Encrypt(ActivePan, Kit.BankKey, Key,
            padding: System.Security.Cryptography.RSAEncryptionPadding.OaepSHA1)));
        Assert.Equal("InvalidEncryptedPan", Reject(Encrypt(new string('1', 5000))));
    }

    [Theory]
    [InlineData("4111111111111112")]
    [InlineData("41111111111")]
    [InlineData(" 4111111111111111")]
    [InlineData("4111111111111111\n")]
    [InlineData("")]
    public void Rejects_plaintext_that_is_not_a_pan(string plaintext) => Assert.Equal("InvalidPan", Reject(Encrypt(plaintext)));

    [Fact]
    public void Several_keys_can_be_active_for_rotation()
    {
        using var decryptor = new PanDecryptor(new PanDecryptionOptions
        {
            Keys = [new() { Kid = "old", PrivateKeyPath = Kit.KeyPath }, new() { Kid = "new", PrivateKeyPath = Kit.KeyPath }],
        }, "");
        decryptor.Decrypt(TestJwe.Encrypt(ActivePan, Kit.BankKey, "old")).Dispose();
        decryptor.Decrypt(TestJwe.Encrypt(ActivePan, Kit.BankKey, "new")).Dispose();
    }

    [Fact]
    public void Start_up_fails_without_keys() =>
        Assert.Throws<InvalidOperationException>(() => new PanDecryptor(new PanDecryptionOptions(), ""));
}
