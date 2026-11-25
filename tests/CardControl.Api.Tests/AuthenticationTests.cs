using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using System.Buffers.Text;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CardControl.Api.Tests;

public sealed class AuthenticationTests(StarterKit kit) : ApiTest(kit)
{
    [Fact]
    public async Task No_token_is_401()
    {
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api, token: ""), 401, "Unauthorized");
    }

    [Fact]
    public async Task Garbage_token_is_401()
    {
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api, token: "not-a-jwt"), 401, "Unauthorized");
    }

    [Fact]
    public async Task Expired_token_is_401()
    {
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api, token: await Kit.GetTokenAsync(lifetime: -60)), 401, "Unauthorized");
    }

    [Fact]
    public async Task Token_for_another_audience_is_401()
    {
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api, token: await Kit.GetTokenAsync(audience: "api://other-api")), 401, "Unauthorized");
    }

    [Fact]
    public async Task Token_without_the_role_is_403()
    {
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api, token: await Kit.GetTokenAsync("partner-readonly")), 403, "Forbidden");
        Assert.Empty(await Kit.AuditAsync());
    }

    [Fact]
    public async Task Token_with_role_added_after_signing_is_401()
    {
        await using var api = new ApiFactory(Kit);
        var parts = (await Kit.GetTokenAsync("partner-readonly")).Split('.');
        var payload = JsonNode.Parse(Base64Url.DecodeFromChars(parts[1]))!;
        payload["roles"] = new JsonArray("CardControl.Write");
        parts[1] = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(payload));
        AssertError(await CallAsync(api, token: string.Join('.', parts)), 401, "Unauthorized");
    }

    [Fact]
    public async Task Token_signed_by_another_key_under_the_real_kid_is_401()
    {
        await using var api = new ApiFactory(Kit);
        var parts = (await Kit.GetTokenAsync()).Split('.');
        using var attacker = RSA.Create(2048);
        var signature = attacker.SignData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        AssertError(await CallAsync(api, token: $"{parts[0]}.{parts[1]}.{Base64Url.EncodeToString(signature)}"), 401, "Unauthorized");
    }

    [Fact]
    public async Task Unsigned_alg_none_token_is_401()
    {
        await using var api = new ApiFactory(Kit);
        var parts = (await Kit.GetTokenAsync()).Split('.');
        var header = Base64Url.EncodeToString("""{"alg":"none","typ":"JWT"}"""u8);
        AssertError(await CallAsync(api, token: $"{header}.{parts[1]}."), 401, "Unauthorized");
    }

    [Fact]
    public async Task Hmac_token_signed_with_the_public_key_is_401()
    {
        await using var api = new ApiFactory(Kit);
        var parts = (await Kit.GetTokenAsync()).Split('.');
        var jwks = await Kit.Http.GetFromJsonAsync<JsonElement>($"{Kit.IdpUrl}/jwks");
        var jwk = jwks.GetProperty("keys")[0];
        using var rsa = RSA.Create(new RSAParameters
        {
            Modulus = Base64Url.DecodeFromChars(jwk.GetProperty("n").GetString()),
            Exponent = Base64Url.DecodeFromChars(jwk.GetProperty("e").GetString()),
        });
        var header = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(
            new { alg = "HS256", typ = "JWT", kid = jwk.GetProperty("kid").GetString() }));
        var mac = HMACSHA256.HashData(Encoding.ASCII.GetBytes(rsa.ExportSubjectPublicKeyInfoPem()),
            Encoding.ASCII.GetBytes($"{header}.{parts[1]}"));
        AssertError(await CallAsync(api, token: $"{header}.{parts[1]}.{Base64Url.EncodeToString(mac)}"), 401, "Unauthorized");
    }

    [Fact]
    public async Task Token_from_an_issuer_that_shares_the_key_but_not_the_name_is_401()
    {
        // The API trusts whatever issuer the discovery document names, so point it at a document naming a different one.
        // Same signing keys, so only the issuer check can reject the token.
        var discovery = JsonSerializer.Serialize(new { issuer = "https://other.example", jwks_uri = $"{Kit.IdpUrl}/jwks" });
        await using var api = new ApiFactory(Kit, s => s.Configure<JwtBearerOptions>(
            "Bearer", o => o.BackchannelHttpHandler = new FakeHandler(async request =>
                request.RequestUri!.AbsolutePath.EndsWith("openid-configuration")
                    ? new HttpResponseMessage { Content = new StringContent(discovery) }
                    : await Kit.Http.GetAsync(request.RequestUri))));
        AssertError(await CallAsync(api), 401, "Unauthorized");
    }

    [Fact]
    public async Task Unreachable_identity_provider_fails_closed()
    {
        await using var api = new ApiFactory(Kit, settings: new() { ["Auth:Authority"] = StarterKit.FreeUrl() });
        AssertError(await CallAsync(api), 401, "Unauthorized");
        Assert.Contains("Access token rejected", api.Logs.Text);
        Assert.Empty(await Kit.AuditAsync());
    }

    [Fact]
    public async Task Health_is_anonymous_but_unknown_routes_are_not()
    {
        await using var api = new ApiFactory(Kit);
        using var client = api.CreateClient();
        Assert.Equal(200, (int)(await client.GetAsync("/healthz")).StatusCode);
        Assert.Equal(401, (int)(await client.GetAsync("/v1/anything")).StatusCode);
    }
}
