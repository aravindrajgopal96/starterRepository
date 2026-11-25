using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace CardControl.Api.Tests;

public sealed class CardControlTests(StarterKit kit) : ApiTest(kit)
{
    [Fact]
    public async Task Lock_then_unlock_changes_the_card_and_audits_the_user()
    {
        await using var api = new ApiFactory(Kit);

        var locked = await CallAsync(api, "lock");
        Assert.Equal(200, (int)locked.Status);
        Assert.Equal("Locked", locked.Json.GetProperty("status").GetString());
        Assert.Equal("CORP-1001", locked.Json.GetProperty("corporateId").GetString());

        var unlocked = await CallAsync(api, "unlock", users: ["bob@acme.example"]);
        Assert.Equal("Active", unlocked.Json.GetProperty("status").GetString());

        var audit = await Kit.AuditAsync();
        Assert.Equal(
            [("Lock", "Success", User, "partner-app"), ("Unlock", "Success", "bob@acme.example", "partner-app")],
            audit.Select(e => (Text(e, "action"), Text(e, "outcome"), Text(e, "initiatingUser"), Text(e, "channel"))));
    }

    [Fact]
    public async Task Second_enabled_corporate_works()
    {
        await using var api = new ApiFactory(Kit);
        Assert.Equal(200, (int)(await CallAsync(api, pan: ActivePan2, corporateId: "CORP-2002")).Status);
    }

    [Fact]
    public async Task Response_contains_only_what_the_partner_needs()
    {
        await using var api = new ApiFactory(Kit);
        var result = await CallAsync(api);
        Assert.Equal(["corporateId", "status", "updatedAt"], result.Json.EnumerateObject().Select(p => p.Name));
    }

    // ---- Platform rejections: passed on, and still audited ----

    [Theory]
    [InlineData("lock", LockedPan, "CORP-1001", 409, "CardAlreadyLocked")]
    [InlineData("unlock", ActivePan, "CORP-1001", 409, "CardNotLocked")]
    [InlineData("lock", CancelledPan, "CORP-2002", 422, "CardCancelled")]
    [InlineData("unlock", CancelledPan, "CORP-2002", 422, "CardCancelled")]
    public async Task Rejected_change_is_reported_and_audited(string action, string pan, string corporate, int status, string code)
    {
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api, action, pan, corporate), status, code);

        var entry = Assert.Single(await Kit.AuditAsync());
        Assert.Equal((code, User), (Text(entry, "outcome"), Text(entry, "initiatingUser")));
    }

    // ---- Entitlement ----

    [Theory]
    [InlineData(OtherCorporatePan, "CORP-3003")]
    [InlineData(ActivePan, "CORP-9999")]
    [InlineData(ActivePan, "corp-1001")]
    public async Task Corporate_not_enabled_is_403(string pan, string corporate)
    {
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api, pan: pan, corporateId: corporate), 403, "CorporateNotEnabled");
        Assert.Empty(await Kit.AuditAsync());
        Assert.Contains($"initiating user {User}", api.Logs.Text);
    }

    [Theory]
    [InlineData(ActivePan, "CORP-2002")] // both enabled, but it isn't this one's card
    [InlineData(OtherCorporatePan, "CORP-1001")] // claims an enabled corporate for someone else's card
    [InlineData(NoCorporatePan, "CORP-1001")] // card has no corporate
    [InlineData(UnknownPan, "CORP-1001")] // card doesn't exist
    public async Task Card_outside_the_stated_corporate_looks_the_same_as_no_card(string pan, string corporate)
    {
        await using var api = new ApiFactory(Kit);
        var result = await CallAsync(api, pan: pan, corporateId: corporate);
        AssertError(result, 404, "CardNotFound");
        Assert.Equal("No such card for this corporate.", result.Json.GetProperty("detail").GetString());
        Assert.Empty(await Kit.AuditAsync());
    }

    [Fact]
    public async Task Entitlement_belongs_to_the_calling_partner()
    {
        // partner-readonly's list is empty even though partner-app's isn't: the list is looked up by the token's azp.
        var entitlements = new Cards.PartnerEntitlements(Microsoft.Extensions.Options.Options.Create(
            new Dictionary<string, Cards.PartnerOptions> { ["partner-app"] = new() { Corporates = ["CORP-1001"] } }));
        Assert.True(entitlements.IsEnabled("partner-app", "CORP-1001"));
        Assert.False(entitlements.IsEnabled("partner-readonly", "CORP-1001"));
        Assert.False(entitlements.IsEnabled("PARTNER-APP", "CORP-1001"));

        await using var api = new ApiFactory(Kit, settings: new() { ["Partners:partner-app:Corporates:1"] = "CORP-7777" });
        AssertError(await CallAsync(api, pan: ActivePan2, corporateId: "CORP-2002"), 403, "CorporateNotEnabled");
    }

    // ---- Input ----

    public static TheoryData<string[]> BadUsers => new()
    {
        Array.Empty<string>(),
        new[] { "" },
        new[] { "   " },
        new[] { new string('a', 129) },
        new[] { "jane", "bob" },
        new[] { "jane‮boss" },
        new[] { "jane\u0001" },
        new[] { ActivePan },
    };

    [Theory, MemberData(nameof(BadUsers))]
    public async Task Bad_initiating_user_is_400(string[] users)
    {
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api, users: users), 400, "InvalidRequest");
        Assert.Empty(await Kit.AuditAsync());
    }

    [Theory]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{")]
    [InlineData("""{"encryptedPan":"x"}""")]
    [InlineData("""{"corporateId":"CORP-1001"}""")]
    [InlineData("""{"encryptedPan":"x","corporateId":1001}""")]
    [InlineData("""{"encryptedPan":"x","corporateId":"CORP-3003","corporateId":"CORP-1001"}""")]
    public async Task Bad_body_is_400(string body)
    {
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api, content: new StringContent(body, Encoding.UTF8, "application/json")), 400, "InvalidRequest");
    }

    [Fact]
    public async Task Wrong_content_type_is_415()
    {
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api, content: new StringContent("hi")), 415, "UnsupportedMediaType");
    }

    [Fact]
    public async Task Invalid_pan_inside_a_valid_jwe_is_400()
    {
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api, pan: "4111111111111112"), 400, "InvalidPan");
    }

    // ---- Faults in the real card platform stub ----

    [Fact]
    public async Task Platform_outage_is_503()
    {
        await Kit.SetFaultsAsync(0, 1);
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api), 503, "ServiceUnavailable");
    }

    [Fact]
    public async Task Slow_platform_still_works()
    {
        await Kit.SetFaultsAsync(1000, 0);
        await using var api = new ApiFactory(Kit);
        Assert.Equal(200, (int)(await CallAsync(api)).Status);
    }

    [Fact]
    public async Task Very_slow_platform_is_504()
    {
        await Kit.SetFaultsAsync(20_000, 0);
        await using var api = new ApiFactory(Kit);
        AssertError(await CallAsync(api), 504, "UpstreamTimeout");
    }

    private static string? Text(JsonElement element, string name) => element.GetProperty(name).GetString();
}
