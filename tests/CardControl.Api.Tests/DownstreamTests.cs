using System.Net;
using System.Text;
using CardControl.Api.Downstream;
using Microsoft.Extensions.DependencyInjection;

namespace CardControl.Api.Tests;

/// <summary>Failures the real stubs can't produce.</summary>
public sealed class DownstreamTests(StarterKit kit) : ApiTest(kit)
{
    private ApiFactory Api(string clientName, FakeHandler handler) =>
        new(Kit, s => s.AddHttpClient(clientName).ConfigurePrimaryHttpMessageHandler(() => handler));

    private static FakeHandler Returns(int status, string body) =>
        new(_ => Task.FromResult(Response(status, body)));

    private static HttpResponseMessage Response(int status, string body) =>
        new((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    [Theory]
    [InlineData(200, "{}", 502, "UpstreamError")]
    [InlineData(200, "<html>", 502, "UpstreamError")]
    [InlineData(404, "", 502, "UpstreamError")]
    [InlineData(307, "", 502, "UpstreamError")]
    [InlineData(400, """{"code":"InvalidPan"}""", 400, "InvalidPan")]
    [InlineData(400, """{"code":"Other"}""", 502, "UpstreamError")]
    public async Task Tokenisation_responses(int status, string body, int expected, string code)
    {
        await using var api = Api(TokenisationClient.ClientName, Returns(status, body));
        AssertError(await CallAsync(api), expected, code);
        Assert.Empty(await Kit.AuditAsync());
    }

    [Theory]
    [InlineData(404, "no code, e.g. a misrouted request", 502, "UpstreamError")]
    [InlineData(404, """{"code":"CardNotFound"}""", 404, "CardNotFound")]
    [InlineData(200, "null", 502, "UpstreamError")]
    [InlineData(200, """{"status":"Active"}""", 404, "CardNotFound")] // corporateId absent: never entitled
    public async Task Get_card_responses(int status, string body, int expected, string code)
    {
        await using var api = Api(CardPlatformClient.ReadClientName, Returns(status, body));
        AssertError(await CallAsync(api), expected, code);
        Assert.Empty(await Kit.AuditAsync());
    }

    [Theory]
    [InlineData(200, "<html>", 502, "OutcomeUnknown")]
    [InlineData(200, """{"status":"Active"}""", 502, "OutcomeUnknown")] // claims success but isn't locked
    [InlineData(500, "", 502, "OutcomeUnknown")]
    [InlineData(400, """{"code":"InvalidRequest"}""", 502, "UpstreamError")]
    [InlineData(503, """{"code":"ServiceUnavailable"}""", 503, "ServiceUnavailable")]
    public async Task Lock_responses_are_mapped_and_never_retried(int status, string body, int expected, string code)
    {
        var handler = Returns(status, body);
        await using var api = Api(CardPlatformClient.WriteClientName, handler);
        AssertError(await CallAsync(api), expected, code);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Lock_timeout_is_reported_as_unknown_and_not_retried()
    {
        var handler = new FakeHandler(_ => throw new TaskCanceledException());
        await using var api = Api(CardPlatformClient.WriteClientName, handler);
        AssertError(await CallAsync(api), 504, "OutcomeUnknown");
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Lock_connection_dropped_mid_flight_is_unknown_but_never_connected_is_not()
    {
        await using var dropped = Api(CardPlatformClient.WriteClientName,
            new FakeHandler(_ => throw new HttpRequestException(HttpRequestError.ResponseEnded)));
        AssertError(await CallAsync(dropped), 502, "OutcomeUnknown");

        await using var refused = Api(CardPlatformClient.WriteClientName,
            new FakeHandler(_ => throw new HttpRequestException(HttpRequestError.ConnectionError)));
        AssertError(await CallAsync(refused), 503, "ServiceUnavailable");
    }

    [Fact]
    public async Task Transient_read_failure_is_retried()
    {
        var first = true;
        using var real = new HttpClient();
        var handler = new FakeHandler(async request =>
        {
            if (first)
            {
                first = false;
                return Response(503, "");
            }
            return await real.GetAsync(request.RequestUri);
        });
        await using var api = Api(CardPlatformClient.ReadClientName, handler);
        Assert.Equal(200, (int)(await CallAsync(api)).Status);
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task Tokenisation_retry_resends_the_whole_pan()
    {
        var bodies = new List<string>();
        var handler = new FakeHandler(async request =>
        {
            bodies.Add(await request.Content!.ReadAsStringAsync());
            return bodies.Count == 1 ? Response(503, "") : Response(200, """{"cardToken":"ctok_8f3a1c2e9b7d4a01"}""");
        });
        await using var api = Api(TokenisationClient.ClientName, handler);
        Assert.Equal(200, (int)(await CallAsync(api)).Status);
        Assert.Equal([$$"""{"pan":"{{ActivePan}}"}""", $$"""{"pan":"{{ActivePan}}"}"""], bodies);
    }

    [Fact]
    public async Task Initiating_user_is_passed_on_unchanged_in_meaning()
    {
        const string user = "O'Brien \"the boss\" <x@y.example>";
        await using var api = new ApiFactory(Kit);
        Assert.Equal(200, (int)(await CallAsync(api, users: [user])).Status);
        Assert.Equal(user, Assert.Single(await Kit.AuditAsync()).GetProperty("initiatingUser").GetString());
    }
}
