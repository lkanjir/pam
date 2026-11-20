using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Api.Authorization;
using Application.Authorization;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Backend.IntegrationTests.Authentication;

[Collection("Cookie sessions")]
public sealed class OidcReauthenticationTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Callback_FreshSameIdentity_ReplacesOnlyOriginalSession(bool omitOriginalCookie)
    {
        // Arrange
        await using var flow = await CreateAsync();
        string oldCookie = flow.Cookies.GetCookieHeader(flow.BaseAddress);
        var original = await flow.Test.Database.Context.AuthenticationSessionLedgers.SingleAsync();
        flow.Test.Clock.Now = flow.Test.Clock.Now.AddMinutes(12);
        string callback = await flow.StartAsync();

        // Act
        using var response = await flow.SendAsync(callback, omitOriginalCookie);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/api/me", response.Headers.Location?.OriginalString);
        var sessions = await flow.Test.Database.Context.AuthenticationSessionLedgers.AsNoTracking().ToListAsync();
        Assert.Equal(2, sessions.Count);
        var ended = Assert.Single(sessions, session => session.Id == original.Id);
        Assert.Equal("reauthentication", ended.EndReason);
        Assert.Equal(flow.Test.Clock.Now.UtcDateTime, ended.EndedAt);
        Assert.Null(Assert.Single(sessions, session => session.Id != original.Id).EndedAt);
        Assert.Equal(1, await flow.EndAuditCountAsync());
        using var recent = await flow.SendAsync("/api/recent-check");
        Assert.Equal(HttpStatusCode.OK, recent.StatusCode);
        using var oldRequest = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        oldRequest.Headers.Add("Cookie", oldCookie);
        using var old = await flow.Test.Client.SendAsync(oldRequest);
        Assert.Equal(HttpStatusCode.Unauthorized, old.StatusCode);
    }

    [Theory]
    [InlineData("missing-time", 403)]
    [InlineData("stale-time", 403)]
    [InlineData("future-time", 403)]
    [InlineData("other-account", 403)]
    [InlineData("wrong-nonce", 500)]
    [InlineData("wrong-signature", 500)]
    [InlineData("invalid-state", 500)]
    [InlineData("missing-correlation", 500)]
    public async Task Callback_InvalidFreshnessIdentityOrProtocol_LeavesOriginalSessionActive(string fault, int status)
    {
        // Arrange
        await using var flow = await CreateAsync();
        flow.Provider.Fault = fault;
        if (fault == "other-account")
        {
            var other = new Infrastructure.Persistence.Entities.Principal
            {
                Issuer = TokenEndpoint.Issuer,
                Subject = "bob"
            };
            flow.Test.Database.Context.Principals.Add(other);
            await flow.Test.Database.Context.SaveChangesAsync();
            await flow.Test.Database.Context.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE principals SET is_enabled = true WHERE id = {other.Id}");
        }
        string callback = await flow.StartAsync();
        if (fault == "invalid-state")
        {
            callback = "/signin-oidc?code=test&state=invalid";
        }
        if (fault == "missing-correlation")
        {
            foreach (Cookie cookie in flow.Cookies.GetAllCookies())
            {
                if (cookie.Name.StartsWith(".AspNetCore.Correlation.", StringComparison.Ordinal))
                {
                    cookie.Expired = true;
                }
            }
        }

        // Act
        using var response = await flow.SendAsync(callback);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var session = await flow.Test.Database.Context.AuthenticationSessionLedgers.AsNoTracking().SingleAsync();
        Assert.Null(session.EndedAt);
        Assert.Equal(0, await flow.EndAuditCountAsync());
        using var original = await flow.SendAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        if (fault is "invalid-state" or "missing-correlation")
        {
            Assert.Equal(0, flow.Provider.Exchanges);
        }
        else
        {
            Assert.Equal(1, flow.Provider.Exchanges);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Callback_OriginalEndedOrExpired_DoesNotCreateReplacement(bool logout)
    {
        // Arrange
        await using var flow = await CreateAsync();
        string callback = await flow.StartAsync();
        if (logout)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout");
            request.Headers.Add("Cookie", flow.Cookies.GetCookieHeader(flow.BaseAddress));
            using var response = await flow.Test.Client.SendAsync(request);
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        }
        else
        {
            flow.Test.Clock.Now = flow.Test.Clock.Now.AddMinutes(31);
        }

        // Act
        using var result = await flow.SendAsync(callback);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, result.StatusCode);
        var session = await flow.Test.Database.Context.AuthenticationSessionLedgers.AsNoTracking().SingleAsync();
        Assert.Equal(logout ? "logout" : null, session.EndReason);
        Assert.Equal(logout ? 1 : 0, await flow.EndAuditCountAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Callback_TwoValidFlows_OnlyOneCreatesReplacement(bool concurrent)
    {
        // Arrange
        await using var flow = await CreateAsync();
        string first = await flow.StartAsync();
        string second = await flow.StartAsync();

        // Act
        var results = concurrent
            ? await Task.WhenAll(flow.SendAsync(first), flow.SendAsync(second))
            : [await flow.SendAsync(first), await flow.SendAsync(second)];
        using var firstResult = results[0];
        using var secondResult = results[1];

        // Assert
        Assert.Single(results, result => result.StatusCode == HttpStatusCode.Redirect);
        Assert.Single(results, result => result.StatusCode == HttpStatusCode.Forbidden);
        Assert.Equal(2, await flow.Test.Database.Context.AuthenticationSessionLedgers.CountAsync());
        Assert.Equal(1, await flow.EndAuditCountAsync());
        using var profile = await flow.SendAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, profile.StatusCode);
    }

    [Fact]
    public async Task Callback_OriginalRenewedAfterChallenge_ClosesTheCurrentLease()
    {
        // Arrange
        await using var flow = await CreateAsync();
        string callback = await flow.StartAsync();
        var initial = flow.Test.Clock.Now;
        flow.Test.Clock.Now = initial.AddMinutes(16);
        using var profile = await flow.SendAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, profile.StatusCode);
        Assert.Equal(initial.AddMinutes(46).UtcDateTime,
            await flow.Test.Database.Context.AuthenticationSessionLedgers.Select(session => session.ExpectedExpiresAt).SingleAsync());

        // Act
        using var response = await flow.SendAsync(callback);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var original = await flow.Test.Database.Context.AuthenticationSessionLedgers.AsNoTracking()
            .SingleAsync(session => session.EndReason == "reauthentication");
        Assert.Equal(initial.AddMinutes(46).UtcDateTime, original.ExpectedExpiresAt);
        Assert.Equal(flow.Test.Clock.Now.UtcDateTime, original.EndedAt);
        Assert.Equal(1, await flow.EndAuditCountAsync());
    }

    private async Task<Flow> CreateAsync()
    {
        var provider = new TokenEndpoint();
        var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, app =>
        {
            var options = app.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("oidc");
            options.Configuration = new OpenIdConnectConfiguration
            {
                Issuer = TokenEndpoint.Issuer,
                AuthorizationEndpoint = TokenEndpoint.Issuer + "/authorize",
                TokenEndpoint = TokenEndpoint.Issuer + "/token",
                SigningKeys = { provider.Key }
            };
            options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
            options.Backchannel = new HttpClient(provider);
            app.MapGet("/api/recent-check", () => TypedResults.Ok())
                .RequireAuthorization(PamPermissions.ResourcesReadAll, PamPolicies.RecentAuthentication);
        });
        provider.AuthenticationTime = () => test.Clock.Now;
        // CookieContainer evaluates Expires against the system clock. Keep the
        // controllable clock in the same epoch without introducing sleeps.
        test.Clock.Now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        test.Client.BaseAddress = new Uri("https://localhost");
        await test.AuthenticateAsync(includeResourceVersion: false);
        var cookies = new CookieContainer();
        foreach (string cookie in test.Client.DefaultRequestHeaders.GetValues("Cookie").SelectMany(value => value.Split(';')))
        {
            cookies.SetCookies(test.Client.BaseAddress!, cookie.Trim());
        }
        test.Client.DefaultRequestHeaders.Remove("Cookie");
        return new Flow(test, provider, cookies);
    }

    // Only the IdP transport is substituted. Framework state, correlation, nonce,
    // signature and lifetime validation run unchanged against PostgreSQL/Redis sessions.
    private sealed class Flow(ResourceTestContext test, TokenEndpoint provider, CookieContainer cookies) : IAsyncDisposable
    {
        public ResourceTestContext Test { get; } = test;
        public TokenEndpoint Provider { get; } = provider;
        public CookieContainer Cookies { get; } = cookies;
        public Uri BaseAddress => Test.Client.BaseAddress ?? throw new InvalidOperationException("Missing test URL.");

        public async Task<string> StartAsync()
        {
            using var response = await SendAsync("/api/auth/reauthenticate?returnUrl=https://untrusted.example");
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            var location = Assert.IsType<Uri>(response.Headers.Location);
            var query = QueryHelpers.ParseQuery(location.Query);
            Assert.Equal("0", query["max_age"].ToString());
            Assert.Equal("S256", query["code_challenge_method"].ToString());
            Assert.NotEmpty(query["code_challenge"].ToString());
            string code = Guid.NewGuid().ToString("N");
            Provider.Nonces.Add(code, query["nonce"].ToString());
            return QueryHelpers.AddQueryString("/signin-oidc", new Dictionary<string, string?>
            {
                ["code"] = code,
                ["state"] = query["state"].ToString()
            });
        }

        public async Task<HttpResponseMessage> SendAsync(string path, bool omitOriginalCookie = false)
        {
            var uri = new Uri(BaseAddress, path);
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            string cookieHeader = Cookies.GetCookieHeader(uri);
            if (omitOriginalCookie)
            {
                cookieHeader = string.Join("; ", cookieHeader.Split(';').Select(value => value.Trim())
                    .Where(value => !value.StartsWith("pam.session", StringComparison.Ordinal)));
            }
            request.Headers.Add("Cookie", cookieHeader);
            var response = await Test.Client.SendAsync(request);
            if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (string cookie in setCookies)
                {
                    Cookies.SetCookies(uri, cookie);
                }
            }
            return response;
        }

        public Task<int> EndAuditCountAsync() => Test.Database.Context.AuditEvents
            .CountAsync(value => value.EventType == "authentication.session.ended");

        public ValueTask DisposeAsync() => Test.DisposeAsync();
    }

    private sealed class TokenEndpoint : HttpMessageHandler
    {
        public const string Issuer = "https://identity.example/realms/pam";
        public SymmetricSecurityKey Key { get; } = new(RandomNumberGenerator.GetBytes(32)) { KeyId = "test-key" };
        public Dictionary<string, string> Nonces { get; } = [];
        public Func<DateTimeOffset> AuthenticationTime { get; set; } = () => DateTimeOffset.UtcNow;
        public string Fault { get; set; } = string.Empty;
        public int Exchanges { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal("/realms/pam/token", request.RequestUri?.AbsolutePath);
            var form = QueryHelpers.ParseQuery(await (request.Content ?? throw new InvalidOperationException("Missing form"))
                .ReadAsStringAsync(cancellationToken));
            string nonce = Nonces[form["code"].ToString()];
            Exchanges++;
            var now = DateTime.UtcNow;
            var signingKey = Fault == "wrong-signature" ? new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)) : Key;
            var token = new JwtSecurityToken(Issuer, "test-bff",
                [new Claim("sub", Fault == "other-account" ? "bob" : "ana"),
                    new Claim("nonce", Fault == "wrong-nonce" ? "wrong" : nonce)],
                now.AddSeconds(-5), now.AddMinutes(5), new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256));
            token.Payload["iat"] = EpochTime.GetIntDate(now);
            if (Fault != "missing-time")
            {
                var authenticatedAt = AuthenticationTime();
                token.Payload["auth_time"] = Fault switch
                {
                    "stale-time" => authenticatedAt.AddMinutes(-11).ToUnixTimeSeconds(),
                    "future-time" => authenticatedAt.AddSeconds(61).ToUnixTimeSeconds(),
                    _ => authenticatedAt.ToUnixTimeSeconds()
                };
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    id_token = new JwtSecurityTokenHandler().WriteToken(token),
                    access_token = "test-access-token",
                    token_type = "Bearer",
                    expires_in = 300
                }), System.Text.Encoding.UTF8, "application/json")
            };
        }
    }
}
