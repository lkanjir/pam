using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Api.Authentication;
using Api.Errors;
using Api.Filters;
using Application.Identity;
using FakeItEasy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

namespace Backend.IntegrationTests.Authentication;

public sealed class OidcErrorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Callback_UnknownOrDisabledPrincipal_DeniesWithoutSession(bool disabled)
    {
        // Arrange
        await using var host = await OidcHost.CreateAsync();
        A.CallTo(() => host.Reader.FindAsync(OidcHost.Issuer, "ana", A<CancellationToken>._))
            .Returns(Task.FromResult<PrincipalIdentity?>(disabled
                ? new PrincipalIdentity(42, Guid.NewGuid(), "Ana Horvat", false, [])
                : null));
        var state = await host.StartLoginAsync();

        // Act
        using var response = await host.CallbackAsync(state);

        // Assert
        await AssertProblemAsync(response, 403);
        AssertNoSession(host, response);
    }

    [Fact]
    public async Task Callback_PrincipalLookupFailure_ReturnsGenericInternalErrorWithoutSession()
    {
        // Arrange
        await using var host = await OidcHost.CreateAsync();
        A.CallTo(() => host.Reader.FindAsync(OidcHost.Issuer, "ana", A<CancellationToken>._))
            .ThrowsAsync(new Npgsql.NpgsqlException("secret-sentinel"));
        var state = await host.StartLoginAsync();

        // Act
        using var response = await host.CallbackAsync(state);

        // Assert
        await AssertProblemAsync(response, 500);
        AssertNoSession(host, response);
    }

    [Fact]
    public async Task Callback_IdpAccessDenied_ReturnsForbiddenWithoutSession()
    {
        // Arrange
        await using var host = await OidcHost.CreateAsync();
        var state = await host.StartLoginAsync();

        // Act
        using var response = await host.Client.GetAsync(
            "/signin-oidc?error=access_denied&state=" + Uri.EscapeDataString(state));

        // Assert
        await AssertProblemAsync(response, 403);
        AssertNoSession(host, response);
    }

    [Fact]
    public async Task Callback_InvalidState_ReturnsAgreedGenericInternalError()
    {
        // Arrange
        await using var host = await OidcHost.CreateAsync();

        // Act
        using var response = await host.CallbackAsync("invalid-state");

        // Assert
        await AssertProblemAsync(response, 500);
        AssertNoSession(host, response);
    }

    [Fact]
    public async Task Callback_ValidPrincipal_IssuesSession()
    {
        // Arrange
        await using var host = await OidcHost.CreateAsync();
        var state = await host.StartLoginAsync();

        // Act
        using var response = await host.CallbackAsync(state);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), cookie => cookie.StartsWith("pam.session="));
        A.CallTo(() => host.Tickets.StoreAsync(A<AuthenticationTicket>._, A<HttpContext>._,
            A<CancellationToken>._)).MustHaveHappenedOnceExactly();
    }

    private static async Task AssertProblemAsync(HttpResponseMessage response, int status)
    {
        var text = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(text);
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal(status, json.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("oidc-test-request", json.RootElement.GetProperty("correlationId").GetString());
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.DoesNotContain("secret-sentinel", text);
    }

    private static void AssertNoSession(OidcHost host, HttpResponseMessage response)
    {
        Assert.DoesNotContain(response.Headers.TryGetValues("Set-Cookie", out var cookies) ? cookies : [],
            cookie => cookie.StartsWith("pam.session="));
        A.CallTo(() => host.Tickets.StoreAsync(A<AuthenticationTicket>._, A<HttpContext>._,
            A<CancellationToken>._)).MustNotHaveHappened();
    }

    // Uses real OIDC/cookie handlers with a local token-endpoint transport.
    // No callback validation, nonce, state or signature checks are disabled.
    private sealed class OidcHost(WebApplication app, HttpClient client, TokenEndpoint endpoint,
        IPrincipalIdentityReader reader, ITicketStore tickets) : IAsyncDisposable
    {
        public const string Issuer = "https://identity.example/realms/pam";
        public HttpClient Client { get; } = client;
        public IPrincipalIdentityReader Reader { get; } = reader;
        public ITicketStore Tickets { get; } = tickets;

        public static async Task<OidcHost> CreateAsync()
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" });
            builder.WebHost.UseTestServer();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = Issuer,
                ["Keycloak:MetadataAddress"] = Issuer + "/.well-known/openid-configuration",
                ["Keycloak:ClientId"] = "test-bff",
                ["Keycloak:ClientSecret"] = "test-secret",
                ["PamSession:IdleTimeout"] = "00:30:00",
                ["PamSession:AbsoluteTimeout"] = "08:00:00"
            });
            builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
            builder.Services.AddPamAuthentication(builder.Configuration, builder.Environment);
            builder.Services.AddPamErrorHandling();
            builder.Services.AddPamAntiforgery(builder.Environment);
            builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
            var reader = A.Fake<IPrincipalIdentityReader>();
            A.CallTo(() => reader.FindAsync(Issuer, "ana", A<CancellationToken>._))
                .Returns(Task.FromResult<PrincipalIdentity?>(
                    new PrincipalIdentity(42, Guid.NewGuid(), "Ana Horvat", true, ["user"])));
            builder.Services.AddSingleton(reader);
            var tickets = A.Fake<ITicketStore>();
            A.CallTo(() => tickets.StoreAsync(A<AuthenticationTicket>._, A<HttpContext>._,
                A<CancellationToken>._)).Returns(Task.FromResult(new string('A', 64)));
            builder.Services.Replace(ServiceDescriptor.Singleton(tickets));
            var endpoint = new TokenEndpoint();
            builder.Services.PostConfigure<OpenIdConnectOptions>("oidc", options =>
            {
                options.Configuration = new OpenIdConnectConfiguration
                {
                    Issuer = Issuer,
                    AuthorizationEndpoint = Issuer + "/authorize",
                    TokenEndpoint = Issuer + "/token",
                    SigningKeys = { endpoint.Key }
                };
                options.ConfigurationManager =
                    new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
                options.Backchannel = new HttpClient(endpoint);
            });
            var app = builder.Build();
            app.Use(async (context, next) =>
            {
                context.TraceIdentifier = "oidc-test-request";
                await next(context);
            });
            app.UsePamErrorHandling();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapGroup("/api").MapAuthenticationEndpoints();
            await app.StartAsync();
            var client = app.GetTestClient();
            client.DefaultRequestHeaders.Accept.ParseAdd("text/html");
            return new OidcHost(app, client, endpoint, reader, tickets);
        }

        public async Task<string> StartLoginAsync()
        {
            using var response = await Client.GetAsync("/api/auth/login");
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
            endpoint.Nonce = query["nonce"].ToString();
            Client.DefaultRequestHeaders.Add("Cookie", string.Join("; ",
                response.Headers.GetValues("Set-Cookie").Select(cookie => cookie.Split(';')[0])));
            return query["state"].ToString();
        }

        public Task<HttpResponseMessage> CallbackAsync(string state) =>
            Client.GetAsync("/signin-oidc?code=test-code&state=" + Uri.EscapeDataString(state));

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await app.DisposeAsync();
        }
    }

    private sealed class TokenEndpoint : HttpMessageHandler
    {
        public SymmetricSecurityKey Key { get; } = new(RandomNumberGenerator.GetBytes(32)) { KeyId = "test-key" };
        public string Nonce { get; set; } = string.Empty;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath != "/realms/pam/token")
                throw new InvalidOperationException("Unexpected test IdP request.");
            var now = DateTime.UtcNow;
            var token = new JwtSecurityToken(OidcHost.Issuer, "test-bff",
                [new Claim("sub", "ana"), new Claim("nonce", Nonce)],
                now.AddSeconds(-5), now.AddMinutes(5), new SigningCredentials(Key, SecurityAlgorithms.HmacSha256));
            token.Payload["iat"] = EpochTime.GetIntDate(now);
            var json = JsonSerializer.Serialize(new
            {
                id_token = new JwtSecurityTokenHandler().WriteToken(token),
                access_token = "test-access-token",
                token_type = "Bearer",
                expires_in = 300
            });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
            });
        }
    }
}
