using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Api;
using Api.Authentication;
using Infrastructure.Authentication;
using Api.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting.Internal;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Infrastructure.Persistence.Entities;
using Infrastructure.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Backend.IntegrationTests.Sessions;

public sealed class CookieSessionTests(PostgresFixture postgres, RedisFixture redis)
    : IClassFixture<PostgresFixture>, IClassFixture<RedisFixture>
{
    [Fact]
    public async Task LogoutEndpoint_DoesNotLeakEndReasonIntoLaterCleanup()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock);
        var cookie = await LoginAsync(services, clock, principalId);
        var store = services.GetRequiredService<Microsoft.AspNetCore.Authentication.Cookies.ITicketStore>();
        var otherId = await store.StoreAsync(SessionTestData.Ticket(clock.Now, principalId));
        var otherHash = SessionTestData.Hash(otherId);
        await using var scope = services.CreateAsyncScope();
        var context = CreateLogoutContext(scope.ServiceProvider, cookie);
        await ExecuteLogoutEndpointAsync(context);

        // Act
        await store.RemoveAsync(otherId, context, CancellationToken.None);

        // Assert
        Assert.Null(await database.Context.AuthenticationSessionLedgers
            .Where(s => s.SessionIdHash == otherHash).Select(s => s.EndedAt).SingleAsync());
        Assert.Equal(1, await database.Context.AuditEvents.CountAsync(e =>
            e.EventType == "authentication.session.ended" && e.ReasonCode == "logout"));
        Assert.False(await redis.Connection.GetDatabase().KeyExistsAsync("pam:session:" + otherHash));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SignIn_WithDefaultProperties_UsesConfiguredCookieLifetime(bool persistent)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var server = await CreateSessionServerAsync(database, clock, principalId);
        using var client = server.GetTestClient();

        // Act
        using var response = await client.GetAsync($"/login?persistent={persistent}");
        response.EnsureSuccessStatusCode();

        // Assert
        var cookie = Microsoft.Net.Http.Headers.SetCookieHeaderValue.Parse(
            response.Headers.GetValues("Set-Cookie").Single());
        Assert.Equal("pam.session", cookie.Name.ToString());
        Assert.True(cookie.HttpOnly);
        Assert.Equal(Microsoft.Net.Http.Headers.SameSiteMode.Strict, cookie.SameSite);
        Assert.Equal("/", cookie.Path.ToString());
        Assert.Equal(persistent ? clock.Now.AddMinutes(30) : (DateTimeOffset?)null, cookie.Expires);
        Assert.Equal(clock.Now.AddMinutes(30).UtcDateTime,
            await database.Context.AuthenticationSessionLedgers.Select(s => s.ExpectedExpiresAt).SingleAsync());
    }

    [Fact]
    public async Task SignIn_WithRedirect_ReturnsUsableCookieAndNoStoreHeaders()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var server = await CreateSessionServerAsync(database, clock, principalId);
        using var client = server.GetTestClient();

        // Act
        using var response = await client.GetAsync("/login?redirect=true");

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/me", response.Headers.Location?.OriginalString);
        Assert.True(response.Headers.CacheControl?.NoStore);
        UpdateCookie(client, response);
        using var authenticated = await client.GetAsync("/me");
        Assert.Equal(HttpStatusCode.OK, authenticated.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Authenticate_WhenAccessChanges_RevokesSession(bool rolesChanged)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var server = await CreateSessionServerAsync(database, clock, principalId);
        using var client = server.GetTestClient();
        using var login = await client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        UpdateCookie(client, login);
        var hash = await database.Context.AuthenticationSessionLedgers.Select(s => s.SessionIdHash).SingleAsync();
        if (rolesChanged)
        {
            await database.Context.Database.ExecuteSqlRawAsync("""
                INSERT INTO pam_roles (code, description, created_by_principal_id)
                SELECT 'admin', 'Administrator', id FROM principals;
                INSERT INTO pam_role_assignments (principal_id, role_id, assigned_by_principal_id)
                SELECT p.id, r.id, p.id FROM principals p CROSS JOIN pam_roles r;
                """);
        }
        else
            await database.Context.Database.ExecuteSqlRawAsync("UPDATE principals SET is_enabled = false");
        clock.Now = clock.Now.AddMinutes(16); // Also exercise a pending sliding renewal.

        // Act
        using var response = await client.GetAsync("/me");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(await redis.Connection.GetDatabase().KeyExistsAsync("pam:session:" + hash));
        Assert.Equal("access_changed", await database.Context.AuthenticationSessionLedgers
            .Select(s => s.EndReason).SingleAsync());
    }

    [Fact]
    public async Task SignIn_AsAnotherPrincipal_RecordsNewIdentityUnderNewSession()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var firstId = await SeedPrincipalAsync(database);
        var second = new Principal { Issuer = "https://identity.example/realms/pam", Subject = "bob" };
        database.Context.Principals.Add(second);
        await database.Context.SaveChangesAsync();
        await database.Context.Database.ExecuteSqlRawAsync("UPDATE principals SET is_enabled = true");
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock);
        var oldCookie = await LoginAsync(services, clock, firstId);
        await using var scope = services.CreateAsyncScope();
        var context = CreateContext(scope.ServiceProvider);
        context.Request.Headers.Cookie = oldCookie;
        var ticket = SessionTestData.Ticket(clock.Now, second.Id.ToString());
        var identity = (System.Security.Claims.ClaimsIdentity)ticket.Principal.Identity!;
        identity.RemoveClaim(identity.FindFirst("sub")!);
        identity.AddClaim(new System.Security.Claims.Claim("sub", "bob"));

        // Act
        await context.SignInAsync("Cookies", ticket.Principal, ticket.Properties);

        // Assert
        var active = await database.Context.AuthenticationSessionLedgers.SingleAsync(s => s.EndedAt == null);
        Assert.Equal(second.Id, active.PrincipalId);
        var audit = await database.Context.AuditEvents.SingleAsync(e =>
            e.SessionIdHash == active.SessionIdHash && e.EventType == "authentication.session.started");
        Assert.Equal(second.Id, audit.ActorPrincipalId);
        Assert.Equal(2, await database.Context.AuthenticationSessionLedgers.CountAsync());
    }

    [Fact]
    public async Task SignIn_WithExistingCookie_RotatesSessionAndAuditsBothLifetimes()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var server = await CreateSessionServerAsync(database, clock, principalId);
        using var client = server.GetTestClient();
        using var first = await client.GetAsync("/login");
        first.EnsureSuccessStatusCode();
        UpdateCookie(client, first);
        var oldCookie = client.DefaultRequestHeaders.GetValues("Cookie").Single();
        var oldHash = await database.Context.AuthenticationSessionLedgers.Select(s => s.SessionIdHash).SingleAsync();
        clock.Now = clock.Now.AddMinutes(16);

        // Act
        using var second = await client.GetAsync("/login");
        second.EnsureSuccessStatusCode();
        UpdateCookie(client, second);

        // Assert
        Assert.Equal(2, await database.Context.AuditEvents.CountAsync(e => e.EventType == "authentication.session.started"));
        var oldSession = await database.Context.AuthenticationSessionLedgers.SingleAsync(s => s.SessionIdHash == oldHash);
        Assert.Equal("reauthentication", oldSession.EndReason);
        Assert.False(await redis.Connection.GetDatabase().KeyExistsAsync("pam:session:" + oldHash));
        using var current = await client.GetAsync("/me");
        Assert.Equal(HttpStatusCode.OK, current.StatusCode);
        client.DefaultRequestHeaders.Remove("Cookie");
        client.DefaultRequestHeaders.Add("Cookie", oldCookie);
        using var replay = await client.GetAsync("/me");
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task SignIn_WithExistingCookieAndFailedAudit_DoesNotIssueNewSession()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock);
        var cookie = await LoginAsync(services, clock, principalId);
        await database.Context.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION reject_new_login() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.event_type = 'authentication.session.started' THEN RAISE EXCEPTION 'test rejection'; END IF;
                RETURN NEW;
            END $$;
            CREATE TRIGGER reject_new_login BEFORE INSERT ON audit_events
            FOR EACH ROW EXECUTE FUNCTION reject_new_login();
            """);
        await using var scope = services.CreateAsyncScope();
        var context = CreateContext(scope.ServiceProvider);
        context.Request.Headers.Cookie = cookie;
        var ticket = SessionTestData.Ticket(clock.Now, principalId);

        // Act
        await Assert.ThrowsAsync<DbUpdateException>(() => context.SignInAsync("Cookies", ticket.Principal, ticket.Properties));

        // Assert
        // The standard sign-out expires the previous cookie; no usable new cookie is issued.
        Assert.Single(context.Response.Headers.SetCookie);
        Assert.StartsWith("pam.session=;", context.Response.Headers.SetCookie[0]);
        Assert.Equal(1, await database.Context.AuthenticationSessionLedgers.CountAsync());
        var hash = await database.Context.AuthenticationSessionLedgers.Select(s => s.SessionIdHash).SingleAsync();
        Assert.False(await redis.Connection.GetDatabase().KeyExistsAsync("pam:session:" + hash));
    }

    [Fact]
    public async Task SignInAsync_WhenPersistenceSucceeds_IssuesSessionCookie()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock);
        await using var scope = services.CreateAsyncScope();
        var context = CreateContext(scope.ServiceProvider);
        var ticket = SessionTestData.Ticket(clock.Now, principalId);

        // Act
        await context.SignInAsync("Cookies", ticket.Principal, ticket.Properties);

        // Assert
        Assert.Contains(context.Response.Headers.SetCookie, value => value!.StartsWith("pam.session="));
    }

    [Fact]
    public async Task SignInAsync_WhenAuditPersistenceFails_DoesNotIssueCookie()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        await database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_test_event CHECK (event_type <> 'authentication.session.started')");
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock);
        await using var scope = services.CreateAsyncScope();
        var context = CreateContext(scope.ServiceProvider);
        var ticket = SessionTestData.Ticket(clock.Now, principalId);

        // Act
        await Assert.ThrowsAsync<DbUpdateException>(() => context.SignInAsync("Cookies", ticket.Principal, ticket.Properties));

        // Assert
        Assert.Equal(0, context.Response.Headers.SetCookie.Count);
    }

    [Fact]
    public async Task LogoutEndpoint_RecordsSessionEnd()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock);
        var cookie = await LoginAsync(services, clock, principalId);
        await using var scope = services.CreateAsyncScope();
        var context = CreateLogoutContext(scope.ServiceProvider, cookie);

        // Act
        await ExecuteLogoutEndpointAsync(context);

        // Assert
        Assert.Equal("logout", await database.Context.AuthenticationSessionLedgers.Select(s => s.EndReason).SingleAsync());
    }

    [Fact]
    public async Task LogoutEndpoint_RecordsLogoutAudit()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock);
        var cookie = await LoginAsync(services, clock, principalId);
        await using var scope = services.CreateAsyncScope();
        var context = CreateLogoutContext(scope.ServiceProvider, cookie);

        // Act
        await ExecuteLogoutEndpointAsync(context);

        // Assert
        Assert.Equal(1, await database.Context.AuditEvents.CountAsync(e =>
            e.EventType == "authentication.session.ended" && e.ReasonCode == "logout"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LogoutEndpoint_RevokesRedisSessionEvenIfAuditFails(bool auditFails)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock);
        var cookie = await LoginAsync(services, clock, principalId);
        var hash = await database.Context.AuthenticationSessionLedgers.Select(s => s.SessionIdHash).SingleAsync();
        if (auditFails)
            await RejectLogoutAuditAsync(database);
        await using var scope = services.CreateAsyncScope();
        var context = CreateLogoutContext(scope.ServiceProvider, cookie);

        // Act
        await ExecuteLogoutEndpointAsync(context);

        // Assert
        Assert.False(await redis.Connection.GetDatabase().KeyExistsAsync("pam:session:" + hash));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LogoutEndpoint_ExpiresCookieEvenIfAuditFails(bool auditFails)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock);
        var cookie = await LoginAsync(services, clock, principalId);
        if (auditFails)
            await RejectLogoutAuditAsync(database);
        await using var scope = services.CreateAsyncScope();
        var context = CreateLogoutContext(scope.ServiceProvider, cookie);

        // Act
        await ExecuteLogoutEndpointAsync(context);

        // Assert
        Assert.Contains(context.Response.Headers.SetCookie, value => value!.StartsWith("pam.session=;"));
    }

    [Fact]
    public async Task RetrieveAsync_WithLegacyTicketWithoutAbsoluteDeadline_RejectsSession()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock);
        var rawStore = services.GetRequiredService<ISessionTicketStore>();
        var id = await rawStore.StoreAsync(SessionTestData.Ticket(clock.Now));
        var store = services.GetRequiredService<Microsoft.AspNetCore.Authentication.Cookies.ITicketStore>();

        // Act
        var ticket = await store.RetrieveAsync(id);

        // Assert
        Assert.Null(ticket);
    }

    [Fact]
    public async Task SignIn_WithExistingSessionCookie_InitializesFreshTicketDeadline()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var server = await CreateSessionServerAsync(database, clock, principalId);
        using var client = server.GetTestClient();
        using var firstLogin = await client.GetAsync("/login");
        firstLogin.EnsureSuccessStatusCode();
        UpdateCookie(client, firstLogin);
        clock.Now = clock.Now.AddMinutes(1);

        // Act
        using var secondLogin = await client.GetAsync("/login");
        secondLogin.EnsureSuccessStatusCode();
        UpdateCookie(client, secondLogin);
        using var response = await client.GetAsync("/me");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData(479, HttpStatusCode.OK)]
    [InlineData(480, HttpStatusCode.Unauthorized)]
    public async Task Authenticate_WithContinuousSlidingRenewal_EnforcesAbsoluteDeadline(
        int elapsedMinutes, HttpStatusCode expectedStatus)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        var startedAt = clock.Now;
        await using var server = await CreateSessionServerAsync(database, clock, principalId);
        using var client = server.GetTestClient();
        using var login = await client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        UpdateCookie(client, login);
        for (var minute = 16; minute < elapsedMinutes; minute += 16)
        {
            clock.Now = startedAt.AddMinutes(minute);
            using var activeRequest = await client.GetAsync("/me");
            activeRequest.EnsureSuccessStatusCode();
            UpdateCookie(client, activeRequest);
        }
        clock.Now = startedAt.AddMinutes(elapsedMinutes);

        // Act
        using var response = await client.GetAsync("/me");

        // Assert
        Assert.Equal(expectedStatus, response.StatusCode);
    }

    [Fact]
    public async Task SlidingRenewal_NearAbsoluteDeadline_CapsLedgerExpiry()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        var startedAt = clock.Now;
        await using var server = await CreateSessionServerAsync(database, clock, principalId);
        using var client = server.GetTestClient();
        using var login = await client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        UpdateCookie(client, login);
        for (var minute = 16; minute <= 448; minute += 16)
        {
            clock.Now = startedAt.AddMinutes(minute);
            using var activeRequest = await client.GetAsync("/me");
            activeRequest.EnsureSuccessStatusCode();
            UpdateCookie(client, activeRequest);
        }
        clock.Now = startedAt.AddMinutes(464);

        // Act
        using var response = await client.GetAsync("/me");
        response.EnsureSuccessStatusCode();

        // Assert
        Assert.Equal(startedAt.AddHours(8).UtcDateTime, await database.Context.AuthenticationSessionLedgers
            .Select(s => s.ExpectedExpiresAt).SingleAsync());
    }

    [Fact]
    public async Task SlidingRenewal_NearAbsoluteDeadline_CapsRedisTtl()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        var startedAt = clock.Now;
        await using var server = await CreateSessionServerAsync(database, clock, principalId);
        using var client = server.GetTestClient();
        using var login = await client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        UpdateCookie(client, login);
        for (var minute = 16; minute <= 448; minute += 16)
        {
            clock.Now = startedAt.AddMinutes(minute);
            using var activeRequest = await client.GetAsync("/me");
            activeRequest.EnsureSuccessStatusCode();
            UpdateCookie(client, activeRequest);
        }
        clock.Now = startedAt.AddMinutes(464);
        var hash = await database.Context.AuthenticationSessionLedgers.Select(s => s.SessionIdHash).SingleAsync();

        // Act
        using var response = await client.GetAsync("/me");
        response.EnsureSuccessStatusCode();

        // Assert
        var ttl = await redis.Connection.GetDatabase().KeyTimeToLiveAsync("pam:session:" + hash);
        Assert.InRange(ttl ?? TimeSpan.Zero, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(16));
    }

    private async Task<WebApplication> CreateSessionServerAsync(
        TestDatabase database, TestTimeProvider clock, string principalId)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" });
        builder.WebHost.UseTestServer();
        ConfigureServices(builder.Services, database, clock);
        var app = builder.Build();
        app.UseAuthentication();
        app.Run(async context =>
        {
            if (context.Request.Path == "/login")
            {
                var ticket = SessionTestData.Ticket(clock.Now, principalId);
                // As with OIDC, let the cookie handler initialize issue/expiry times.
                var properties = new AuthenticationProperties
                {
                    IsPersistent = context.Request.Query["persistent"] == "True",
                    RedirectUri = context.Request.Query["redirect"] == "true" ? "/me" : null
                };
                await context.SignInAsync("Cookies", ticket.Principal, properties);
                return;
            }
            var authenticated = await context.AuthenticateAsync("Cookies");
            context.Response.StatusCode = authenticated.Succeeded ? 200 : 401;
        });
        await app.StartAsync();
        return app;
    }

    private static void UpdateCookie(HttpClient client, HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var cookies)) return;
        // Standard sign-out followed by sign-in emits deletion and replacement.
        // Apply them in response order, as a browser does.
        var jar = new CookieContainer();
        foreach (var cookie in cookies)
            jar.SetCookies(client.BaseAddress!, cookie);
        client.DefaultRequestHeaders.Remove("Cookie");
        var header = jar.GetCookieHeader(client.BaseAddress!);
        if (header.Length > 0) client.DefaultRequestHeaders.Add("Cookie", header);
    }

    private static Task RejectLogoutAuditAsync(TestDatabase database) =>
        database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_session_end CHECK (event_type <> 'authentication.session.ended')");

    private static async Task<string> LoginAsync(ServiceProvider services, TimeProvider clock, string principalId)
    {
        await using var scope = services.CreateAsyncScope();
        var context = CreateContext(scope.ServiceProvider);
        var ticket = SessionTestData.Ticket(clock.GetUtcNow(), principalId);
        await context.SignInAsync("Cookies", ticket.Principal, ticket.Properties);
        return context.Response.Headers.SetCookie.Single(value => value!.StartsWith("pam.session="))!.Split(';')[0];
    }

    private static DefaultHttpContext CreateLogoutContext(IServiceProvider services, string cookie)
    {
        var context = CreateContext(services);
        context.Request.Method = "POST";
        context.Request.Path = "/auth/logout";
        context.Request.Headers.Cookie = cookie;
        return context;
    }

    private static Task ExecuteLogoutEndpointAsync(HttpContext context)
    {
        // Execute the real endpoint delegate, including its internal termination feature.
        // Authorization/antiforgery middleware are outside this lifecycle test's scope.
        var routes = new TestRouteBuilder(context.RequestServices);
        routes.MapAuthenticationEndpoints();
        var endpoint = routes.DataSources.SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>().Single(e => e.RoutePattern.RawText == "/auth/logout");
        return endpoint.RequestDelegate!(context);
    }

    private sealed class TestRouteBuilder(IServiceProvider services) : IEndpointRouteBuilder
    {
        public IServiceProvider ServiceProvider => services;
        public ICollection<EndpointDataSource> DataSources { get; } = new List<EndpointDataSource>();
        public IApplicationBuilder CreateApplicationBuilder() => new ApplicationBuilder(services);
    }

    private ServiceProvider CreateServices(TestDatabase database, TimeProvider clock)
    {
        var services = new ServiceCollection();
        ConfigureServices(services, database, clock);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    private void ConfigureServices(IServiceCollection services, TestDatabase database, TimeProvider clock)
    {
        services.AddLogging();
        services.AddRouting();
        services.AddAntiforgery();
        services.AddDataProtection();
        services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        services.AddSingleton(clock);
        services.AddSingleton(redis.Connection);
        services.AddSingleton<ISessionTicketStore, RedisTicketStore>();
        services.AddSingleton<Microsoft.AspNetCore.Authentication.Cookies.ITicketStore, PamTicketStore>();
        // Each operation gets a fresh DbContext against this test's isolated database.
        services.AddDbContext<Infrastructure.Persistence.PamDbContext>(options => options
            .UseNpgsql(database.Context.Database.GetConnectionString()).UseSnakeCaseNamingConvention());
        services.AddScoped<ISessionLedgerWriter, SessionLedgerWriter>();
        services.AddScoped<SessionTerminator>();
        services.AddScoped<Application.Identity.IPrincipalIdentityReader, Infrastructure.Identity.PrincipalIdentityReader>();
        services.AddSingleton<IOptions<PamSessionOptions>>(Options.Create(new PamSessionOptions
        {
            IdleTimeout = TimeSpan.FromMinutes(30),
            AbsoluteTimeout = TimeSpan.FromHours(8)
        }));
        services.AddSingleton<IOptions<KeycloakOptions>>(Options.Create(new KeycloakOptions
        {
            Authority = "https://identity.example/realms/pam",
            MetadataAddress = "https://identity.example/realms/pam/.well-known/openid-configuration",
            ClientId = "test-bff",
            ClientSecret = "test-secret"
        }));
        services.AddPamAuthentication(new HostingEnvironment { EnvironmentName = "Development" });
        services.Configure<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>(
            "Cookies", options => options.TimeProvider = clock);
    }

    private static DefaultHttpContext CreateContext(IServiceProvider services)
    {
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Scheme = "http";
        return context;
    }

    private static async Task<string> SeedPrincipalAsync(TestDatabase database)
    {
        var principal = new Principal { Issuer = "https://identity.example/realms/pam", Subject = "ana" };
        database.Context.Principals.Add(principal);
        await database.Context.SaveChangesAsync();
        await database.Context.Database.ExecuteSqlInterpolatedAsync($"UPDATE principals SET is_enabled = true WHERE id = {principal.Id}");
        return principal.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}
