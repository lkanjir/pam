using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Api;
using Api.Authentication;
using Api.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting.Internal;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Domain;
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
        var rawStore = services.GetRequiredService<RedisTicketStore>();
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
                await context.SignInAsync("Cookies", ticket.Principal, ticket.Properties);
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
        var cookie = cookies.Single(value => value.StartsWith("pam.session=")).Split(';')[0];
        client.DefaultRequestHeaders.Remove("Cookie");
        client.DefaultRequestHeaders.Add("Cookie", cookie);
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
        services.AddSingleton<RedisTicketStore>();
        services.AddSingleton<Microsoft.AspNetCore.Authentication.Cookies.ITicketStore, PamTicketStore>();
        // Each operation gets a fresh DbContext against this test's isolated database.
        services.AddDbContext<Infrastructure.Persistence.PamDbContext>(options => options
            .UseNpgsql(database.Context.Database.GetConnectionString()).UseSnakeCaseNamingConvention());
        services.AddScoped<ISessionLedgerWriter, SessionLedgerWriter>();
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
        var principal = new Principal { Issuer = "test", Subject = "ana" };
        database.Context.Principals.Add(principal);
        await database.Context.SaveChangesAsync();
        return principal.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}
