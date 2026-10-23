using Api.Authentication;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Domain;
using Infrastructure.Sessions;
using Microsoft.AspNetCore.Authentication;
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

    private ServiceProvider CreateServices(TestDatabase database, TimeProvider clock)
    {
        var services = new ServiceCollection();
        services.AddLogging();
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
        services.AddAuthentication("Cookies").AddCookie("Cookies", options =>
        {
            options.Cookie.Name = "pam.session";
            options.TimeProvider = clock;
        });
        services.AddOptions<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>("Cookies")
            .Configure<Microsoft.AspNetCore.Authentication.Cookies.ITicketStore>((options, store) => options.SessionStore = store);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
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
