using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using static Backend.IntegrationTests.Sessions.SessionTestHost;

namespace Backend.IntegrationTests.Sessions;

[Collection("Cookie sessions")]
public sealed class CookieLogoutTests(PostgresFixture postgres, RedisFixture redis)
{
    [Fact]
    public async Task LogoutEndpoint_DoesNotLeakEndReasonIntoLaterCleanup()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock, redis.Connection);
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

    [Fact]
    public async Task LogoutEndpoint_RecordsSessionEnd()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock, redis.Connection);
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
        await using var services = CreateServices(database, clock, redis.Connection);
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
        await using var services = CreateServices(database, clock, redis.Connection);
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
        await using var services = CreateServices(database, clock, redis.Connection);
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
}
