using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Infrastructure.Persistence.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using static Backend.IntegrationTests.Sessions.SessionTestHost;

namespace Backend.IntegrationTests.Sessions;

[Collection("Cookie sessions")]
public sealed class CookieRotationTests(PostgresFixture postgres, RedisFixture redis)
{
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
        await using var services = CreateServices(database, clock, redis.Connection);
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
        await using var server = await CreateSessionServerAsync(database, clock, principalId, redis.Connection);
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
        using var current = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, current.StatusCode);
        client.DefaultRequestHeaders.Remove("Cookie");
        client.DefaultRequestHeaders.Add("Cookie", oldCookie);
        using var replay = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task SignIn_WithExistingCookieAndFailedAudit_DoesNotIssueNewSession()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock, redis.Connection);
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
    public async Task SignIn_WithExistingSessionCookie_InitializesFreshTicketDeadline()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var server = await CreateSessionServerAsync(database, clock, principalId, redis.Connection);
        using var client = server.GetTestClient();
        using var firstLogin = await client.GetAsync("/login");
        firstLogin.EnsureSuccessStatusCode();
        UpdateCookie(client, firstLogin);
        clock.Now = clock.Now.AddMinutes(1);

        // Act
        using var secondLogin = await client.GetAsync("/login");
        secondLogin.EnsureSuccessStatusCode();
        UpdateCookie(client, secondLogin);
        using var response = await client.GetAsync("/api/me");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
