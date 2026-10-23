using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Domain;
using Infrastructure.Persistence;
using Infrastructure.Sessions;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Sessions;

public sealed class SessionLedgerWriterTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    [Fact]
    public async Task RecordStartedAsync_PersistsSessionLedger()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var session = await CreateSessionAsync(database.Context);
        var writer = new SessionLedgerWriter(database.Context);

        // Act
        await writer.RecordStartedAsync(session);

        // Assert
        Assert.True(await database.Context.AuthenticationSessionLedgers
            .AnyAsync(s => s.SessionIdHash == session.SessionIdHash && s.PrincipalId == session.PrincipalId));
    }

    [Fact]
    public async Task RecordStartedAsync_PersistsPrincipalSnapshot()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var session = await CreateSessionAsync(database.Context);
        var writer = new SessionLedgerWriter(database.Context);

        // Act
        await writer.RecordStartedAsync(session);

        // Assert
        var audit = await database.Context.AuditEvents.AsNoTracking().SingleAsync();
        using var snapshot = System.Text.Json.JsonDocument.Parse(audit.ActorSnapshot!);
        Assert.Equal(session.DisplayName, snapshot.RootElement.GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task RecordStartedAsync_WhenAuditInsertFails_RollsBackLedgerInsert()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var session = await CreateSessionAsync(database.Context);
        await database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_test_event CHECK (event_type <> 'authentication.session.started')");
        var writer = new SessionLedgerWriter(database.Context);

        // Act
        await Assert.ThrowsAsync<DbUpdateException>(() => writer.RecordStartedAsync(session));

        // Assert
        Assert.False(await database.Context.AuthenticationSessionLedgers.AsNoTracking()
            .AnyAsync(s => s.SessionIdHash == session.SessionIdHash));
    }

    [Fact]
    public async Task RecordStartedAsync_WhenLedgerInsertFails_DoesNotPersistAudit()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var session = await CreateSessionAsync(database.Context);
        await database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE authentication_session_ledger ADD CONSTRAINT reject_test_session CHECK (session_id_hash = 'never')");
        var writer = new SessionLedgerWriter(database.Context);

        // Act
        await Assert.ThrowsAsync<DbUpdateException>(() => writer.RecordStartedAsync(session));

        // Assert
        Assert.False(await database.Context.AuditEvents.AsNoTracking().AnyAsync());
    }

    [Fact]
    public async Task RecordRenewedAsync_WithLaterExpiry_ExtendsLedgerExpiry()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var session = await CreateSessionAsync(database.Context);
        var writer = new SessionLedgerWriter(database.Context);
        await writer.RecordStartedAsync(session);
        var expiry = session.ExpectedExpiresAt.AddMinutes(15);

        // Act
        await writer.RecordRenewedAsync(session.SessionIdHash, expiry);

        // Assert
        Assert.Equal(expiry.UtcDateTime, await database.Context.AuthenticationSessionLedgers
            .Select(s => s.ExpectedExpiresAt).SingleAsync());
    }

    [Fact]
    public async Task RecordRenewedAsync_WithEarlierExpiry_DoesNotShortenLedgerExpiry()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var session = await CreateSessionAsync(database.Context);
        var writer = new SessionLedgerWriter(database.Context);
        await writer.RecordStartedAsync(session);

        // Act
        await writer.RecordRenewedAsync(session.SessionIdHash, session.ExpectedExpiresAt.AddMinutes(-5));

        // Assert
        Assert.Equal(session.ExpectedExpiresAt.UtcDateTime, await database.Context.AuthenticationSessionLedgers
            .Select(s => s.ExpectedExpiresAt).SingleAsync());
    }

    [Fact]
    public async Task RecordEndedAsync_WhenRepeated_PreservesOriginalEndReason()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var session = await CreateSessionAsync(database.Context);
        var writer = new SessionLedgerWriter(database.Context);
        await writer.RecordStartedAsync(session);
        await writer.RecordEndedAsync(session.SessionIdHash, session.CreatedAt.AddMinutes(1), "logout");

        // Act
        await writer.RecordEndedAsync(session.SessionIdHash, session.CreatedAt.AddMinutes(2), "removed");

        // Assert
        Assert.Equal("logout", await database.Context.AuthenticationSessionLedgers.Select(s => s.EndReason).SingleAsync());
    }

    private static async Task<SessionStarted> CreateSessionAsync(PamDbContext db)
    {
        var principal = new Principal { Issuer = "test-issuer", Subject = "ana" };
        db.Principals.Add(principal);
        await db.SaveChangesAsync();
        var createdAt = new DateTimeOffset(2026, 10, 23, 12, 0, 0, TimeSpan.Zero);
        return new SessionStarted(principal.Id, new string('A', 64), "idp-session", createdAt,
            createdAt.AddMinutes(30), null, "Test browser", principal.PublicId.ToString(),
            "Ana Horvat", principal.Issuer, principal.Subject, "test-correlation");
    }
}
