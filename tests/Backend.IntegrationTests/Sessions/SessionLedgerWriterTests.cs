using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Infrastructure.Persistence.Entities;
using Infrastructure.Persistence;
using Infrastructure.Sessions;
using Microsoft.EntityFrameworkCore;
using Npgsql;

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
            .AnyAsync(s => s.SessionIdHash == session.SessionIdHash && s.PrincipalId == session.Principal.Id));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SessionAudit_PreservesPrincipalSnapshotJsonContract(bool ended)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var session = await CreateSessionAsync(database.Context);
        var writer = new SessionLedgerWriter(database.Context);

        // Give SQL's current principal snapshot the same source values as the start event.
        await database.Context.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE principals SET display_name = {session.Principal.DisplayName} WHERE id = {session.Principal.Id}");

        // Act
        await writer.RecordStartedAsync(session);
        if (ended)
        {
            await writer.RecordEndedAsync(session.SessionIdHash, session.CreatedAt.AddMinutes(1), "logout");
        }

        // Assert
        var eventType = ended ? "authentication.session.ended" : "authentication.session.started";
        var audit = await database.Context.AuditEvents.AsNoTracking().SingleAsync(e => e.EventType == eventType);
        Assert.Equal(1, audit.SchemaVersion);
        foreach (var json in new[] { audit.ActorSnapshot, audit.SubjectSnapshot })
        {
            using var snapshot = System.Text.Json.JsonDocument.Parse(json!);
            var root = snapshot.RootElement;
            Assert.Equal(new[] { "displayName", "id", "issuer", "publicId", "subject" },
                root.EnumerateObject().Select(property => property.Name).Order().ToArray());
            Assert.Equal(session.Principal.Id, root.GetProperty("id").GetInt64());
            Assert.Equal(session.Principal.PublicId.ToString(), root.GetProperty("publicId").GetString());
            Assert.Equal("Ana Horvat", root.GetProperty("displayName").GetString());
            Assert.Equal("test-issuer", root.GetProperty("issuer").GetString());
            Assert.Equal("ana", root.GetProperty("subject").GetString());
        }
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

    [Fact]
    public async Task RecordEndedAsync_PersistsLogoutAuditForSession()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var session = await CreateSessionAsync(database.Context);
        var writer = new SessionLedgerWriter(database.Context);
        await writer.RecordStartedAsync(session);

        // Act
        await writer.RecordEndedAsync(session.SessionIdHash, session.CreatedAt.AddMinutes(1), "logout");

        // Assert
        Assert.True(await database.Context.AuditEvents.AnyAsync(e =>
            e.EventType == "authentication.session.ended" &&
            e.SessionIdHash == session.SessionIdHash &&
            e.ActorPrincipalId == session.Principal.Id &&
            e.SubjectPrincipalId == session.Principal.Id &&
            e.ReasonCode == "logout"));
    }

    [Fact]
    public async Task RecordEndedAsync_WhenRepeated_DoesNotDuplicateAudit()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var session = await CreateSessionAsync(database.Context);
        var writer = new SessionLedgerWriter(database.Context);
        await writer.RecordStartedAsync(session);
        await writer.RecordEndedAsync(session.SessionIdHash, session.CreatedAt.AddMinutes(1), "logout");

        // Act
        await writer.RecordEndedAsync(session.SessionIdHash, session.CreatedAt.AddMinutes(2), "logout");

        // Assert
        Assert.Equal(1, await database.Context.AuditEvents.CountAsync(e =>
            e.EventType == "authentication.session.ended" && e.SessionIdHash == session.SessionIdHash));
    }

    [Fact]
    public async Task RecordEndedAsync_WhenAuditInsertFails_KeepsSessionOpen()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var session = await CreateSessionAsync(database.Context);
        var writer = new SessionLedgerWriter(database.Context);
        await writer.RecordStartedAsync(session);
        await database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_session_end CHECK (event_type <> 'authentication.session.ended')");

        // Act
        var error = await Record.ExceptionAsync(() =>
            writer.RecordEndedAsync(session.SessionIdHash, session.CreatedAt.AddMinutes(1), "logout"));

        // Assert
        // A syntax error must not masquerade as a successful rollback test.
        var postgresError = Assert.IsType<PostgresException>(error);
        Assert.Equal(PostgresErrorCodes.CheckViolation, postgresError.SqlState);
        Assert.Equal("reject_session_end", postgresError.ConstraintName);
        var persisted = await database.Context.AuthenticationSessionLedgers.AsNoTracking().SingleAsync();
        Assert.Null(persisted.EndedAt);
        Assert.Null(persisted.EndReason);
    }

    private static async Task<SessionStarted> CreateSessionAsync(PamDbContext db)
    {
        var principal = new Principal { Issuer = "test-issuer", Subject = "ana" };
        db.Principals.Add(principal);
        await db.SaveChangesAsync();
        var createdAt = new DateTimeOffset(2026, 10, 23, 12, 0, 0, TimeSpan.Zero);
        return new SessionStarted(
            new PrincipalSnapshot(principal.Id, principal.PublicId, "Ana Horvat", principal.Issuer, principal.Subject),
            new string('A', 64), "idp-session", createdAt, createdAt.AddMinutes(30),
            new SessionRequestMetadata(null, "Test browser", "test-correlation"));
    }
}
