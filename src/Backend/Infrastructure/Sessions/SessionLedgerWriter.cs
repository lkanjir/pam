using System.Text.Json;
using Application.Sessions;
using Domain;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Sessions;

public sealed class SessionLedgerWriter(PamDbContext dbContext) : ISessionLedgerWriter
{
    public async Task RecordStartedAsync(SessionStarted session, CancellationToken cancellationToken = default)
    {
        var ledger = new AuthenticationSessionLedger
        {
            PrincipalId = session.PrincipalId,
            SessionIdHash = session.SessionIdHash,
            IdpSessionId = session.IdpSessionId,
            CreatedAt = session.CreatedAt.UtcDateTime,
            ExpectedExpiresAt = session.ExpectedExpiresAt.UtcDateTime,
            ClientIpAddress = session.ClientIpAddress,
            UserAgent = session.UserAgent,
        };

        var principalSnapshot = JsonSerializer.Serialize(new
        {
            id = session.PrincipalId,
            publicId = session.PrincipalPublicId,
            displayName = session.DisplayName,
            issuer = session.Issuer,
            subject = session.Subject
        });

        var auditEvent = new AuditEvent
        {
            EventType = "authentication.session.started",
            SchemaVersion = 1,
            OccurredAt = session.CreatedAt.UtcDateTime,

            ActorKind = "principal",
            ActorPrincipalId = session.PrincipalId,
            SubjectPrincipalId = session.PrincipalId,
            ActorSnapshot = principalSnapshot,
            SubjectSnapshot = principalSnapshot,

            SessionIdHash = session.SessionIdHash,
            CorrelationId = session.CorrelationId,
            Source = "pam.api",
            Outcome = "success"
        };

        dbContext.AuthenticationSessionLedgers.Add(ledger);
        dbContext.AuditEvents.Add(auditEvent);
        
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task RecordRenewedAsync(string sessionIdHash, DateTimeOffset expectedExpiresAt,
        CancellationToken cancellationToken = default)
    {
        var expiresAtUtc = expectedExpiresAt.UtcDateTime;

        await dbContext.AuthenticationSessionLedgers
            .Where(session => session.SessionIdHash == sessionIdHash && session.EndedAt == null &&
                              session.ExpectedExpiresAt < expiresAtUtc)
            .ExecuteUpdateAsync(setters =>
                setters.SetProperty(session => session.ExpectedExpiresAt, expiresAtUtc), cancellationToken);
    }

    public async Task RecordEndedAsync(string sessionIdHash, DateTimeOffset endedAt, string reason,
        CancellationToken cancellationToken = default)
    {
        var endedAtUtc = endedAt.UtcDateTime;

        await dbContext.AuthenticationSessionLedgers
            .Where(session => session.SessionIdHash == sessionIdHash && session.EndedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(session => session.EndedAt, endedAtUtc)
                    .SetProperty(session => session.EndReason, reason), cancellationToken);
    }
}