using System.Text.Json;
using Application.Sessions;
using Infrastructure.Persistence.Entities;
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
        var correlationId = Guid.NewGuid().ToString("N");

        await dbContext.Database.ExecuteSqlInterpolatedAsync(
            $"""
                WITH ended AS (
                    UPDATE authentication_session_ledger
                    SET ended_at = {endedAtUtc},
                        end_reason = {reason}
                    WHERE session_id_hash = {sessionIdHash} AND ended_at IS NULL
                    RETURNING principal_id, session_id_hash
                ),
                snapshot AS (
                    SELECT
                        e.principal_id,
                        e.session_id_hash,
                        jsonb_build_object(
                            'id', p.id,
                            'publicId', p.public_id,
                            'displayName', p.display_name,
                            'issuer', p.issuer,
                            'subject', p.subject
                        ) AS principal_snapshot
                    FROM ended e
                    JOIN principals p ON p.id = e.principal_id
                )
                INSERT INTO audit_events (
                    event_type,
                    schema_version,
                    occurred_at,
                    actor_kind,
                    actor_principal_id,
                    subject_principal_id,
                    actor_snapshot,
                    subject_snapshot,
                    session_id_hash,
                    correlation_id,
                    source,
                    outcome,
                    reason_code
                )
                SELECT
                    'authentication.session.ended',
                    1,
                    {endedAtUtc},
                    'principal',
                    principal_id,
                    principal_id,
                    principal_snapshot,
                    principal_snapshot,
                    session_id_hash,
                    {correlationId},
                    'pam.api',
                    'success',
                    {reason}
                FROM snapshot
             """, cancellationToken);
    }
}
