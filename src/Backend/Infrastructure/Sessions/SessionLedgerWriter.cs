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

        dbContext.AuthenticationSessionLedgers.Add(ledger);
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