using Application.Sessions;
using Infrastructure.Authentication;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Sessions;

internal static class PrincipalSessionRevocation
{
    private const int BatchSize = 200;

    // The caller holds the principal FOR UPDATE until its privilege change commits.
    // Publication commits the ledger FK before issuing a cookie, so that lock fences
    // previously published sessions without adding a version claim to their tickets.
    public static async Task<bool> RevokeBeforeRestorationAsync(PamDbContext database, ISessionTicketStore tickets,
        TimeProvider clock, long principalId, DateTimeOffset revokedAt, string correlationId, CancellationToken cancellationToken)
    {
        var sessions = await database.AuthenticationSessionLedgers
            .Where(session => session.PrincipalId == principalId && session.EndedAt == null)
            .OrderBy(session => session.Id).Take(BatchSize + 1)
            .Select(session => new IssuedSession(session.SessionIdHash, session.CreatedAt)).ToListAsync(cancellationToken);
        foreach (var session in sessions.Take(BatchSize))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var observed = await tickets.ObserveAsync(session.Hash);
            if (!observed.HasTicket)
            {
                continue;
            }
            var now = clock.GetUtcNow();
            var expiry = observed.LeaseExpiresAt ?? observed.TicketExpiresAt;
            bool expired = expiry is { } deadline && deadline <= now;
            var createdAt = new DateTimeOffset(session.CreatedAt, TimeSpan.Zero);
            var endedAt = expired && expiry is { } expiredAt ? expiredAt : revokedAt < createdAt ? createdAt : revokedAt;
            var reason = expired ? SessionEndReason.Expired : SessionEndReason.AccessChanged;
            var completion = await tickets.EndAsync(new PendingSessionEnd(session.Hash, endedAt, reason.ToCode(), correlationId, expiry), observed);
            if (completion is null && (await tickets.ObserveAsync(session.Hash)).HasTicket)
            {
                return false;
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        // Pending end audits are deliberately completed outside the caller's transaction;
        // their FK checks must not wait on the principal lock held by this request.
        return sessions.Count <= BatchSize;
    }

    private sealed record IssuedSession(string Hash, DateTime CreatedAt);
}
