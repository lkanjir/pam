using Application.Common.Diagnostics;
using Application.Sessions;
using Infrastructure.Authentication;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Infrastructure.Sessions;

public sealed class SessionReconciler(
    PamDbContext database,
    ISessionTicketStore tickets,
    ISessionLedgerWriter ledger,
    TimeProvider timeProvider,
    ILogger<SessionReconciler> logger)
{
    private static readonly Action<ILogger, string, string, string?, string, Exception?> LogCompletionFailure =
        LoggerMessage.Define<string, string, string?, string>(LogLevel.Error, new EventId(0),
            "Session reconciliation will retry. Session hash: {SessionIdHash}; error type: {ErrorType}; "
            + "database code: {DatabaseCode}; location: {ErrorLocation}.");

    public async Task<SessionReconciliationPosition> RunAsync(
        SessionReconciliationPosition position, int limit, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, 1000);
        cancellationToken.ThrowIfCancellationRequested();
        var pending = await tickets.ReadPendingEndsAsync(limit, cancellationToken);
        foreach (var completion in pending)
        {
            await TryCompleteAsync(completion, cancellationToken);
        }
        var leases = await tickets.ReadLeasePageAsync(position.Leases, limit, cancellationToken);
        foreach (string hash in leases.SessionIdHashes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var observed = await tickets.ObserveAsync(hash);
            if (observed.HasTicket || observed.PendingEnd is not null
                || observed.LeaseExpiresAt is not { } expiry || expiry > timeProvider.GetUtcNow())
            {
                continue;
            }
            await using var publication = await database.Database.BeginTransactionAsync(cancellationToken);
            await SessionPublicationGuard.LockAsync(database, hash, cancellationToken);
            if (!await database.AuthenticationSessionLedgers.AnyAsync(value => value.SessionIdHash == hash, cancellationToken))
            {
                await tickets.DiscardExpiredLeaseAsync(hash, observed);
            }
            await publication.CommitAsync(cancellationToken);
        }
        var nextPosition = position with { Leases = leases.Next };

        long ceiling = position.ThroughId;
        if (ceiling == 0)
        {
            ceiling = await database.AuthenticationSessionLedgers.Where(item => item.EndedAt == null)
                .MaxAsync(item => (long?)item.Id, cancellationToken) ?? 0;
        }

        if (ceiling == 0)
        {
            return nextPosition with { AfterId = 0, ThroughId = 0 };
        }

        var sessions = await (from item in database.AuthenticationSessionLedgers
                              join principal in database.Principals on item.PrincipalId equals principal.Id
                              where item.EndedAt == null && item.Id > position.AfterId && item.Id <= ceiling
                              orderby item.Id
                              select new OpenSession(item.Id, item.SessionIdHash, item.CreatedAt, principal.IsEnabled,
                                  principal.IsEnabled ? null : database.AuditEvents
                                      .Where(audit => audit.SubjectPrincipalId == principal.Id && audit.EventType == "principal.disabled")
                                      .OrderByDescending(audit => audit.Id).Select(audit => (DateTime?)audit.OccurredAt).FirstOrDefault()))
            .Take(limit).ToListAsync(cancellationToken);
        string correlation = "session-reconciliation-" + Guid.CreateVersion7(timeProvider.GetUtcNow()).ToString("N");
        foreach (var session in sessions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Redis failures propagate; an unavailable store must never be interpreted as a missing ticket.
            var observed = await tickets.ObserveAsync(session.Hash);
            if (observed.PendingEnd is { } completion)
            {
                await TryCompleteAsync(completion, cancellationToken);
                continue;
            }

            var now = timeProvider.GetUtcNow();
            if (observed.HasTicket && observed.TicketExpiresAt is { } expiry && expiry > now)
            {
                if (!session.PrincipalEnabled)
                {
                    var disabledAt = session.DisabledAt is { } recorded ? new DateTimeOffset(recorded, TimeSpan.Zero) : now;
                    var createdAt = new DateTimeOffset(session.CreatedAt, TimeSpan.Zero);
                    var disabledIntent = new PendingSessionEnd(session.Hash, disabledAt < createdAt ? createdAt : disabledAt,
                        SessionEndReason.AccessChanged.ToCode(), correlation, expiry);
                    var disabledCompletion = await tickets.EndAsync(disabledIntent, observed);
                    if (disabledCompletion is not null)
                    {
                        await TryCompleteAsync(disabledCompletion, cancellationToken);
                    }
                    continue;
                }
                await ledger.RecordRenewedAsync(session.Hash, expiry, cancellationToken);
                continue;
            }

            var knownExpiry = observed.LeaseExpiresAt ?? observed.TicketExpiresAt;
            bool expired = knownExpiry is { } deadline && deadline <= now;
            var reason = expired ? SessionEndReason.Expired : SessionEndReason.SessionLost;
            var endedAt = expired && knownExpiry is { } expiredAt ? expiredAt : now;
            var intent = new PendingSessionEnd(session.Hash, endedAt, reason.ToCode(), correlation, knownExpiry);
            var sealedCompletion = await tickets.EndAsync(intent, observed);
            if (sealedCompletion is not null)
            {
                await TryCompleteAsync(sealedCompletion, cancellationToken);
            }
        }

        long lastId = sessions.Count == 0 ? ceiling : sessions[^1].Id;
        return nextPosition with { AfterId = lastId >= ceiling ? 0 : lastId, ThroughId = lastId >= ceiling ? 0 : ceiling };
    }

    private async Task TryCompleteAsync(PendingSessionEnd completion, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            if (completion.ExpectedExpiresAt is { } expiry)
            {
                await ledger.RecordRenewedAsync(completion.SessionIdHash, expiry, cancellationToken);
            }

            await ledger.RecordEndedAsync(completion.SessionIdHash, completion.EndedAt,
                completion.Reason, completion.CorrelationId, cancellationToken);
            await tickets.AcknowledgeEndAsync(completion.SessionIdHash);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            var diagnostic = ExceptionDiagnostics.Capture(exception);
            LogCompletionFailure(logger, completion.SessionIdHash, diagnostic.ErrorType,
                diagnostic.DatabaseCode, diagnostic.Location, null);
        }
    }

    private sealed record OpenSession(long Id, string Hash, DateTime CreatedAt, bool PrincipalEnabled, DateTime? DisabledAt);
}
