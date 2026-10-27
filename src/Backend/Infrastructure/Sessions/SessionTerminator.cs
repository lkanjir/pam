using Application.Sessions;
using Infrastructure.Authentication;
using Microsoft.Extensions.Logging;

namespace Infrastructure.Sessions;

public sealed class SessionTerminator(
    ISessionTicketStore ticketStore,
    ISessionLedgerWriter ledgerWriter,
    TimeProvider timeProvider,
    ILogger<SessionTerminator> logger)
{
    public async Task EndSessionAsync(string sessionId, SessionEndReason reason, string? correlationId)
    {
        var reasonCode = reason.ToCode();
        if (!SessionIdentifier.IsValid(sessionId))
            return;

        // Revocation must succeed before recording an end. Once revoked, audit
        // persistence must not be cancelled by the HTTP client disconnecting.
        await ticketStore.RemoveAsync(sessionId);
        var sessionIdHash = SessionIdentifier.Hash(sessionId);
        try
        {
            await ledgerWriter.RecordEndedAsync(sessionIdHash, timeProvider.GetUtcNow(), reasonCode,
                CancellationToken.None);
        }
        catch (Exception exception)
        {
            logger.LogError(
                "Session was revoked, but its ledger/audit end could not be persisted. " +
                "Session hash: {SessionIdHash}; correlation: {CorrelationId}; error type: {ErrorType}.",
                sessionIdHash, correlationId, exception.GetType().Name);
        }
    }
}
