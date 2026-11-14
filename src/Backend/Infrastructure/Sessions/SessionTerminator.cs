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
    private static readonly Action<ILogger, string, string, string, Exception?> LogSessionEndFailure =
        LoggerMessage.Define<string, string, string>(
            LogLevel.Error,
            new EventId(0),
            "Session was revoked, but its ledger/audit end could not be persisted. " +
            "Session hash: {SessionIdHash}; correlation: {CorrelationId}; error type: {ErrorType}.");

    public async Task EndSessionAsync(string sessionId, SessionEndReason reason, string correlationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(correlationId);

        string reasonCode = reason.ToCode();
        if (!SessionIdentifier.IsValid(sessionId))
        {
            return;
        }

        await ticketStore.RemoveAsync(sessionId);
        string sessionIdHash = SessionIdentifier.Hash(sessionId);
        try
        {
            await ledgerWriter.RecordEndedAsync(
                sessionIdHash,
                timeProvider.GetUtcNow(),
                reasonCode,
                correlationId,
                CancellationToken.None);
        }
        catch (Exception exception)
        {
            LogSessionEndFailure(
                logger,
                sessionIdHash,
                correlationId,
                exception.GetType().Name,
                null);
        }
    }
}
