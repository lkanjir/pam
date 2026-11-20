using Application.Common.Diagnostics;
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
    private static readonly Action<ILogger, string, string, string, string?, string, Exception?> LogSessionEndFailure =
        LoggerMessage.Define<string, string, string, string?, string>(
            LogLevel.Error,
            new EventId(0),
            "Session was revoked; its ledger/audit completion will be retried. " +
            "Session hash: {SessionIdHash}; correlation: {CorrelationId}; error type: {ErrorType}; "
            + "database code: {DatabaseCode}; location: {ErrorLocation}.");

    public async Task EndSessionAsync(string sessionId, SessionEndReason reason, string correlationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(correlationId);

        string reasonCode = reason.ToCode();
        if (!SessionIdentifier.IsValid(sessionId))
        {
            return;
        }

        string sessionIdHash = SessionIdentifier.Hash(sessionId);
        PendingSessionEnd? end;
        try
        {
            end = await ticketStore.EndAsync(new PendingSessionEnd(sessionIdHash,
                timeProvider.GetUtcNow(), reasonCode, correlationId));
        }
        catch
        {
            // If recovery metadata cannot be retained, still attempt the security-critical revocation.
            await ticketStore.RemoveAsync(sessionId);
            throw;
        }

        if (end is null)
        {
            return;
        }

        await PersistCompletionAsync(sessionIdHash, end, correlationId);
    }

    public async Task<bool> TryEndForReauthenticationAsync(
        string sessionIdHash, SessionObservation observed, string correlationId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(correlationId);
        cancellationToken.ThrowIfCancellationRequested();
        var now = timeProvider.GetUtcNow();
        if (!SessionIdentifier.IsValid(sessionIdHash) || !observed.HasTicket || observed.PendingEnd is not null
            || observed.TicketExpiresAt is not { } expiresAt || expiresAt <= now)
        {
            return false;
        }

        var end = await ticketStore.EndAsync(new PendingSessionEnd(sessionIdHash, now,
            SessionEndReason.Reauthentication.ToCode(), correlationId,
            observed.LeaseExpiresAt ?? observed.TicketExpiresAt), observed);
        if (end is null)
        {
            return false;
        }

        await PersistCompletionAsync(sessionIdHash, end, correlationId);
        return true;
    }

    private async Task PersistCompletionAsync(string sessionIdHash, PendingSessionEnd end, string correlationId)
    {
        try
        {
            if (end.ExpectedExpiresAt is { } expiry)
            {
                await ledgerWriter.RecordRenewedAsync(sessionIdHash, expiry, CancellationToken.None);
            }

            await ledgerWriter.RecordEndedAsync(
                sessionIdHash,
                end.EndedAt,
                end.Reason,
                end.CorrelationId,
                CancellationToken.None);
            await ticketStore.AcknowledgeEndAsync(sessionIdHash);
        }
        catch (Exception exception)
        {
            var diagnostic = ExceptionDiagnostics.Capture(exception);
            LogSessionEndFailure(
                logger,
                sessionIdHash,
                correlationId,
                diagnostic.ErrorType,
                diagnostic.DatabaseCode,
                diagnostic.Location,
                null);
        }
    }
}
