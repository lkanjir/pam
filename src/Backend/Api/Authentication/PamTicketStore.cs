using Application.Common.Diagnostics;
using Application.Sessions;
using Infrastructure.Authentication;
using Infrastructure.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Api.Authentication;

public sealed class PamTicketStore(
    ISessionTicketStore ticketStore,
    IServiceScopeFactory scopeFactory,
    TimeProvider timeProvider,
    PamSessionLifetime sessionLifetime,
    ILogger<PamTicketStore> logger) : ITicketStore
{
    private static readonly Action<ILogger, string, string?, string, Exception?> LogUnissuedSessionRemovalFailure =
        LoggerMessage.Define<string, string?, string>(
            LogLevel.Error,
            new EventId(0),
            "Failed to remove an unissued session. " +
            "Error type: {ErrorType}; correlation: {CorrelationId}; location: {ErrorLocation}. " +
            "The stored ticket will expire through its TTL.");

    private static readonly Action<ILogger, string, string, string?, string, Exception?> LogRenewalFailure =
        LoggerMessage.Define<string, string, string?, string>(LogLevel.Error, new EventId(0),
            "Session renewal is retained in Redis; ledger reconciliation will retry. " +
            "Session hash: {SessionIdHash}; error type: {ErrorType}; database code: {DatabaseCode}; location: {ErrorLocation}.");

    public Task<string> StoreAsync(AuthenticationTicket ticket) =>
        StoreCoreAsync(ticket, null, CancellationToken.None);

    public Task<string> StoreAsync(AuthenticationTicket ticket, CancellationToken cancellationToken) =>
        StoreCoreAsync(ticket, null, cancellationToken);

    public Task<string> StoreAsync(
        AuthenticationTicket ticket,
        HttpContext httpContext,
        CancellationToken cancellationToken) =>
        StoreCoreAsync(ticket, httpContext, cancellationToken);

    private async Task<string> StoreCoreAsync(AuthenticationTicket ticket, HttpContext? context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        sessionLifetime.Initialize(ticket.Properties);

        await using var scope = scopeFactory.CreateAsyncScope();

        var ledgerWriter = scope.ServiceProvider.GetRequiredService<ISessionLedgerWriter>();
        var sessionId = await ticketStore.StoreAsync(ticket);

        try
        {
            var session = SessionStartedFactory.Create(sessionId, ticket, context, timeProvider.GetUtcNow());
            await ledgerWriter.RecordStartedAsync(session, cancellationToken);

            return sessionId;
        }
        catch
        {
            await TryRemoveUnissuedSessionAsync(sessionId, context?.TraceIdentifier);
            throw;
        }
    }

    private async Task TryRemoveUnissuedSessionAsync(string sessionId, string? correlationId)
    {
        try
        {
            await ticketStore.DiscardUnissuedAsync(sessionId);
        }
        catch (Exception ex)
        {
            var diagnostic = ExceptionDiagnostics.Capture(ex);
            LogUnissuedSessionRemovalFailure(
                logger,
                diagnostic.ErrorType,
                correlationId,
                diagnostic.Location,
                null);
        }
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket) => RenewAsync(key, ticket, CancellationToken.None);

    public async Task RenewAsync(string key, AuthenticationTicket ticket, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!sessionLifetime.TryLimitExpiration(ticket.Properties))
        {
            return;
        }

        await using var scope = scopeFactory.CreateAsyncScope();
        var ledgerWriter = scope.ServiceProvider.GetRequiredService<ISessionLedgerWriter>();

        var renewed = await ticketStore.TryRenewAsync(key, ticket);
        if (!renewed)
        {
            return;
        }

        var expiresAt = ticket.Properties.ExpiresUtc
            ?? throw new InvalidOperationException("Renewed authentication ticket must have an expiration time.");
        string hash = SessionIdentifier.Hash(key);
        try
        {
            await ledgerWriter.RecordRenewedAsync(hash, expiresAt, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            var diagnostic = ExceptionDiagnostics.Capture(exception);
            LogRenewalFailure(logger, hash, diagnostic.ErrorType, diagnostic.DatabaseCode, diagnostic.Location, null);
        }
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var ticket = await ticketStore.RetrieveAsync(key);
        return ticket is not null && sessionLifetime.IsValid(ticket.Properties) ? ticket : null;
    }

    public Task RemoveAsync(string key) => ticketStore.RemoveAsync(key);

    public async Task RemoveAsync(string key, HttpContext httpContext, CancellationToken cancellationToken)
    {
        if (PamSessionSignOut.GetEndReason(httpContext) is not { } reason)
        {
            // Framework cleanup, without an explicit session-ending intent.
            await RemoveAsync(key);
            return;
        }

        await using var scope = scopeFactory.CreateAsyncScope();
        var terminator = scope.ServiceProvider.GetRequiredService<SessionTerminator>();
        await terminator.EndSessionAsync(key, reason, httpContext.TraceIdentifier);
    }
}
