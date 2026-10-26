using Application.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Api.Authentication;

public sealed class PamTicketStore(
    RedisTicketStore redisStore,
    IServiceScopeFactory scopeFactory,
    TimeProvider timeProvider,
    PamSessionLifetime sessionLifetime,
    ILogger<PamTicketStore> logger) : ITicketStore
{
    public Task<string> StoreAsync(AuthenticationTicket ticket) =>
        StoreCoreAsync(ticket, null, CancellationToken.None);

    public Task<string> StoreAsync(AuthenticationTicket ticket, CancellationToken token) =>
        StoreCoreAsync(ticket, null, token);

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
        var sessionId = await redisStore.StoreAsync(ticket);

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
            await redisStore.RemoveAsync(sessionId);
        }
        catch (Exception ex)
        {
            logger.LogError("Failed to remove an unissued session. " +
                            "Error type: {ErrorType}; correlation: {CorrelationId}. " +
                            "The Redis entry will expire through its TTL.",
                ex.GetType().Name,
                correlationId);
        }
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket) => RenewAsync(key, ticket, CancellationToken.None);

    public async Task RenewAsync(string key, AuthenticationTicket ticket, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!sessionLifetime.TryLimitExpiration(ticket.Properties)) return;

        await using var scope = scopeFactory.CreateAsyncScope();
        var ledgerWriter = scope.ServiceProvider.GetRequiredService<ISessionLedgerWriter>();

        var renewed = await redisStore.TryRenewAsync(key, ticket);
        if (!renewed) return;

        var expiresAt = ticket.Properties.ExpiresUtc!.Value;

        await ledgerWriter.RecordRenewedAsync(SessionIdentifier.Hash(key), expiresAt, token);
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var ticket = await redisStore.RetrieveAsync(key);
        return ticket is not null && sessionLifetime.IsValid(ticket.Properties) ? ticket : null;
    }

    public Task RemoveAsync(string key) => redisStore.RemoveAsync(key);

    public async Task RemoveAsync(string key, HttpContext httpContext, CancellationToken cancellationToken)
    {
        if (!SessionIdentifier.IsValid(key)) return;

        await redisStore.RemoveAsync(key);

        var termination = httpContext.Features.Get<SessionTermination>();
        if (termination is null) return;

        var sessionIdHash = SessionIdentifier.Hash(key);

        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var ledgerWriter = scope.ServiceProvider.GetRequiredService<ISessionLedgerWriter>();

            await ledgerWriter.RecordEndedAsync(sessionIdHash, timeProvider.GetUtcNow(), termination.Reason,
                CancellationToken.None);
        }
        catch (Exception exception)
        {
            logger.LogError(
                "Session was revoked, but its ledger/audit end could not be persisted. " +
                "Session hash: {SessionIdHash}; correlation: {CorrelationId}; " +
                "error type: {ErrorType}.",
                sessionIdHash,
                httpContext.TraceIdentifier,
                exception.GetType().Name);
        }
    }
}
