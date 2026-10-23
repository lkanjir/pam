using Application.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Api.Authentication;

public sealed class PamTicketStore(
    RedisTicketStore redisStore,
    IServiceScopeFactory scopeFactory,
    TimeProvider timeProvider,
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

    public Task RenewAsync(string key, AuthenticationTicket ticket) => redisStore.RenewAsync(key, ticket);

    public Task<AuthenticationTicket?> RetrieveAsync(string key) => redisStore.RetrieveAsync(key);

    public Task RemoveAsync(string key) => redisStore.RemoveAsync(key);
}