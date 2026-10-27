using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Application.Sessions;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;

namespace Infrastructure.Authentication;

public sealed class RedisTicketStore : ISessionTicketStore
{
    private readonly IDatabase _database;
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;

    private const string KeyPrefix = "pam:session:";

    public RedisTicketStore(IConnectionMultiplexer redis, IDataProtectionProvider dataProtectionProvider,
        TimeProvider timeProvider)
    {
        _database = redis.GetDatabase();
        _protector = dataProtectionProvider.CreateProtector("Pam.RedisTicketStore");
        _timeProvider = timeProvider;
    }

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var sessionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var redisKey = GetRedisKey(sessionId);
            var payload = Protect(ticket, redisKey);
            var ttl = GetTimeToLive(ticket);

            var stored = await _database.StringSetAsync(redisKey, payload, ttl, When.NotExists);

            if (stored)
                return sessionId;
        }

        throw new InvalidOperationException("Unable to allocate unique session identifier.");
    }

    public async Task<bool> TryRenewAsync(string key, AuthenticationTicket ticket)
    {
        if (!SessionIdentifier.IsValid(key))
            return false;

        var redisKey = GetRedisKey(key);
        var payload = Protect(ticket, redisKey);
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var previous = await _database.StringGetAsync(redisKey);
            var current = Unprotect(previous, redisKey);
            if (current?.Properties.ExpiresUtc is not { } currentExpiry
                || currentExpiry <= _timeProvider.GetUtcNow()
                || ticket.Properties.ExpiresUtc is not { } proposedExpiry
                || proposedExpiry <= currentExpiry)
                return false;

            var ttl = GetTimeToLive(ticket);
            var transaction = _database.CreateTransaction();
            transaction.AddCondition(Condition.StringEqual(redisKey, previous));
            // Queue the write before executing; awaiting it here would deadlock.
            var write = transaction.StringSetAsync(redisKey, payload, ttl);
            if (await transaction.ExecuteAsync())
                return await write;
        }

        // Under sustained contention, leave the winning ticket intact.
        return false;
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        if (!SessionIdentifier.IsValid(key))
            return null;

        var redisKey = GetRedisKey(key);
        var value = await _database.StringGetAsync(redisKey);

        var ticket = Unprotect(value, redisKey);
        return ticket?.Properties.ExpiresUtc is { } expiresAt && expiresAt > _timeProvider.GetUtcNow()
            ? ticket : null;
    }

    private AuthenticationTicket? Unprotect(RedisValue value, string redisKey)
    {
        if (value.IsNull)
            return null;
        try
        {
            var serialized = _protector.CreateProtector(redisKey).Unprotect(value!);
            return TicketSerializer.Default.Deserialize(serialized);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    public async Task RemoveAsync(string key)
    {
        if (!SessionIdentifier.IsValid(key))
            return;

        await _database.KeyDeleteAsync(GetRedisKey(key));
    }

    private static string GetRedisKey(string sessionId) => KeyPrefix + SessionIdentifier.Hash(sessionId);

    private byte[] Protect(AuthenticationTicket ticket, string redisKey)
    {
        var serialized = TicketSerializer.Default.Serialize(ticket);
        return _protector.CreateProtector(redisKey).Protect(serialized);
    }

    private TimeSpan GetTimeToLive(AuthenticationTicket ticket)
    {
        if (ticket.Properties.ExpiresUtc is not { } expireAt)
            throw new InvalidOperationException("Authentication ticket must have an expiration time");

        var ttl = expireAt - _timeProvider.GetUtcNow();
        return ttl < TimeSpan.FromMilliseconds(1)
            ? throw new InvalidOperationException("Authentication ticket has expired or is about to expire")
            : ttl;
    }
}
