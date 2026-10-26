using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;

namespace Api.Authentication;

public sealed class RedisTicketStore : ITicketStore
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

            if (stored) return sessionId;
        }

        throw new InvalidOperationException("Unable to allocate unique session identifier.");
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        await TryRenewAsync(key, ticket);
    }

    public async Task<bool> TryRenewAsync(string key, AuthenticationTicket ticket)
    {
        if (!SessionIdentifier.IsValid(key)) return false;

        var redisKey = GetRedisKey(key);
        var payload = Protect(ticket, redisKey);
        var ttl = GetTimeToLive(ticket);

        return await _database.StringSetAsync(redisKey, payload, ttl, When.Exists);
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        if (!SessionIdentifier.IsValid(key)) return null;

        var redisKey = GetRedisKey(key);
        var value = await _database.StringGetAsync(redisKey);

        if (value.IsNull) return null;

        AuthenticationTicket? ticket;
        try
        {
            var serialized = _protector.CreateProtector(redisKey).Unprotect(value!);
            ticket = TicketSerializer.Default.Deserialize(serialized);
        }
        catch (CryptographicException)
        {
            return null;
        }

        if (ticket?.Properties.ExpiresUtc is not { } expiresAt)
            return null;

        return expiresAt > _timeProvider.GetUtcNow() ? ticket : null;
    }

    public async Task RemoveAsync(string key)
    {
        if (!SessionIdentifier.IsValid(key)) return;

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