using System.Security.Cryptography;
using System.Text.Json;
using Application.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;

namespace Infrastructure.Authentication;

public sealed class RedisTicketStore : ISessionTicketStore
{
    private readonly IDatabase _database;
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;

    private const string KeyPrefix = "pam:session:";
    private readonly string _leasesKey;
    private readonly string _pendingEndsKey;
    private static readonly JsonSerializerOptions RecoveryJsonOptions = new(JsonSerializerDefaults.Web);
    private const string ObserveScript = """
        local ticket = redis.call('GET', KEYS[1])
        return {ticket, redis.call('HGET', KEYS[2], ARGV[1]), redis.call('HGET', KEYS[3], ARGV[1]),
            ticket and redis.sha1hex(ticket) or false}
        """;
    private const string EndScript = """
        local pending = redis.call('HGET', KEYS[3], ARGV[1])
        if pending then
            if ARGV[3] == 'observed' then return false end
            return pending
        end
        local ticket = redis.call('GET', KEYS[1])
        local lease = redis.call('HGET', KEYS[2], ARGV[1])
        if ARGV[3] == 'observed' then
            if (ticket and '1' or '0') ~= ARGV[4] or (lease or '') ~= ARGV[5]
                or (ticket and redis.sha1hex(ticket) or '') ~= ARGV[6] then return false end
        elseif not ticket and not lease then
            return false
        end
        local record = cjson.decode(ARGV[2])
        if lease then record.expectedExpiresAt = cjson.decode(lease).expiresAt end
        local encoded = cjson.encode(record)
        redis.call('HSET', KEYS[3], ARGV[1], encoded)
        redis.call('DEL', KEYS[1])
        redis.call('HDEL', KEYS[2], ARGV[1])
        return encoded
        """;

    public RedisTicketStore(IConnectionMultiplexer redis, IDataProtectionProvider dataProtectionProvider,
        TimeProvider timeProvider, string? recoveryScope = null)
    {
        _database = redis.GetDatabase();
        string suffix = recoveryScope is null ? string.Empty : ":" + recoveryScope;
        _leasesKey = "pam:session:leases" + suffix;
        _pendingEndsKey = "pam:session:pending-ends" + suffix;
        _protector = dataProtectionProvider.CreateProtector("Pam.RedisTicketStore");
        _timeProvider = timeProvider;
    }

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var sessionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var redisKey = GetRedisKey(sessionId);
            ticket.Properties.Items[SessionTicketMetadata.SessionIdHash] = SessionIdentifier.Hash(sessionId);
            var payload = Protect(ticket, redisKey);
            var ttl = GetTimeToLive(ticket);

            var transaction = _database.CreateTransaction();
            transaction.AddCondition(Condition.KeyNotExists(redisKey));
            var write = transaction.StringSetAsync(redisKey, payload, ttl);
            var lease = transaction.HashSetAsync(_leasesKey, SessionIdentifier.Hash(sessionId),
                JsonSerializer.Serialize(new LeaseV1(ticket.Properties.ExpiresUtc), RecoveryJsonOptions));
            if (await transaction.ExecuteAsync())
            {
                await write;
                await lease;
                return sessionId;
            }
        }

        throw new InvalidOperationException("Unable to allocate unique session identifier.");
    }

    public async Task<bool> TryRenewAsync(string key, AuthenticationTicket ticket)
    {
        if (!SessionIdentifier.IsValid(key))
        {
            return false;
        }

        var redisKey = GetRedisKey(key);
        ticket.Properties.Items[SessionTicketMetadata.SessionIdHash] = SessionIdentifier.Hash(key);
        var payload = Protect(ticket, redisKey);
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var previous = await _database.StringGetAsync(redisKey);
            var current = Unprotect(previous, redisKey);
            if (current?.Properties.ExpiresUtc is not { } currentExpiry
                || currentExpiry <= _timeProvider.GetUtcNow()
                || ticket.Properties.ExpiresUtc is not { } proposedExpiry
                || proposedExpiry <= currentExpiry)
            {
                return false;
            }

            var ttl = GetTimeToLive(ticket);
            var transaction = _database.CreateTransaction();
            transaction.AddCondition(Condition.StringEqual(redisKey, previous));
            // Queue the write before executing; awaiting it here would deadlock.
            var write = transaction.StringSetAsync(redisKey, payload, ttl);
            var lease = transaction.HashSetAsync(_leasesKey, SessionIdentifier.Hash(key),
                JsonSerializer.Serialize(new LeaseV1(proposedExpiry), RecoveryJsonOptions));
            if (await transaction.ExecuteAsync())
            {
                await lease;
                return await write;
            }
        }

        // Under sustained contention, leave the winning ticket intact.
        return false;
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        if (!SessionIdentifier.IsValid(key))
        {
            return null;
        }

        var redisKey = GetRedisKey(key);
        var value = await _database.StringGetAsync(redisKey);

        var ticket = Unprotect(value, redisKey);
        if (ticket?.Properties.ExpiresUtc is not { } expiresAt || expiresAt <= _timeProvider.GetUtcNow())
        {
            return null;
        }

        // Derive from the actual storage key, including legacy tickets; never trust a caller's metadata value.
        ticket.Properties.Items[SessionTicketMetadata.SessionIdHash] = SessionIdentifier.Hash(key);
        return ticket;
    }

    private AuthenticationTicket? Unprotect(RedisValue value, string redisKey)
    {
        if (value.IsNull)
        {
            return null;
        }

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
        {
            return;
        }

        await _database.KeyDeleteAsync(GetRedisKey(key));
    }

    public async Task DiscardUnissuedAsync(string key)
    {
        if (!SessionIdentifier.IsValid(key))
        {
            return;
        }

        var transaction = _database.CreateTransaction();
        var ticket = transaction.KeyDeleteAsync(GetRedisKey(key));
        var lease = transaction.HashDeleteAsync(_leasesKey, SessionIdentifier.Hash(key));
        if (await transaction.ExecuteAsync())
        {
            await ticket;
            await lease;
        }
    }

    public async Task<SessionObservation> ObserveAsync(string sessionIdHash)
    {
        if (!SessionIdentifier.IsValid(sessionIdHash))
        {
            throw new ArgumentException("A valid session hash is required.", nameof(sessionIdHash));
        }

        var redisKey = KeyPrefix + sessionIdHash;
        var result = (RedisResult[]?)await _database.ScriptEvaluateAsync(ObserveScript,
            [redisKey, _leasesKey, _pendingEndsKey], [sessionIdHash])
            ?? throw new InvalidOperationException("Session observation returned no result.");
        RedisValue value = (RedisValue)result[0];
        string? token = (string?)result[1];
        var lease = token is null ? null : JsonSerializer.Deserialize<LeaseV1>(token, RecoveryJsonOptions);
        return new SessionObservation(!value.IsNull, Unprotect(value, redisKey)?.Properties.ExpiresUtc,
            lease?.ExpiresAt, token)
        {
            PendingEnd = result[2].IsNull ? null : ReadEnd((string?)result[2], sessionIdHash),
            TicketVersion = (string?)result[3]
        };
    }

    public async Task<PendingSessionEnd?> EndAsync(PendingSessionEnd completion, SessionObservation? expected = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(completion.CorrelationId);
        if (!SessionIdentifier.IsValid(completion.SessionIdHash))
        {
            throw new ArgumentException("A valid session hash is required.", nameof(completion));
        }

        if (expected is null && completion.ExpectedExpiresAt is null)
        {
            var current = await ObserveAsync(completion.SessionIdHash);
            completion = completion with { ExpectedExpiresAt = current.TicketExpiresAt ?? current.LeaseExpiresAt };
        }

        var result = await _database.ScriptEvaluateAsync(EndScript,
            [KeyPrefix + completion.SessionIdHash, _leasesKey, _pendingEndsKey],
            [completion.SessionIdHash, JsonSerializer.Serialize(completion, RecoveryJsonOptions), expected is null ? "explicit" : "observed",
                expected?.HasTicket == true ? "1" : "0", expected?.LeaseVersion ?? string.Empty, expected?.TicketVersion ?? string.Empty]);
        return result.IsNull ? null : ReadEnd((string?)result, completion.SessionIdHash);
    }

    public async Task<IReadOnlyList<PendingSessionEnd>> ReadPendingEndsAsync(
        int limit, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, 1000);
        var result = new List<PendingSessionEnd>();
        await foreach (var entry in _database.HashScanAsync(_pendingEndsKey, pageSize: limit).WithCancellation(cancellationToken))
        {
            result.Add(ReadEnd(entry.Value.ToString(), entry.Name.ToString()));
            if (result.Count == limit)
            {
                break;
            }
        }

        return result;
    }

    public Task AcknowledgeEndAsync(string sessionIdHash)
    {
        if (!SessionIdentifier.IsValid(sessionIdHash))
        {
            throw new ArgumentException("A valid session hash is required.", nameof(sessionIdHash));
        }

        return _database.HashDeleteAsync(_pendingEndsKey, sessionIdHash);
    }

    private static PendingSessionEnd ReadEnd(string? json, string hash)
    {
        var end = json is null ? null : JsonSerializer.Deserialize<PendingSessionEnd>(json, RecoveryJsonOptions);
        if (end is null || end.SessionIdHash != hash || !SessionIdentifier.IsValid(hash)
            || string.IsNullOrWhiteSpace(end.CorrelationId))
        {
            throw new InvalidOperationException("The session recovery record is invalid.");
        }

        return end;
    }

    private sealed record LeaseV1(DateTimeOffset? ExpiresAt);

    private static string GetRedisKey(string sessionId) => KeyPrefix + SessionIdentifier.Hash(sessionId);

    private byte[] Protect(AuthenticationTicket ticket, string redisKey)
    {
        var serialized = TicketSerializer.Default.Serialize(ticket);
        return _protector.CreateProtector(redisKey).Protect(serialized);
    }

    private TimeSpan GetTimeToLive(AuthenticationTicket ticket)
    {
        if (ticket.Properties.ExpiresUtc is not { } expireAt)
        {
            throw new InvalidOperationException("Authentication ticket must have an expiration time");
        }

        var ttl = expireAt - _timeProvider.GetUtcNow();
        return ttl < TimeSpan.FromMilliseconds(1)
            ? throw new InvalidOperationException("Authentication ticket has expired or is about to expire")
            : ttl;
    }
}
