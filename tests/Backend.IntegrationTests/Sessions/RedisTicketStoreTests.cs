using Infrastructure.Authentication;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Microsoft.AspNetCore.DataProtection;

namespace Backend.IntegrationTests.Sessions;

public sealed class RedisTicketStoreTests(RedisFixture redis) : IClassFixture<RedisFixture>
{
    [Fact]
    public async Task TryRenewAsync_ConcurrentRemoval_DoesNotResurrectSession()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        var id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        var renewal = SessionTestData.Ticket(clock.Now.AddMinutes(16));
        clock.Now = clock.Now.AddMinutes(16);

        // Act
        await Task.WhenAll(store.TryRenewAsync(id, renewal), store.RemoveAsync(id));

        // Assert
        Assert.False(await redis.Connection.GetDatabase().KeyExistsAsync(SessionTestData.RedisKey(id)));
    }

    [Fact]
    public async Task TryRenewAsync_WithExpiredStoredTicket_DoesNotReviveSession()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        var id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        clock.Now = clock.Now.AddMinutes(30);
        var renewal = SessionTestData.Ticket(clock.Now);

        // Act
        var renewed = await store.TryRenewAsync(id, renewal);

        // Assert
        Assert.False(renewed);
        Assert.Null(await store.RetrieveAsync(id));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RenewAsync_WithOutOfOrderRequests_PreservesLatestExpiryAndTtl(bool concurrent)
    {
        // Arrange
        var clock = new TestTimeProvider();
        var protection = new EphemeralDataProtectionProvider();
        var first = new RedisTicketStore(redis.Connection, protection, clock);
        var second = new RedisTicketStore(redis.Connection, protection, clock);
        var id = await first.StoreAsync(SessionTestData.Ticket(clock.Now));
        var older = SessionTestData.Ticket(clock.Now.AddMinutes(16));
        var newer = SessionTestData.Ticket(clock.Now.AddMinutes(20));
        clock.Now = clock.Now.AddMinutes(20);

        // Act
        if (concurrent)
            await Task.WhenAll(first.TryRenewAsync(id, newer), second.TryRenewAsync(id, older));
        else
        {
            await first.TryRenewAsync(id, newer);
            await second.TryRenewAsync(id, older);
        }

        // Assert
        var result = await first.RetrieveAsync(id);
        Assert.Equal(newer.Properties.ExpiresUtc, result!.Properties.ExpiresUtc);
        var ttl = await redis.Connection.GetDatabase().KeyTimeToLiveAsync(SessionTestData.RedisKey(id));
        Assert.InRange(ttl ?? TimeSpan.Zero, TimeSpan.FromMinutes(29), TimeSpan.FromMinutes(30));
    }

    [Fact]
    public async Task StoreAsync_TicketCanBeRetrievedByAnotherStoreWithSharedProtectionKeys()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var protection = new EphemeralDataProtectionProvider();
        var writer = new RedisTicketStore(redis.Connection, protection, clock);
        var reader = new RedisTicketStore(redis.Connection, protection, clock);
        var id = await writer.StoreAsync(SessionTestData.Ticket(clock.Now));

        // Act
        var ticket = await reader.RetrieveAsync(id);

        // Assert
        Assert.Equal("Ana Horvat", ticket?.Principal.Identity?.Name);
    }

    [Fact]
    public async Task StoreAsync_SetsBoundedRedisTtl()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);

        // Act
        var id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));

        // Assert
        var ttl = await redis.Connection.GetDatabase().KeyTimeToLiveAsync(SessionTestData.RedisKey(id));
        Assert.InRange(ttl ?? TimeSpan.Zero, TimeSpan.FromMinutes(29), TimeSpan.FromMinutes(30));
    }

    [Fact]
    public async Task RetrieveAsync_WhenTicketExpires_RejectsItEvenIfRedisEntryStillExists()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        var id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        clock.Now = clock.Now.AddMinutes(30);

        // Act
        var ticket = await store.RetrieveAsync(id);

        // Assert
        Assert.Null(ticket);
    }

    [Fact]
    public async Task RenewAsync_AfterRemoval_DoesNotResurrectSession()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        var ticket = SessionTestData.Ticket(clock.Now);
        var id = await store.StoreAsync(ticket);
        await store.RemoveAsync(id);

        // Act
        await store.TryRenewAsync(id, ticket);

        // Assert
        Assert.False(await redis.Connection.GetDatabase().KeyExistsAsync(SessionTestData.RedisKey(id)));
    }

    [Fact]
    public async Task RetrieveAsync_WhenPayloadIsCopiedToAnotherSessionKey_RejectsIt()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        var source = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        var target = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        var database = redis.Connection.GetDatabase();
        var copiedPayload = await database.StringGetAsync(SessionTestData.RedisKey(source));
        await database.StringSetAsync(SessionTestData.RedisKey(target), copiedPayload);

        // Act
        var ticket = await store.RetrieveAsync(target);

        // Assert
        Assert.Null(ticket);
    }
}
