using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Infrastructure.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace Backend.IntegrationTests.Sessions;

public sealed class SessionRecoveryStoreTests(RedisFixture redis) : IClassFixture<RedisFixture>
{
    [Fact]
    public async Task Store_TicketAndLease_ExposeOnlyNonSecretRecoveryMetadata()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);

        // Act
        string id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        var state = await store.ObserveAsync(SessionIdentifier.Hash(id));

        // Assert
        Assert.True(state.HasTicket);
        Assert.Equal(clock.Now.AddMinutes(30), state.TicketExpiresAt);
        Assert.Equal(clock.Now.AddMinutes(30), state.LeaseExpiresAt);
        Assert.NotNull(state.LeaseVersion);
        Assert.DoesNotContain(id, state.LeaseVersion, StringComparison.Ordinal);
        Assert.DoesNotContain("Ana Horvat", state.LeaseVersion, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Renew_StaleRenewalAndTicketLoss_PreservesTheLatestKnownLease()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        string id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        var original = SessionTestData.Ticket(clock.Now);
        clock.Now = clock.Now.AddMinutes(16);
        Assert.True(await store.TryRenewAsync(id, SessionTestData.Ticket(clock.Now)));

        // Act
        bool stale = await store.TryRenewAsync(id, original);
        await store.RemoveAsync(id);
        var state = await store.ObserveAsync(SessionIdentifier.Hash(id));

        // Assert
        Assert.False(stale);
        Assert.False(state.HasTicket);
        Assert.Null(state.TicketExpiresAt);
        Assert.Equal(clock.Now.AddMinutes(30), state.LeaseExpiresAt);
    }

    [Fact]
    public async Task Discard_UnissuedSession_RemovesBothTicketAndRecoveryLease()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        string id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));

        // Act
        await store.DiscardUnissuedAsync(id);
        var state = await store.ObserveAsync(SessionIdentifier.Hash(id));

        // Assert
        Assert.Equal(new SessionObservation(false, null, null, null), state);
    }
}
