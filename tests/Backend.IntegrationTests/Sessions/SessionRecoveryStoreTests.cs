using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Infrastructure.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace Backend.IntegrationTests.Sessions;

public sealed class SessionRecoveryStoreTests(RedisFixture redis) : IClassFixture<RedisFixture>
{
    [Fact]
    public async Task End_IdenticalConcurrentObservedIntents_OnlyOneCallerWins()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        string id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        string hash = SessionIdentifier.Hash(id);
        var observed = await store.ObserveAsync(hash);
        var intent = new PendingSessionEnd(hash, clock.Now, "reauthentication", "shared-correlation");

        // Act
        var results = await Task.WhenAll(store.EndAsync(intent, observed), store.EndAsync(intent, observed));

        // Assert
        var winner = Assert.Single(results, result => result is not null);
        Assert.Single(results, result => result is null);
        Assert.Equal(intent with { ExpectedExpiresAt = clock.Now.AddMinutes(30) }, winner);
        Assert.Null(await store.RetrieveAsync(id));
        Assert.Equal(winner, (await store.ObserveAsync(hash)).PendingEnd);
        await store.AcknowledgeEndAsync(hash);
    }

    [Fact]
    public async Task End_LogoutWonAfterObservation_DoesNotReportSuccessfulReauthentication()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        string id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        string hash = SessionIdentifier.Hash(id);
        var observed = await store.ObserveAsync(hash);
        var logout = await store.EndAsync(new PendingSessionEnd(hash, clock.Now, "logout", "shared-correlation"));
        Assert.NotNull(logout);

        // Act
        var result = await store.EndAsync(new PendingSessionEnd(hash, clock.Now, "reauthentication", "shared-correlation"), observed);

        // Assert
        Assert.Null(result);
        Assert.Equal(logout, (await store.ObserveAsync(hash)).PendingEnd);
        Assert.Null(await store.RetrieveAsync(id));
        await store.AcknowledgeEndAsync(hash);
    }

    [Fact]
    public async Task End_RepeatedIntent_RetainsOriginalReasonTimeAndCorrelationUntilAcknowledged()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        var initial = clock.Now;
        string id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        string hash = SessionIdentifier.Hash(id);
        clock.Now = clock.Now.AddMinutes(1);
        var requested = new PendingSessionEnd(hash, clock.Now, "logout", "first-request");
        var first = await store.EndAsync(requested);
        Assert.NotNull(first);
        clock.Now = clock.Now.AddMinutes(1);

        // Act
        var second = await store.EndAsync(new PendingSessionEnd(hash, clock.Now, "access_changed", "later-request"));

        // Assert
        Assert.Equal(requested with { ExpectedExpiresAt = initial.AddMinutes(30) }, first);
        Assert.Equal(first, second);
        var state = await store.ObserveAsync(hash);
        Assert.False(state.HasTicket);
        Assert.Null(state.LeaseVersion);
        Assert.Equal(first, state.PendingEnd);
        Assert.False(await store.TryRenewAsync(id, SessionTestData.Ticket(clock.Now)));
        Assert.Contains(first, await store.ReadPendingEndsAsync(1000));
        Assert.Single(await store.ReadPendingEndsAsync(1));
        await store.AcknowledgeEndAsync(hash);
        Assert.Null((await store.ObserveAsync(hash)).PendingEnd);
    }

    [Fact]
    public async Task End_ConcurrentReasons_ReturnsOneImmutableCompletion()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        string id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        string hash = SessionIdentifier.Hash(id);

        // Act
        var results = await Task.WhenAll(
            store.EndAsync(new PendingSessionEnd(hash, clock.Now, "logout", "logout-request")),
            store.EndAsync(new PendingSessionEnd(hash, clock.Now, "access_changed", "access-request")));

        // Assert
        Assert.NotNull(results[0]);
        Assert.Equal(results[0], results[1]);
        Assert.Null(await store.RetrieveAsync(id));
        Assert.Equal(results[0], (await store.ObserveAsync(hash)).PendingEnd);
        await store.AcknowledgeEndAsync(hash);
    }

    [Fact]
    public async Task End_StaleExpiryObservation_DoesNotCloseAConcurrentlyRenewedSession()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        string id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        string hash = SessionIdentifier.Hash(id);
        var observed = await store.ObserveAsync(hash);
        clock.Now = clock.Now.AddMinutes(16);
        Assert.True(await store.TryRenewAsync(id, SessionTestData.Ticket(clock.Now)));
        clock.Now = clock.Now.AddMinutes(15);

        // Act
        var result = await store.EndAsync(new PendingSessionEnd(hash, clock.Now.AddMinutes(-1), "expired", "stale-observer"), observed);

        // Assert
        Assert.Null(result);
        Assert.Equal(clock.Now.AddMinutes(15), (await store.RetrieveAsync(id))?.Properties.ExpiresUtc);
        Assert.Null((await store.ObserveAsync(hash)).PendingEnd);
        await store.DiscardUnissuedAsync(id);
    }

    [Fact]
    public async Task End_TicketChangedWithoutLeaseChange_RejectsStaleObservation()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        string id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        string hash = SessionIdentifier.Hash(id);
        var original = await store.ObserveAsync(hash);
        clock.Now = clock.Now.AddMinutes(16);
        Assert.True(await store.TryRenewAsync(id, SessionTestData.Ticket(clock.Now)));
        Assert.NotNull(original.LeaseVersion);
        // Simulate a legacy producer that changes the encrypted ticket without updating the lease.
        await redis.Connection.GetDatabase().HashSetAsync("pam:session:leases", hash, original.LeaseVersion);

        // Act
        var result = await store.EndAsync(new PendingSessionEnd(hash, clock.Now, "expired", "old-observer"), original);

        // Assert
        Assert.Null(result);
        Assert.NotNull(await store.RetrieveAsync(id));
        Assert.Null((await store.ObserveAsync(hash)).PendingEnd);
        await store.DiscardUnissuedAsync(id);
    }

    [Fact]
    public async Task PendingEnds_DistinctDatabaseScopes_DoNotDrainEachOthersCompletions()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var protection = new EphemeralDataProtectionProvider();
        var first = new RedisTicketStore(redis.Connection, protection, clock, Guid.NewGuid().ToString("N"));
        var second = new RedisTicketStore(redis.Connection, protection, clock, Guid.NewGuid().ToString("N"));
        string one = SessionIdentifier.Hash(await first.StoreAsync(SessionTestData.Ticket(clock.Now)));
        string two = SessionIdentifier.Hash(await second.StoreAsync(SessionTestData.Ticket(clock.Now)));
        await first.EndAsync(new PendingSessionEnd(one, clock.Now, "logout", "first"));
        await second.EndAsync(new PendingSessionEnd(two, clock.Now, "logout", "second"));

        // Act
        var firstQueue = await first.ReadPendingEndsAsync(10);
        await first.AcknowledgeEndAsync(one);
        var secondQueue = await second.ReadPendingEndsAsync(10);

        // Assert
        Assert.Equal(one, Assert.Single(firstQueue).SessionIdHash);
        Assert.Equal(two, Assert.Single(secondQueue).SessionIdHash);
        Assert.Empty(await first.ReadPendingEndsAsync(10));
        await second.AcknowledgeEndAsync(two);
    }

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
