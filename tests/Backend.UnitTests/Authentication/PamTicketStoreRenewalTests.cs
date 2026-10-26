using Backend.Tests.Support;
using FakeItEasy;
using StackExchange.Redis;

namespace Backend.UnitTests.Authentication;

public sealed class PamTicketStoreRenewalTests
{
    private static readonly string SessionId = new('A', 64);

    [Fact]
    public async Task RenewAsync_AfterAbsoluteDeadline_DoesNotWriteRedis()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var ticket = fixture.StartedTicket();
        fixture.Clock.Now = fixture.Clock.Now.AddHours(8);
        ticket.Properties.ExpiresUtc = fixture.Clock.Now.AddMinutes(30);

        // Act
        await fixture.Store.RenewAsync(SessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Database.StringSetAsync(A<RedisKey>._, A<RedisValue>._,
            A<TimeSpan?>._, When.Exists)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RenewAsync_WithoutAbsoluteDeadline_DoesNotWriteRedis()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var ticket = SessionTestData.Ticket(fixture.Clock.Now);

        // Act
        await fixture.Store.RenewAsync(SessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Database.StringSetAsync(A<RedisKey>._, A<RedisValue>._,
            A<TimeSpan?>._, When.Exists)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RenewAsync_WhenRedisSucceeds_UpdatesLedgerExpiry()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var ticket = fixture.StartedTicket();
        A.CallTo(() => fixture.Database.StringSetAsync(A<RedisKey>._, A<RedisValue>._,
            A<TimeSpan?>._, When.Exists)).Returns(true);

        // Act
        await fixture.Store.RenewAsync(SessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(SessionTestData.Hash(SessionId),
            ticket.Properties.ExpiresUtc!.Value, CancellationToken.None)).MustHaveHappenedOnceExactly();
    }

    [Fact]
    public async Task RenewAsync_WhenRedisSessionIsMissing_DoesNotUpdateLedger()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var ticket = fixture.StartedTicket();
        A.CallTo(() => fixture.Database.StringSetAsync(A<RedisKey>._, A<RedisValue>._,
            A<TimeSpan?>._, When.Exists)).Returns(false);

        // Act
        await fixture.Store.RenewAsync(SessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(A<string>._,
            A<DateTimeOffset>._, A<CancellationToken>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RenewAsync_WhenRedisFails_DoesNotUpdateLedger()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        A.CallTo(() => fixture.Database.StringSetAsync(A<RedisKey>._, A<RedisValue>._,
            A<TimeSpan?>._, When.Exists)).ThrowsAsync(new InvalidOperationException("Redis unavailable"));

        // Act
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Store.RenewAsync(SessionId, fixture.StartedTicket()));

        // Assert
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(A<string>._,
            A<DateTimeOffset>._, A<CancellationToken>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RenewAsync_WhenLedgerFails_PropagatesOriginalFailure()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var failure = new InvalidOperationException("Database unavailable");
        A.CallTo(() => fixture.Database.StringSetAsync(A<RedisKey>._, A<RedisValue>._,
            A<TimeSpan?>._, When.Exists)).Returns(true);
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(A<string>._,
            A<DateTimeOffset>._, A<CancellationToken>._)).ThrowsAsync(failure);

        // Act
        var error = await Record.ExceptionAsync(() =>
            fixture.Store.RenewAsync(SessionId, fixture.StartedTicket()));

        // Assert
        Assert.Same(failure, error);
    }

    [Fact]
    public async Task RenewAsync_WhenLedgerFails_DoesNotRevokeExistingSession()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        A.CallTo(() => fixture.Database.StringSetAsync(A<RedisKey>._, A<RedisValue>._,
            A<TimeSpan?>._, When.Exists)).Returns(true);
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(A<string>._,
            A<DateTimeOffset>._, A<CancellationToken>._))
            .ThrowsAsync(new InvalidOperationException("Database unavailable"));

        // Act
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Store.RenewAsync(SessionId, fixture.StartedTicket()));

        // Assert
        A.CallTo(() => fixture.Database.KeyDeleteAsync(A<RedisKey>._, CommandFlags.None)).MustNotHaveHappened();
    }
}
