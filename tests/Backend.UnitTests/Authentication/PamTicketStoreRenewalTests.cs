using Backend.Tests.Support;
using FakeItEasy;
using StackExchange.Redis;

namespace Backend.UnitTests.Authentication;

public sealed class PamTicketStoreRenewalTests
{
    [Fact]
    public async Task RenewAsync_AfterAbsoluteDeadline_DoesNotWriteRedis()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = await fixture.SeedRenewableSessionAsync();
        var ticket = fixture.StartedTicket();
        fixture.Clock.Now = fixture.Clock.Now.AddHours(8);
        ticket.Properties.ExpiresUtc = fixture.Clock.Now.AddMinutes(30);

        // Act
        await fixture.Store.RenewAsync(sessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Database.ScriptEvaluateAsync(A<string>._, A<RedisKey[]>._,
            A<RedisValue[]>._, CommandFlags.None)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RenewAsync_WithoutAbsoluteDeadline_DoesNotWriteRedis()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = await fixture.SeedRenewableSessionAsync();
        var ticket = SessionTestData.Ticket(fixture.Clock.Now);

        // Act
        await fixture.Store.RenewAsync(sessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Database.ScriptEvaluateAsync(A<string>._, A<RedisKey[]>._,
            A<RedisValue[]>._, CommandFlags.None)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RenewAsync_WhenRedisSucceeds_UpdatesLedgerExpiry()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = await fixture.SeedRenewableSessionAsync();
        var ticket = fixture.StartedTicket();
        A.CallTo(() => fixture.Database.ScriptEvaluateAsync(A<string>._, A<RedisKey[]>._,
            A<RedisValue[]>._, CommandFlags.None)).Returns(RedisResult.Create((RedisValue)1));

        // Act
        await fixture.Store.RenewAsync(sessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(SessionTestData.Hash(sessionId),
            ticket.Properties.ExpiresUtc!.Value, CancellationToken.None)).MustHaveHappenedOnceExactly();
    }

    [Fact]
    public async Task RenewAsync_WhenRedisSessionIsMissing_DoesNotUpdateLedger()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = await fixture.SeedRenewableSessionAsync();
        var ticket = fixture.StartedTicket();
        A.CallTo(() => fixture.Database.StringGetAsync(A<RedisKey>._, CommandFlags.None))
            .Returns(RedisValue.Null);

        // Act
        await fixture.Store.RenewAsync(sessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(A<string>._,
            A<DateTimeOffset>._, A<CancellationToken>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RenewAsync_WhenRedisFails_DoesNotUpdateLedger()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = await fixture.SeedRenewableSessionAsync();
        A.CallTo(() => fixture.Database.ScriptEvaluateAsync(A<string>._, A<RedisKey[]>._,
            A<RedisValue[]>._, CommandFlags.None)).ThrowsAsync(new InvalidOperationException("Redis unavailable"));

        // Act
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Store.RenewAsync(sessionId, fixture.StartedTicket()));

        // Assert
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(A<string>._,
            A<DateTimeOffset>._, A<CancellationToken>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RenewAsync_WhenLedgerFails_PropagatesOriginalFailure()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = await fixture.SeedRenewableSessionAsync();
        var failure = new InvalidOperationException("Database unavailable");
        A.CallTo(() => fixture.Database.ScriptEvaluateAsync(A<string>._, A<RedisKey[]>._,
            A<RedisValue[]>._, CommandFlags.None)).Returns(RedisResult.Create((RedisValue)1));
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(A<string>._,
            A<DateTimeOffset>._, A<CancellationToken>._)).ThrowsAsync(failure);

        // Act
        var error = await Record.ExceptionAsync(() =>
            fixture.Store.RenewAsync(sessionId, fixture.StartedTicket()));

        // Assert
        Assert.Same(failure, error);
    }

    [Fact]
    public async Task RenewAsync_WhenLedgerFails_DoesNotRevokeExistingSession()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = await fixture.SeedRenewableSessionAsync();
        A.CallTo(() => fixture.Database.ScriptEvaluateAsync(A<string>._, A<RedisKey[]>._,
            A<RedisValue[]>._, CommandFlags.None)).Returns(RedisResult.Create((RedisValue)1));
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(A<string>._,
            A<DateTimeOffset>._, A<CancellationToken>._))
            .ThrowsAsync(new InvalidOperationException("Database unavailable"));

        // Act
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Store.RenewAsync(sessionId, fixture.StartedTicket()));

        // Assert
        A.CallTo(() => fixture.Database.KeyDeleteAsync(A<RedisKey>._, CommandFlags.None)).MustNotHaveHappened();
    }
}
