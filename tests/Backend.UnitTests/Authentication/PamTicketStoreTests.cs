using Application.Sessions;
using Backend.Tests.Support;
using FakeItEasy;
using Microsoft.AspNetCore.Http;
using StackExchange.Redis;

namespace Backend.UnitTests.Authentication;

public sealed class PamTicketStoreTests
{
    [Fact]
    public async Task StoreAsync_WhenLedgerIsPending_DoesNotComplete()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        A.CallTo(() => fixture.Ledger.RecordStartedAsync(A<SessionStarted>._, A<CancellationToken>._))
            .Returns(completion.Task);

        // Act
        var storing = fixture.Store.StoreAsync(SessionTestData.Ticket(fixture.Clock.Now));
        var wasPending = !storing.IsCompleted;
        completion.SetResult();
        await storing;

        // Assert
        Assert.True(wasPending);
    }

    [Fact]
    public async Task StoreAsync_WhenLedgerFails_RemovesUnissuedSession()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        A.CallTo(() => fixture.Ledger.RecordStartedAsync(A<SessionStarted>._, A<CancellationToken>._))
            .ThrowsAsync(new InvalidOperationException("Database unavailable"));
        RedisKey storedKey = default;
        A.CallTo(() => fixture.Database.StringSetAsync(A<RedisKey>._, A<RedisValue>._,
                A<TimeSpan?>._, When.NotExists))
            .Invokes(call => storedKey = call.GetArgument<RedisKey>(0)).Returns(true);

        // Act
        await Record.ExceptionAsync(() => fixture.Store.StoreAsync(SessionTestData.Ticket(fixture.Clock.Now)));

        // Assert
        A.CallTo(() => fixture.Database.KeyDeleteAsync(storedKey, CommandFlags.None)).MustHaveHappenedOnceExactly();
    }

    [Fact]
    public async Task StoreAsync_WhenCleanupAlsoFails_PreservesOriginalFailure()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var original = new InvalidOperationException("Database unavailable");
        A.CallTo(() => fixture.Ledger.RecordStartedAsync(A<SessionStarted>._, A<CancellationToken>._))
            .ThrowsAsync(original);
        A.CallTo(() => fixture.Database.KeyDeleteAsync(A<RedisKey>._, CommandFlags.None))
            .ThrowsAsync(new InvalidOperationException("Redis unavailable"));

        // Act
        var error = await Record.ExceptionAsync(() => fixture.Store.StoreAsync(SessionTestData.Ticket(fixture.Clock.Now)));

        // Assert
        Assert.Same(original, error);
    }

    [Fact]
    public async Task StoreAsync_WhenRedisFails_DoesNotWriteLedger()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        A.CallTo(() => fixture.Database.StringSetAsync(A<RedisKey>._, A<RedisValue>._,
            A<TimeSpan?>._, When.NotExists)).ThrowsAsync(new InvalidOperationException("Redis unavailable"));

        // Act
        await Record.ExceptionAsync(() => fixture.Store.StoreAsync(SessionTestData.Ticket(fixture.Clock.Now)));

        // Assert
        A.CallTo(() => fixture.Ledger.RecordStartedAsync(A<SessionStarted>._, A<CancellationToken>._))
            .MustNotHaveHappened();
    }

    [Fact]
    public async Task StoreAsync_WhenCancelledAfterRedisWrite_StillAttemptsCleanup()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        using var cancellation = new CancellationTokenSource();
        A.CallTo(() => fixture.Ledger.RecordStartedAsync(A<SessionStarted>._, cancellation.Token))
            .ReturnsLazily(() => { cancellation.Cancel(); return Task.FromCanceled(cancellation.Token); });

        // Act
        await Record.ExceptionAsync(() => fixture.Store.StoreAsync(SessionTestData.Ticket(fixture.Clock.Now), cancellation.Token));

        // Assert
        A.CallTo(() => fixture.Database.KeyDeleteAsync(A<RedisKey>._, CommandFlags.None)).MustHaveHappenedOnceExactly();
    }

    [Fact]
    public async Task StoreAsync_PersistsHashInsteadOfRawSessionId()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        SessionStarted? recorded = null;
        A.CallTo(() => fixture.Ledger.RecordStartedAsync(A<SessionStarted>._, A<CancellationToken>._))
            .Invokes(call => recorded = call.GetArgument<SessionStarted>(0));

        // Act
        var id = await fixture.Store.StoreAsync(SessionTestData.Ticket(fixture.Clock.Now));

        // Assert
        Assert.Equal(SessionTestData.Hash(id), recorded?.SessionIdHash);
    }

    [Fact]
    public async Task StoreAsync_WithHttpContext_PreservesRequestCorrelation()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var context = new DefaultHttpContext { TraceIdentifier = "request-42" };

        // Act
        await fixture.Store.StoreAsync(SessionTestData.Ticket(fixture.Clock.Now), context, CancellationToken.None);

        // Assert
        A.CallTo(() => fixture.Ledger.RecordStartedAsync(
            A<SessionStarted>.That.Matches(s => s.CorrelationId == "request-42"), A<CancellationToken>._))
            .MustHaveHappenedOnceExactly();
    }

    [Fact]
    public async Task StoreAsync_WithLongUserAgent_TruncatesToDatabaseLimit()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var context = new DefaultHttpContext();
        context.Request.Headers.UserAgent = new string('a', 2049);

        // Act
        await fixture.Store.StoreAsync(SessionTestData.Ticket(fixture.Clock.Now), context, CancellationToken.None);

        // Assert
        A.CallTo(() => fixture.Ledger.RecordStartedAsync(
            A<SessionStarted>.That.Matches(s => s.UserAgent == new string('a', 2048)), A<CancellationToken>._))
            .MustHaveHappenedOnceExactly();
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("0")]
    [InlineData("-1")]
    public async Task StoreAsync_WithInvalidPrincipal_DoesNotWriteLedger(string principalId)
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var ticket = SessionTestData.Ticket(fixture.Clock.Now, principalId);

        // Act
        await Record.ExceptionAsync(() => fixture.Store.StoreAsync(ticket));

        // Assert
        A.CallTo(() => fixture.Ledger.RecordStartedAsync(A<SessionStarted>._, A<CancellationToken>._))
            .MustNotHaveHappened();
    }
}
