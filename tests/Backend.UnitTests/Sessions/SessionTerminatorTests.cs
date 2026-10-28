using Application.Sessions;
using Backend.Tests.Support;
using FakeItEasy;
using Infrastructure.Authentication;
using Infrastructure.Sessions;
using Microsoft.Extensions.Logging.Abstractions;

namespace Backend.UnitTests.Sessions;

public sealed class SessionTerminatorTests
{
    private static readonly string SessionId = new('A', 64);

    [Theory]
    [InlineData(SessionEndReason.Logout, "logout")]
    [InlineData(SessionEndReason.Reauthentication, "reauthentication")]
    [InlineData(SessionEndReason.AccessChanged, "access_changed")]
    public async Task EndSessionAsync_PersistsStableReasonAfterRevocation(SessionEndReason reason, string code)
    {
        // Arrange
        var tickets = A.Fake<ISessionTicketStore>();
        var ledger = A.Fake<ISessionLedgerWriter>();
        var clock = new TestTimeProvider();
        var revoked = false;
        A.CallTo(() => tickets.RemoveAsync(SessionId)).Invokes(() => revoked = true);
        A.CallTo(() => ledger.RecordEndedAsync(A<string>._, A<DateTimeOffset>._, A<string>._, A<string>._,
                A<CancellationToken>._))
            .Invokes(() => Assert.True(revoked));
        var terminator = new SessionTerminator(tickets, ledger, clock, NullLogger<SessionTerminator>.Instance);

        // Act
        await terminator.EndSessionAsync(SessionId, reason, "request-42");

        // Assert
        A.CallTo(() => ledger.RecordEndedAsync(SessionTestData.Hash(SessionId), clock.Now, code, "request-42",
            CancellationToken.None)).MustHaveHappenedOnceExactly();
    }

    [Fact]
    public async Task EndSessionAsync_WhenRevocationFails_DoesNotRecordEnd()
    {
        // Arrange
        var tickets = A.Fake<ISessionTicketStore>();
        var ledger = A.Fake<ISessionLedgerWriter>();
        var failure = new InvalidOperationException("Storage unavailable");
        A.CallTo(() => tickets.RemoveAsync(SessionId)).ThrowsAsync(failure);
        var terminator = new SessionTerminator(tickets, ledger, new TestTimeProvider(),
            NullLogger<SessionTerminator>.Instance);

        // Act
        var error = await Record.ExceptionAsync(() =>
            terminator.EndSessionAsync(SessionId, SessionEndReason.Logout, "request-42"));

        // Assert
        Assert.Same(failure, error);
        A.CallTo(() => ledger.RecordEndedAsync(A<string>._, A<DateTimeOffset>._, A<string>._, A<string>._,
            A<CancellationToken>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task EndSessionAsync_WhenAuditFails_KeepsRevocationSuccessful()
    {
        // Arrange
        var tickets = A.Fake<ISessionTicketStore>();
        var ledger = A.Fake<ISessionLedgerWriter>();
        A.CallTo(() => ledger.RecordEndedAsync(A<string>._, A<DateTimeOffset>._, A<string>._, A<string>._,
            A<CancellationToken>._)).ThrowsAsync(new InvalidOperationException("Database unavailable"));
        var terminator = new SessionTerminator(tickets, ledger, new TestTimeProvider(),
            NullLogger<SessionTerminator>.Instance);

        // Act
        var error = await Record.ExceptionAsync(() =>
            terminator.EndSessionAsync(SessionId, SessionEndReason.Logout, "request-42"));

        // Assert
        Assert.Null(error);
        A.CallTo(() => tickets.RemoveAsync(SessionId)).MustHaveHappenedOnceExactly();
        A.CallTo(() => tickets.StoreAsync(A<Microsoft.AspNetCore.Authentication.AuthenticationTicket>._))
            .MustNotHaveHappened();
    }

    [Fact]
    public async Task EndSessionAsync_WithInvalidIdentifier_DoesNotTouchStorageOrLedger()
    {
        // Arrange
        var tickets = A.Fake<ISessionTicketStore>();
        var ledger = A.Fake<ISessionLedgerWriter>();
        var terminator = new SessionTerminator(tickets, ledger, new TestTimeProvider(),
            NullLogger<SessionTerminator>.Instance);

        // Act
        await terminator.EndSessionAsync("invalid", SessionEndReason.Logout, "request-42");

        // Assert
        A.CallTo(() => tickets.RemoveAsync(A<string>._)).MustNotHaveHappened();
        A.CallTo(() => ledger.RecordEndedAsync(A<string>._, A<DateTimeOffset>._, A<string>._, A<string>._,
            A<CancellationToken>._)).MustNotHaveHappened();
    }
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public async Task EndSessionAsync_WithoutCorrelation_DoesNotRevokeSession(string? correlation)
    {
        // Arrange
        var tickets = A.Fake<ISessionTicketStore>();
        var ledger = A.Fake<ISessionLedgerWriter>();
        var terminator = new SessionTerminator(tickets, ledger, new TestTimeProvider(),
            NullLogger<SessionTerminator>.Instance);

        // Act
        var error = await Record.ExceptionAsync(() =>
            terminator.EndSessionAsync(SessionId, SessionEndReason.Logout, correlation!));

        // Assert
        Assert.IsAssignableFrom<ArgumentException>(error);
        A.CallTo(() => tickets.RemoveAsync(A<string>._)).MustNotHaveHappened();
    }

}
