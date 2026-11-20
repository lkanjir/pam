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
    [InlineData(false)]
    [InlineData(true)]
    public async Task Reauthenticate_ObservedActiveSession_ClosesBeforeAuditAndRetainsFailedCompletion(bool auditFails)
    {
        // Arrange
        var tickets = CreateTickets();
        var ledger = A.Fake<ISessionLedgerWriter>();
        var clock = new TestTimeProvider();
        string hash = SessionIdentifier.Hash(SessionId);
        var observed = new SessionObservation(true, clock.Now.AddMinutes(30), clock.Now.AddMinutes(30), "lease");
        bool revoked = false;
        bool completionSawRevocation = false;
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation?>._))
            .Invokes(() => revoked = true)
            .ReturnsLazily((PendingSessionEnd end, SessionObservation? _) => Task.FromResult<PendingSessionEnd?>(end));
        A.CallTo(() => ledger.RecordEndedAsync(A<string>._, A<DateTimeOffset>._, A<string>._, A<string>._,
            A<CancellationToken>._)).ReturnsLazily(() =>
            {
                completionSawRevocation = revoked;
                return auditFails ? Task.FromException(new InvalidOperationException("storage unavailable")) : Task.CompletedTask;
            });
        var terminator = new SessionTerminator(tickets, ledger, clock, NullLogger<SessionTerminator>.Instance);

        // Act
        bool ended = await terminator.TryEndForReauthenticationAsync(hash, observed, "reauth-flow");

        // Assert
        Assert.True(ended);
        Assert.True(completionSawRevocation);
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>.That.Matches(e => e.SessionIdHash == hash
            && e.Reason == "reauthentication" && e.EndedAt == clock.Now && e.CorrelationId == "reauth-flow"), observed))
            .MustHaveHappenedOnceExactly();
        A.CallTo(() => ledger.RecordEndedAsync(hash, clock.Now, "reauthentication", "reauth-flow", CancellationToken.None))
            .MustHaveHappenedOnceExactly();
        if (auditFails)
        {
            A.CallTo(() => tickets.AcknowledgeEndAsync(hash)).MustNotHaveHappened();
        }
        else
        {
            A.CallTo(() => tickets.AcknowledgeEndAsync(hash)).MustHaveHappenedOnceExactly();
        }
        A.CallTo(() => tickets.RemoveAsync(A<string>._)).MustNotHaveHappened();
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("expired")]
    [InlineData("unknown-expiry")]
    [InlineData("already-ended")]
    public async Task Reauthenticate_ObservationNoLongerAuthorizesSession_DoesNotAttemptEndOrAudit(string scenario)
    {
        // Arrange
        var tickets = CreateTickets();
        var ledger = A.Fake<ISessionLedgerWriter>();
        var clock = new TestTimeProvider();
        string hash = SessionIdentifier.Hash(SessionId);
        var observed = new SessionObservation(scenario != "missing",
            scenario == "unknown-expiry" ? null : scenario == "expired" ? clock.Now : clock.Now.AddMinutes(30), null, null)
        {
            PendingEnd = scenario == "already-ended" ? new PendingSessionEnd(hash, clock.Now, "logout", "old") : null
        };
        var terminator = new SessionTerminator(tickets, ledger, clock, NullLogger<SessionTerminator>.Instance);

        // Act
        bool ended = await terminator.TryEndForReauthenticationAsync(hash, observed, "reauth-flow");

        // Assert
        Assert.False(ended);
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation?>._)).MustNotHaveHappened();
        A.CallTo(() => ledger.RecordEndedAsync(A<string>._, A<DateTimeOffset>._, A<string>._, A<string>._,
            A<CancellationToken>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task Reauthenticate_AnotherEndWonComparison_DoesNotIssueAnAuditOrDeleteAnotherTicket()
    {
        // Arrange
        var tickets = CreateTickets();
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation?>._))
            .Returns(Task.FromResult<PendingSessionEnd?>(null));
        var ledger = A.Fake<ISessionLedgerWriter>();
        var clock = new TestTimeProvider();
        var terminator = new SessionTerminator(tickets, ledger, clock, NullLogger<SessionTerminator>.Instance);
        var observed = new SessionObservation(true, clock.Now.AddMinutes(30), null, null);

        // Act
        bool ended = await terminator.TryEndForReauthenticationAsync(SessionIdentifier.Hash(SessionId), observed, "reauth-flow");

        // Assert
        Assert.False(ended);
        A.CallTo(() => ledger.RecordEndedAsync(A<string>._, A<DateTimeOffset>._, A<string>._, A<string>._,
            A<CancellationToken>._)).MustNotHaveHappened();
        A.CallTo(() => tickets.RemoveAsync(A<string>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task Reauthenticate_PreCancelled_DoesNotTouchStorage()
    {
        // Arrange
        var tickets = CreateTickets();
        var clock = new TestTimeProvider();
        var terminator = new SessionTerminator(tickets, A.Fake<ISessionLedgerWriter>(), clock, NullLogger<SessionTerminator>.Instance);
        var observed = new SessionObservation(true, clock.Now.AddMinutes(30), null, null);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        // Act / Assert
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            terminator.TryEndForReauthenticationAsync(SessionIdentifier.Hash(SessionId), observed, "reauth-flow", cancellation.Token));
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation?>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task EndSessionAsync_RecoveryDataMissing_DoesNotInventAnExplicitLogoutAudit()
    {
        // Arrange
        var tickets = CreateTickets();
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation?>._))
            .Returns(Task.FromResult<PendingSessionEnd?>(null));
        var ledger = A.Fake<ISessionLedgerWriter>();
        var terminator = new SessionTerminator(tickets, ledger, new TestTimeProvider(), NullLogger<SessionTerminator>.Instance);

        // Act
        await terminator.EndSessionAsync(SessionId, SessionEndReason.Logout, "request-42");

        // Assert
        A.CallTo(() => ledger.RecordEndedAsync(A<string>._, A<DateTimeOffset>._, A<string>._, A<string>._,
            A<CancellationToken>._)).MustNotHaveHappened();
        A.CallTo(() => tickets.AcknowledgeEndAsync(A<string>._)).MustNotHaveHappened();
    }


    [Theory]
    [InlineData(SessionEndReason.Logout, "logout")]
    [InlineData(SessionEndReason.Reauthentication, "reauthentication")]
    [InlineData(SessionEndReason.AccessChanged, "access_changed")]
    public async Task EndSessionAsync_PersistsStableReasonAfterRevocation(SessionEndReason reason, string code)
    {
        // Arrange
        var tickets = CreateTickets();
        var ledger = A.Fake<ISessionLedgerWriter>();
        var clock = new TestTimeProvider();
        var revoked = false;
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation?>._))
            .Invokes(() => revoked = true)
            .ReturnsLazily((PendingSessionEnd end, SessionObservation? _) => Task.FromResult<PendingSessionEnd?>(end));
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
        var tickets = CreateTickets();
        var ledger = A.Fake<ISessionLedgerWriter>();
        var failure = new InvalidOperationException("Storage unavailable");
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation?>._)).ThrowsAsync(failure);
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
        var tickets = CreateTickets();
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
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation?>._)).MustHaveHappenedOnceExactly();
        A.CallTo(() => tickets.AcknowledgeEndAsync(A<string>._)).MustNotHaveHappened();
        A.CallTo(() => tickets.StoreAsync(A<Microsoft.AspNetCore.Authentication.AuthenticationTicket>._))
            .MustNotHaveHappened();
    }

    [Fact]
    public async Task EndSessionAsync_WithInvalidIdentifier_DoesNotTouchStorageOrLedger()
    {
        // Arrange
        var tickets = CreateTickets();
        var ledger = A.Fake<ISessionLedgerWriter>();
        var terminator = new SessionTerminator(tickets, ledger, new TestTimeProvider(),
            NullLogger<SessionTerminator>.Instance);

        // Act
        await terminator.EndSessionAsync("invalid", SessionEndReason.Logout, "request-42");

        // Assert
        A.CallTo(() => tickets.RemoveAsync(A<string>._)).MustNotHaveHappened();
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation?>._)).MustNotHaveHappened();
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
        var tickets = CreateTickets();
        var ledger = A.Fake<ISessionLedgerWriter>();
        var terminator = new SessionTerminator(tickets, ledger, new TestTimeProvider(),
            NullLogger<SessionTerminator>.Instance);

        // Act
        var error = await Record.ExceptionAsync(() =>
            terminator.EndSessionAsync(SessionId, SessionEndReason.Logout, correlation!));

        // Assert
        Assert.IsAssignableFrom<ArgumentException>(error);
        A.CallTo(() => tickets.RemoveAsync(A<string>._)).MustNotHaveHappened();
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation?>._)).MustNotHaveHappened();
    }

    private static ISessionTicketStore CreateTickets()
    {
        var tickets = A.Fake<ISessionTicketStore>();
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation?>._))
            .ReturnsLazily((PendingSessionEnd end, SessionObservation? _) => Task.FromResult<PendingSessionEnd?>(end));
        return tickets;
    }

}
