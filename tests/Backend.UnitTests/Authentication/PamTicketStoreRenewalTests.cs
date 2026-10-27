using Backend.Tests.Support;
using FakeItEasy;
using Microsoft.AspNetCore.Authentication;

namespace Backend.UnitTests.Authentication;

public sealed class PamTicketStoreRenewalTests
{
    [Fact]
    public async Task RenewAsync_AfterAbsoluteDeadline_DoesNotWriteStorage()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = TicketStoreFixture.SessionId;
        var ticket = fixture.StartedTicket();
        fixture.Clock.Now = fixture.Clock.Now.AddHours(8);
        ticket.Properties.ExpiresUtc = fixture.Clock.Now.AddMinutes(30);

        // Act
        await fixture.Store.RenewAsync(sessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Tickets.TryRenewAsync(sessionId, A<AuthenticationTicket>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RenewAsync_WithoutAbsoluteDeadline_DoesNotWriteStorage()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = TicketStoreFixture.SessionId;
        var ticket = SessionTestData.Ticket(fixture.Clock.Now);

        // Act
        await fixture.Store.RenewAsync(sessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Tickets.TryRenewAsync(sessionId, A<AuthenticationTicket>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RenewAsync_WhenStorageSucceeds_UpdatesLedgerExpiry()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = TicketStoreFixture.SessionId;
        var ticket = fixture.StartedTicket();
        A.CallTo(() => fixture.Tickets.TryRenewAsync(sessionId, A<AuthenticationTicket>._)).Returns(true);

        // Act
        await fixture.Store.RenewAsync(sessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(SessionTestData.Hash(sessionId),
            ticket.Properties.ExpiresUtc!.Value, CancellationToken.None)).MustHaveHappenedOnceExactly();
    }

    [Fact]
    public async Task RenewAsync_WhenStorageRejectsRenewal_DoesNotUpdateLedger()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = TicketStoreFixture.SessionId;
        var ticket = fixture.StartedTicket();
        A.CallTo(() => fixture.Tickets.TryRenewAsync(sessionId, A<AuthenticationTicket>._))
            .Returns(false);

        // Act
        await fixture.Store.RenewAsync(sessionId, ticket);

        // Assert
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(A<string>._,
            A<DateTimeOffset>._, A<CancellationToken>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RenewAsync_WhenStorageFails_DoesNotUpdateLedger()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var sessionId = TicketStoreFixture.SessionId;
        A.CallTo(() => fixture.Tickets.TryRenewAsync(sessionId, A<AuthenticationTicket>._))
            .ThrowsAsync(new InvalidOperationException("Storage unavailable"));

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
        var sessionId = TicketStoreFixture.SessionId;
        var failure = new InvalidOperationException("Database unavailable");
        A.CallTo(() => fixture.Tickets.TryRenewAsync(sessionId, A<AuthenticationTicket>._)).Returns(true);
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
        var sessionId = TicketStoreFixture.SessionId;
        A.CallTo(() => fixture.Tickets.TryRenewAsync(sessionId, A<AuthenticationTicket>._)).Returns(true);
        A.CallTo(() => fixture.Ledger.RecordRenewedAsync(A<string>._,
            A<DateTimeOffset>._, A<CancellationToken>._))
            .ThrowsAsync(new InvalidOperationException("Database unavailable"));

        // Act
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Store.RenewAsync(sessionId, fixture.StartedTicket()));

        // Assert
        A.CallTo(() => fixture.Tickets.RemoveAsync(sessionId)).MustNotHaveHappened();
    }
}
