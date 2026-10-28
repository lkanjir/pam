using FakeItEasy;
using Microsoft.AspNetCore.Http;

namespace Backend.UnitTests.Authentication;

public sealed class PamTicketStoreRemovalTests
{
    [Fact]
    public async Task RemoveAsync_WithoutExplicitTermination_DoesNotRecordLogout()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var context = new DefaultHttpContext();

        // Act
        await fixture.Store.RemoveAsync(new string('A', 64), context, CancellationToken.None);

        // Assert
        A.CallTo(() => fixture.Ledger.RecordEndedAsync(A<string>._, A<DateTimeOffset>._,
            A<string>._, A<string>._, A<CancellationToken>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RemoveAsync_WhenStorageFails_PropagatesFailure()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var failure = new InvalidOperationException("Storage unavailable");
        A.CallTo(() => fixture.Tickets.RemoveAsync(TicketStoreFixture.SessionId)).ThrowsAsync(failure);

        // Act
        var error = await Record.ExceptionAsync(() =>
            fixture.Store.RemoveAsync(new string('A', 64), new DefaultHttpContext(), CancellationToken.None));

        // Assert
        Assert.Same(failure, error);
    }
}
