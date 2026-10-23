using Backend.Tests.Support;
using FakeItEasy;
using StackExchange.Redis;

namespace Backend.UnitTests.Authentication;

public sealed class RedisTicketStoreTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-session")]
    public async Task RetrieveAsync_WithInvalidIdentifier_DoesNotQueryRedis(string? id)
    {
        // Arrange
        using var fixture = new TicketStoreFixture();

        // Act
        await fixture.Redis.RetrieveAsync(id!);

        // Assert
        A.CallTo(() => fixture.Database.StringGetAsync(A<RedisKey>._, CommandFlags.None)).MustNotHaveHappened();
    }

    [Fact]
    public async Task StoreAsync_WithoutExpiration_RejectsTicket()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var ticket = SessionTestData.Ticket(fixture.Clock.Now);
        ticket.Properties.ExpiresUtc = null;

        // Act
        var error = await Record.ExceptionAsync(() => fixture.Redis.StoreAsync(ticket));

        // Assert
        Assert.IsType<InvalidOperationException>(error);
    }

    [Fact]
    public async Task StoreAsync_WithExpiredTicket_RejectsTicket()
    {
        // Arrange
        using var fixture = new TicketStoreFixture();
        var ticket = SessionTestData.Ticket(fixture.Clock.Now);
        ticket.Properties.ExpiresUtc = fixture.Clock.Now;

        // Act
        var error = await Record.ExceptionAsync(() => fixture.Redis.StoreAsync(ticket));

        // Assert
        Assert.IsType<InvalidOperationException>(error);
    }
}
