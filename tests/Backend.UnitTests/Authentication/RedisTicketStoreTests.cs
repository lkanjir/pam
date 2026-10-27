using Backend.Tests.Support;
using Infrastructure.Authentication;
using Microsoft.AspNetCore.DataProtection;
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
        var fixture = new RedisStoreFixture();

        // Act
        await fixture.Redis.RetrieveAsync(id!);

        // Assert
        A.CallTo(() => fixture.Database.StringGetAsync(A<RedisKey>._, CommandFlags.None)).MustNotHaveHappened();
    }

    [Fact]
    public async Task StoreAsync_WithoutExpiration_RejectsTicket()
    {
        // Arrange
        var fixture = new RedisStoreFixture();
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
        var fixture = new RedisStoreFixture();
        var ticket = SessionTestData.Ticket(fixture.Clock.Now);
        ticket.Properties.ExpiresUtc = fixture.Clock.Now;

        // Act
        var error = await Record.ExceptionAsync(() => fixture.Redis.StoreAsync(ticket));

        // Assert
        Assert.IsType<InvalidOperationException>(error);
    }
    private sealed class RedisStoreFixture
    {
        public IDatabase Database { get; } = A.Fake<IDatabase>();
        public TestTimeProvider Clock { get; } = new();
        public RedisTicketStore Redis { get; }

        public RedisStoreFixture()
        {
            var connection = A.Fake<IConnectionMultiplexer>();
            A.CallTo(() => connection.GetDatabase(A<int>._, A<object>._)).Returns(Database);
            Redis = new RedisTicketStore(connection, new EphemeralDataProtectionProvider(), Clock);
        }
    }

}
