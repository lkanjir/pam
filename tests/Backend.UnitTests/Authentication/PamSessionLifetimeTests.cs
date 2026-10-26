using Api.Authentication;
using Api.Configuration;
using Backend.Tests.Support;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Backend.UnitTests.Authentication;

public sealed class PamSessionLifetimeTests
{
    [Fact]
    public void Initialize_WhenCalledAgain_DoesNotMoveAbsoluteDeadline()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var lifetime = CreateLifetime(clock);
        var ticket = SessionTestData.Ticket(clock.Now);
        lifetime.Initialize(ticket.Properties);
        clock.Now = clock.Now.AddHours(7);
        ticket.Properties.ExpiresUtc = clock.Now.AddHours(2);

        // Act
        lifetime.Initialize(ticket.Properties);

        // Assert
        Assert.Equal(clock.Now.AddHours(1), ticket.Properties.ExpiresUtc);
    }

    [Fact]
    public void TryLimitExpiration_NearAbsoluteDeadline_ClampsProposedExpiry()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var deadline = clock.Now.AddHours(8);
        var lifetime = CreateLifetime(clock);
        var ticket = SessionTestData.Ticket(clock.Now);
        lifetime.Initialize(ticket.Properties);
        clock.Now = deadline.AddMinutes(-10);
        ticket.Properties.IssuedUtc = clock.Now;
        ticket.Properties.ExpiresUtc = clock.Now.AddMinutes(30);

        // Act
        lifetime.TryLimitExpiration(ticket.Properties);

        // Assert
        Assert.Equal(deadline, ticket.Properties.ExpiresUtc);
    }

    [Fact]
    public void TryLimitExpiration_BeforeDeadline_PreservesShorterIdleExpiry()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var lifetime = CreateLifetime(clock);
        var ticket = SessionTestData.Ticket(clock.Now);
        lifetime.Initialize(ticket.Properties);
        var idleExpiry = ticket.Properties.ExpiresUtc;

        // Act
        lifetime.TryLimitExpiration(ticket.Properties);

        // Assert
        Assert.Equal(idleExpiry, ticket.Properties.ExpiresUtc);
    }

    [Fact]
    public void IsValid_AtAbsoluteDeadline_RejectsTicketDespiteLaterIdleExpiry()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var lifetime = CreateLifetime(clock);
        var ticket = SessionTestData.Ticket(clock.Now);
        lifetime.Initialize(ticket.Properties);
        clock.Now = clock.Now.AddHours(8);
        ticket.Properties.ExpiresUtc = clock.Now.AddMinutes(30);

        // Act
        var valid = lifetime.IsValid(ticket.Properties);

        // Assert
        Assert.False(valid);
    }

    [Fact]
    public void IsValid_AtIdleExpiry_RejectsTicketBeforeAbsoluteDeadline()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var lifetime = CreateLifetime(clock);
        var ticket = SessionTestData.Ticket(clock.Now);
        lifetime.Initialize(ticket.Properties);
        clock.Now = clock.Now.AddMinutes(30);

        // Act
        var valid = lifetime.IsValid(ticket.Properties);

        // Assert
        Assert.False(valid);
    }

    [Fact]
    public void TryLimitExpiration_WithoutAbsoluteDeadline_RejectsLegacyTicket()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var lifetime = CreateLifetime(clock);
        var ticket = SessionTestData.Ticket(clock.Now);

        // Act
        var renewed = lifetime.TryLimitExpiration(ticket.Properties);

        // Assert
        Assert.False(renewed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-date")]
    public void IsValid_WithMalformedDeadline_RejectsTicket(string value)
    {
        // Arrange
        var clock = new TestTimeProvider();
        var lifetime = CreateLifetime(clock);
        var ticket = SessionTestData.Ticket(clock.Now);
        ticket.Properties.Items["pam:absolute-expires-utc"] = value;

        // Act
        var valid = lifetime.IsValid(ticket.Properties);

        // Assert
        Assert.False(valid);
    }

    [Fact]
    public void Initialize_UsesConfiguredAbsoluteTimeout()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var lifetime = CreateLifetime(clock, TimeSpan.FromHours(2));
        var properties = new AuthenticationProperties { ExpiresUtc = clock.Now.AddHours(4) };

        // Act
        lifetime.Initialize(properties);

        // Assert
        Assert.Equal(clock.Now.AddHours(2), properties.ExpiresUtc);
    }

    private static PamSessionLifetime CreateLifetime(TestTimeProvider clock, TimeSpan? absolute = null) => new(
        Options.Create(new PamSessionOptions
        {
            IdleTimeout = TimeSpan.FromMinutes(30),
            AbsoluteTimeout = absolute ?? TimeSpan.FromHours(8)
        }), clock);
}
