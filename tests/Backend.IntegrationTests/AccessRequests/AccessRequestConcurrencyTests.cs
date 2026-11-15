using Application.AccessRequests;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.AccessRequests;

[Collection("Cookie sessions")]
public sealed class AccessRequestConcurrencyTests(PostgresFixture postgres, RedisFixture redis)
{
    [Fact]
    public async Task Transition_CompetingTerminalDecisions_CannotOverwriteTheFirstDecision()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var entitlement = await SeedEntitlementAsync(test);
        AddRequest(test, entitlement, Guid.CreateVersion7(test.Clock.Now));
        await test.Database.Context.SaveChangesAsync();
        var options = new DbContextOptionsBuilder<PamDbContext>()
            .UseNpgsql(test.Database.Context.Database.GetConnectionString()).UseSnakeCaseNamingConvention().Options;
        await using var first = new PamDbContext(options);
        await using var second = new PamDbContext(options);
        var approval = await first.AccessRequests.SingleAsync();
        var rejection = await second.AccessRequests.SingleAsync();
        approval.TransitionTo(AccessRequestState.Approved);
        await first.SaveChangesAsync();
        rejection.TransitionTo(AccessRequestState.Rejected);

        // Act
        var error = await Record.ExceptionAsync(() => second.SaveChangesAsync());

        // Assert
        Assert.IsType<DbUpdateConcurrencyException>(error);
        Assert.Equal("Approved", await test.Database.Context.AccessRequests.AsNoTracking().Select(item => item.State).SingleAsync());
    }
}
