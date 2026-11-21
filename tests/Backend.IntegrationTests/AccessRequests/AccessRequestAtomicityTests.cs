using System.Net;
using System.Text.Json;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Microsoft.EntityFrameworkCore;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.AccessRequests;

[Collection(StorageCollection2.Name)]
public sealed class AccessRequestAtomicityTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("request")]
    [InlineData("evaluation")]
    [InlineData("created-audit")]
    [InlineData("evaluated-audit")]
    public async Task Submit_PersistenceFailure_RollsBackRequestPolicyAndAudit(string target)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        string constraint = target switch
        {
            "request" => "ALTER TABLE access_requests ADD CONSTRAINT reject_submission CHECK (state <> 'PendingApproval')",
            "evaluation" => "ALTER TABLE policy_evaluations ADD CONSTRAINT reject_submission CHECK (decision <> 'PendingApproval')",
            "created-audit" => "ALTER TABLE audit_events ADD CONSTRAINT reject_submission CHECK (event_type <> 'access_request.created')",
            _ => "ALTER TABLE audit_events ADD CONSTRAINT reject_submission CHECK (event_type <> 'policy.evaluated')"
        };
        await test.Database.Context.Database.ExecuteSqlRawAsync(constraint);

        // Act
        using var response = await PostAsync(test, Request(test, entitlement));

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Internal Server Error", json.RootElement.GetProperty("title").GetString());
        Assert.False(json.RootElement.TryGetProperty("detail", out _));
        await AssertNoRequestsAsync(test);
    }
}
