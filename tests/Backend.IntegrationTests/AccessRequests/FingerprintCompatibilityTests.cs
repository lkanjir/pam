using System.Net;
using System.Net.Http.Json;
using Application.AccessRequests;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Microsoft.EntityFrameworkCore;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.AccessRequests;

[Collection("Cookie sessions")]
public sealed class FingerprintCompatibilityTests(PostgresFixture postgres, RedisFixture redis)
{
    [Fact]
    public async Task Submit_LegacyUnversionedFingerprint_ReplaysWithoutNewRecords()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        var request = Request(test, entitlement);
        using var created = await PostAsync(test, request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var original = await created.Content.ReadFromJsonAsync<AccessRequestResponse>();
        string? fingerprint = await test.Database.Context.AccessRequests.Select(item => item.PayloadHash).SingleAsync();
        Assert.NotNull(fingerprint);
        Assert.StartsWith("v1:", fingerprint, StringComparison.Ordinal);
        await test.Database.Context.AccessRequests.ExecuteUpdateAsync(
            setters => setters.SetProperty(item => item.PayloadHash, fingerprint.Substring(3)));
        int auditCount = await test.Database.Context.AuditEvents.CountAsync();

        // Act
        using var replay = await PostAsync(test, request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(original, await replay.Content.ReadFromJsonAsync<AccessRequestResponse>());
        Assert.Equal(1, await test.Database.Context.AccessRequests.CountAsync());
        Assert.Equal(1, await test.Database.Context.PolicyEvaluations.CountAsync());
        Assert.Equal(auditCount, await test.Database.Context.AuditEvents.CountAsync());
    }
}
