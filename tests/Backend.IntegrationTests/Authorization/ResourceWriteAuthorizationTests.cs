using System.Net.Http.Json;
using System.Text.Json;
using Application.Authorization;
using Application.Resources;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Infrastructure.Resources;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class ResourceWriteAuthorizationTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("admin", 201)]
    [InlineData("admin,user", 201)]
    [InlineData("user", 403)]
    [InlineData("approver", 403)]
    [InlineData("user,approver", 403)]
    [InlineData("Admin", 403)]
    [InlineData("superadmin", 403)]
    [InlineData("", 403)]
    public async Task Create_RequiresExplicitManagementCapability(string roles, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection,
            roles: roles.Split(',', StringSplitOptions.RemoveEmptyEntries));
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/resources", Payload());

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal(status == 201 ? 2 : 1, await test.Database.Context.ManagedResources.CountAsync());
        Assert.Equal(status == 201 ? 1 : 0,
            await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "resource.created"));
        Assert.Equal(0, await test.Database.Context.EligibilityRules.CountAsync());
    }

    [Theory]
    [InlineData(true, 600, 201)]
    [InlineData(true, 601, 403)]
    [InlineData(false, 0, 403)]
    public async Task Create_RequiresOriginalRecentAuthentication(bool includeTimestamp, int age, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: includeTimestamp);
        test.Clock.Now = test.Clock.Now.AddSeconds(age);

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/resources", Payload());

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        if (status == 403)
        {
            using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal("recent_auth_required", problem.RootElement.GetProperty("code").GetString());
            Assert.Equal(1, await test.Database.Context.ManagedResources.CountAsync());
            Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "resource.created"));
        }
    }

    [Theory]
    [InlineData("revoked-role", ResourceWriteKind.Forbidden)]
    [InlineData("disabled", ResourceWriteKind.Forbidden)]
    [InlineData("forged-subject", ResourceWriteKind.Forbidden)]
    [InlineData("forged-public-id", ResourceWriteKind.Forbidden)]
    [InlineData("stale-auth", ResourceWriteKind.RecentAuthenticationRequired)]
    [InlineData("missing-auth", ResourceWriteKind.RecentAuthenticationRequired)]
    public async Task Create_DirectServiceCaller_CannotBypassCurrentIdentityCapabilityOrFreshness(string change, ResourceWriteKind expected)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var principal = await test.Database.Context.Principals.SingleAsync(value => value.Id == test.ActorId);
        var snapshot = new PrincipalSnapshot(principal.Id, principal.PublicId, principal.DisplayName, principal.Issuer, principal.Subject);
        if (change == "revoked-role")
        {
            await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == test.ActorId)
                .ExecuteDeleteAsync();
        }
        if (change == "disabled")
        {
            await test.Database.Context.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE principals SET is_enabled = false WHERE id = {test.ActorId}");
        }
        if (change == "forged-subject")
        {
            snapshot = snapshot with { Subject = "other-account" };
        }
        if (change == "forged-public-id")
        {
            snapshot = snapshot with { PublicId = Guid.NewGuid() };
        }
        DateTimeOffset? authenticatedAt = change switch
        {
            "missing-auth" => null,
            "stale-auth" => test.Clock.Now.AddSeconds(-601),
            _ => test.Clock.Now
        };
        var service = new ResourceService(test.Database.Context, test.Clock);

        // Act
        var result = await service.CreateAsync(Payload(), new AdministrativeActor(snapshot, authenticatedAt), "direct-call");

        // Assert
        Assert.Equal(expected, result.Kind);
        Assert.Null(result.Resource);
        Assert.Equal(1, await test.Database.Context.ManagedResources.CountAsync());
        Assert.Empty(await test.Database.Context.AuditEvents.ToListAsync());
    }

    private static CreateResourceRequest Payload() => new() { Name = "New target", ResourceType = "linux", Environment = "dev" };
}
