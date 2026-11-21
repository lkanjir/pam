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

[Collection(StorageCollection1.Name)]
public sealed class ResourceWriteAuthorizationTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("post", "admin", 201)]
    [InlineData("put", "admin", 200)]
    [InlineData("delete", "admin", 204)]
    [InlineData("delete", "user", 403)]
    [InlineData("delete", "approver", 403)]
    [InlineData("delete", "", 403)]
    [InlineData("put", "user", 403)]
    [InlineData("put", "approver", 403)]
    [InlineData("put", "", 403)]
    [InlineData("post", "admin,user", 201)]
    [InlineData("post", "user", 403)]
    [InlineData("post", "approver", 403)]
    [InlineData("post", "user,approver", 403)]
    [InlineData("post", "Admin", 403)]
    [InlineData("post", "superadmin", 403)]
    [InlineData("post", "", 403)]
    public async Task Write_RequiresExplicitManagementCapability(string method, string roles, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection,
            roles: roles.Split(',', StringSplitOptions.RemoveEmptyEntries));
        await test.AuthenticateAsync(includeResourceVersion: false);
        if (method != "post" && roles.Split(',').Contains("admin", StringComparer.Ordinal))
        {
            await test.RefreshVersionAsync();
        }

        // Act
        using var response = await WriteAsync(test, method);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal(method == "delete" && status == 204 ? 0 : status == 201 ? 2 : 1, await test.Database.Context.ManagedResources.CountAsync());
        Assert.Equal(status < 300 ? 1 : 0,
            await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == EventFor(method)));
        Assert.Equal(0, await test.Database.Context.EligibilityRules.CountAsync());
        Assert.Equal(method == "put" && status == 200 ? "New target" : "Original target", (await test.ReadResourceAsync()).Name);
    }

    [Theory]
    [InlineData("post", true, 600, 201)]
    [InlineData("put", true, 600, 200)]
    [InlineData("delete", true, 600, 204)]
    [InlineData("delete", true, 601, 403)]
    [InlineData("delete", false, 0, 403)]
    [InlineData("put", true, 601, 403)]
    [InlineData("put", false, 0, 403)]
    [InlineData("post", true, 601, 403)]
    [InlineData("post", false, 0, 403)]
    public async Task Write_RequiresOriginalRecentAuthentication(string method, bool includeTimestamp, int age, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: includeTimestamp);
        await test.RefreshVersionAsync();
        test.Clock.Now = test.Clock.Now.AddSeconds(age);

        // Act
        using var response = await WriteAsync(test, method);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        if (status == 403)
        {
            using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal("recent_auth_required", problem.RootElement.GetProperty("code").GetString());
            Assert.Equal(1, await test.Database.Context.ManagedResources.CountAsync());
            Assert.Equal("Original target", (await test.ReadResourceAsync()).Name);
            Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == EventFor(method)));
        }
    }

    [Theory]
    [InlineData("post", "revoked-role", ResourceWriteKind.Forbidden)]
    [InlineData("put", "revoked-role", ResourceWriteKind.Forbidden)]
    [InlineData("delete", "revoked-role", ResourceWriteKind.Forbidden)]
    [InlineData("post", "disabled", ResourceWriteKind.Forbidden)]
    [InlineData("put", "disabled", ResourceWriteKind.Forbidden)]
    [InlineData("delete", "disabled", ResourceWriteKind.Forbidden)]
    [InlineData("post", "forged-subject", ResourceWriteKind.Forbidden)]
    [InlineData("put", "forged-subject", ResourceWriteKind.Forbidden)]
    [InlineData("delete", "forged-subject", ResourceWriteKind.Forbidden)]
    [InlineData("post", "forged-public-id", ResourceWriteKind.Forbidden)]
    [InlineData("put", "forged-public-id", ResourceWriteKind.Forbidden)]
    [InlineData("delete", "forged-public-id", ResourceWriteKind.Forbidden)]
    [InlineData("post", "stale-auth", ResourceWriteKind.RecentAuthenticationRequired)]
    [InlineData("put", "stale-auth", ResourceWriteKind.RecentAuthenticationRequired)]
    [InlineData("delete", "stale-auth", ResourceWriteKind.RecentAuthenticationRequired)]
    [InlineData("post", "missing-auth", ResourceWriteKind.RecentAuthenticationRequired)]
    [InlineData("put", "missing-auth", ResourceWriteKind.RecentAuthenticationRequired)]
    [InlineData("delete", "missing-auth", ResourceWriteKind.RecentAuthenticationRequired)]
    public async Task Write_DirectServiceCaller_CannotBypassCurrentIdentityCapabilityOrFreshness(string method, string change, ResourceWriteKind expected)
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
        var actor = new AdministrativeActor(snapshot, authenticatedAt);
        var result = method switch
        {
            "post" => await service.CreateAsync(Payload(), actor, "direct-call"),
            "put" => await service.UpdateAsync(test.Resource.PublicId, UpdatePayload(), actor, "direct-call", test.Resource.Version),
            _ => new ResourceWriteResult(await service.DeleteAsync(test.Resource.PublicId, actor, "direct-call", test.Resource.Version))
        };

        // Assert
        Assert.Equal(expected, result.Kind);
        Assert.Null(result.Resource);
        Assert.Equal(1, await test.Database.Context.ManagedResources.CountAsync());
        Assert.Equal("Original target", (await test.ReadResourceAsync()).Name);
        Assert.Empty(await test.Database.Context.AuditEvents.ToListAsync());
    }

    private static Task<HttpResponseMessage> WriteAsync(ResourceTestContext test, string method) => method switch
    {
        "post" => test.Client.PostAsJsonAsync("/api/resources", Payload()),
        "put" => test.Client.PutAsJsonAsync(test.ResourceUrl, UpdatePayload()),
        _ => test.Client.DeleteAsync(test.ResourceUrl)
    };

    private static string EventFor(string method) => method switch
    {
        "post" => "resource.created",
        "put" => "resource.updated",
        _ => "resource.deleted"
    };

    private static UpdateResourceRequest UpdatePayload() => new() { Name = "New target", ResourceType = "linux", Environment = "dev", IsActive = true };

    private static CreateResourceRequest Payload() => new() { Name = "New target", ResourceType = "linux", Environment = "dev" };
}
