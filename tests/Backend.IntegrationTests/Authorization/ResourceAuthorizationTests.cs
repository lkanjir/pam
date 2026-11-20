using System.Net;
using System.Net.Http.Json;
using Application.Common.Pagination;
using Application.Resources;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class ResourceAuthorizationTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("admin", 200)]
    [InlineData("admin,user", 200)]
    [InlineData("user", 403)]
    [InlineData("approver", 403)]
    [InlineData("user,approver", 403)]
    [InlineData("Admin", 403)]
    [InlineData("superadmin", 403)]
    [InlineData("", 403)]
    public async Task List_ManagementCatalog_EnforcesExplicitCapabilityWithoutLeakingResources(string roles, int expectedStatus)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection,
            roles: roles.Split(',', StringSplitOptions.RemoveEmptyEntries));
        await test.AuthenticateAsync();

        // Act
        using var response = await test.Client.GetAsync("/api/resources?requestable=false");

        // Assert
        Assert.Equal(expectedStatus, (int)response.StatusCode);
        if (expectedStatus == 200)
        {
            var page = await response.Content.ReadFromJsonAsync<CursorPage<ResourceResponse>>();
            Assert.NotNull(page);
            Assert.Equal(test.Resource.PublicId, Assert.Single(page.Items).Id);
        }
        else
        {
            Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
            Assert.DoesNotContain("Original target", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task List_AdminRoleRemoved_RejectsRetainedCookie()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["admin"]);
        await test.AuthenticateAsync();
        var assignment = await test.Database.Context.PamRoleAssignments.SingleAsync(a => a.PrincipalId == test.ActorId);
        test.Database.Context.PamRoleAssignments.Remove(assignment);
        await test.Database.Context.SaveChangesAsync();

        // Act
        using var response = await test.Client.GetAsync("/api/resources");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain("Original target", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        var ended = await test.Database.Context.AuthenticationSessionLedgers.AsNoTracking().SingleAsync();
        Assert.Equal("access_changed", ended.EndReason);
        Assert.NotNull(ended.EndedAt);
    }
}
