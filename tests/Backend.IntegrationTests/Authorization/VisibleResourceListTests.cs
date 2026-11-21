using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.Common.Pagination;
using Application.Resources;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Authorization;

[Collection(StorageCollection1.Name)]
public sealed class VisibleResourceListTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("user", true, 200)]
    [InlineData("approver", true, 200)]
    [InlineData("admin,user", true, 200)]
    [InlineData("admin", true, 403)]
    [InlineData("superadmin", true, 403)]
    [InlineData("", true, 403)]
    [InlineData("user", false, 401)]
    public async Task List_RequiresExplicitScopedReadCapability(string role, bool login, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: role.Split(',', StringSplitOptions.RemoveEmptyEntries));
        test.AddViewBinding(test.Resource);
        await test.Database.Context.SaveChangesAsync();
        if (login)
        {
            await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);
        }

        // Act
        using var response = await test.Client.GetAsync("/api/resources/visible");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        if (status == 200)
        {
            var page = await response.Content.ReadFromJsonAsync<CursorPage<ResourceResponse>>();
            Assert.NotNull(page);
            Assert.Equal(test.Resource.PublicId, Assert.Single(page.Items).Id);
        }
        else
        {
            Assert.DoesNotContain("Original target", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task List_CurrentViewAssignments_FilterBeforeCursorPaginationAndIncludeInactiveResources()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["user"]);
        var first = AddResource(test, 1, "visible");
        AddResource(test, 2, "hidden");
        var last = AddResource(test, 3, "inactive-resource");
        AddResource(test, 4, "inactive-binding");
        AddResource(test, 5, "foreign-binding");
        AddResource(test, 6, "retired");
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        using var initial = await test.Client.GetAsync("/api/resources/visible?limit=1");
        Assert.Equal(HttpStatusCode.OK, initial.StatusCode);
        var page = await initial.Content.ReadFromJsonAsync<CursorPage<ResourceResponse>>();
        Assert.NotNull(page);
        Assert.Equal(first.PublicId, Assert.Single(page.Items).Id);
        Assert.NotNull(page.NextCursor);

        // Act
        using var response = await test.Client.GetAsync("/api/resources/visible?limit=1&cursor=" + Uri.EscapeDataString(page.NextCursor));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var continuation = await response.Content.ReadFromJsonAsync<CursorPage<ResourceResponse>>();
        Assert.NotNull(continuation);
        var resource = Assert.Single(continuation.Items);
        Assert.Equal(last.PublicId, resource.Id);
        Assert.False(resource.IsActive);
        Assert.Null(resource.Entitlements);
        Assert.Null(continuation.NextCursor);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(json.RootElement.GetProperty("items")[0].TryGetProperty("entitlements", out _));
    }

    [Fact]
    public async Task List_AdminAndUserWithoutView_HasEmptyScopeDespiteManagementRead()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        using var management = await test.Client.GetAsync("/api/resources");
        Assert.Equal(HttpStatusCode.OK, management.StatusCode);

        // Act
        using var response = await test.Client.GetAsync("/api/resources/visible");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await response.Content.ReadFromJsonAsync<CursorPage<ResourceResponse>>();
        Assert.NotNull(page);
        Assert.Empty(page.Items);
        Assert.Null(page.NextCursor);
    }

    [Theory]
    [InlineData("limit=0")]
    [InlineData("limit=101")]
    [InlineData("cursor=invalid")]
    public async Task List_InvalidPagination_ReturnsValidationProblem(string query)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["user"]);
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync("/api/resources/visible?" + query);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task List_OpenApi_DescribesScopeAndPaginationWithoutRequesterEligibility()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/resources/visible").GetProperty("get");
        Assert.Equal("Resource.ListVisible", operation.GetProperty("operationId").GetString());
        Assert.Contains("resources.read_scoped", operation.GetProperty("description").GetString(), StringComparison.Ordinal);
        Assert.True(operation.GetProperty("responses").TryGetProperty("200", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("403", out _));
    }

    private static ManagedResource AddResource(ResourceTestContext test, int suffix, string state)
    {
        var resource = new ManagedResource
        {
            PublicId = Guid.Parse("00000000-0000-7000-8000-" + suffix.ToString("D12", CultureInfo.InvariantCulture)),
            Name = state,
            ResourceType = "linux",
            Environment = "dev",
            IsActive = state != "inactive-resource",
            CreatedByPrincipalId = test.ActorId,
            ModifiedByPrincipalId = test.ActorId,
            CreatedAt = test.Clock.Now.UtcDateTime,
            ModifiedAt = test.Clock.Now.UtcDateTime,
            DeletedAt = state == "retired" ? test.Clock.Now.UtcDateTime : null
        };
        test.Database.Context.ManagedResources.Add(resource);
        if (state != "hidden")
        {
            test.AddViewBinding(resource, state == "foreign-binding" ? test.Resource.CreatedByPrincipalId : test.ActorId)
                .IsActive = state != "inactive-binding";
        }
        return resource;
    }
}
