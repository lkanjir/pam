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

[Collection("Cookie sessions")]
public sealed class ManagedEntitlementListTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("admin", true, 200)]
    [InlineData("user", true, 403)]
    [InlineData("approver", true, 403)]
    [InlineData("superadmin", true, 403)]
    [InlineData("", true, 403)]
    [InlineData("admin", false, 401)]
    public async Task List_RequiresExplicitResourceConfigurationRead(string role, bool login, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: role.Split(',', StringSplitOptions.RemoveEmptyEntries));
        AddEntitlement(test, 1);
        await test.Database.Context.SaveChangesAsync();
        if (login)
        {
            await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);
        }

        // Act
        using var response = await test.Client.GetAsync(test.ResourceUrl + "/entitlements");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        if (status == 200)
        {
            var page = await response.Content.ReadFromJsonAsync<CursorPage<ManagedEntitlementResponse>>();
            Assert.NotNull(page);
            Assert.Equal("c1", Assert.Single(page.Items).Code);
        }
        else
        {
            Assert.DoesNotContain("c1", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task List_InactiveResourceAndEntitlement_ReturnsConfigurationWithoutCreatingEligibility()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["admin"]);
        test.Resource.IsActive = false;
        var entitlement = AddEntitlement(test, 1, active: false);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync(test.ResourceUrl + "/entitlements");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await response.Content.ReadFromJsonAsync<CursorPage<ManagedEntitlementResponse>>();
        Assert.NotNull(page);
        var item = Assert.Single(page.Items);
        Assert.Equal(entitlement.PublicId, item.Id);
        Assert.Equal("c1", item.Code);
        Assert.Equal("Configuration 1", item.Name);
        Assert.Equal(60, item.MaxDurationMinutes);
        Assert.True(item.RequiresApproval);
        Assert.True(item.RequiresTicket);
        Assert.False(item.IsActive);
        Assert.False(await test.Database.Context.EligibilityRules.AnyAsync());
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.AnyAsync());
    }

    [Theory]
    [InlineData(null, 20, true)]
    [InlineData(1, 1, true)]
    [InlineData(100, 21, false)]
    public async Task List_DefaultAndBoundaryLimits_BoundThePage(int? limit, int expectedCount, bool more)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        for (int index = 1; index <= 21; index++)
        {
            AddEntitlement(test, index);
        }
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        string query = limit is { } value ? "?limit=" + value.ToString(CultureInfo.InvariantCulture) : string.Empty;

        // Act
        using var response = await test.Client.GetAsync(test.ResourceUrl + "/entitlements" + query);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await response.Content.ReadFromJsonAsync<CursorPage<ManagedEntitlementResponse>>();
        Assert.NotNull(page);
        Assert.Equal(expectedCount, page.Items.Count);
        Assert.Equal(more, page.HasNextPage);
    }

    [Fact]
    public async Task List_CursorContinuation_StaysWithinTheSelectedParent()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var first = AddEntitlement(test, 1);
        var last = AddEntitlement(test, 3);
        var foreign = new ManagedResource
        {
            Name = "Foreign",
            ResourceType = "linux",
            Environment = "dev",
            CreatedByPrincipalId = test.ActorId,
            ModifiedByPrincipalId = test.ActorId,
            CreatedAt = test.Clock.Now.UtcDateTime,
            ModifiedAt = test.Clock.Now.UtcDateTime
        };
        var foreignEntitlement = AddEntitlement(test, 2);
        foreignEntitlement.Resource = foreign;
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        var page = await test.Client.GetFromJsonAsync<CursorPage<ManagedEntitlementResponse>>(test.ResourceUrl + "/entitlements?limit=1");
        Assert.NotNull(page);
        Assert.Equal(first.PublicId, Assert.Single(page.Items).Id);
        Assert.NotNull(page.NextCursor);

        // Act
        var continuation = await test.Client.GetFromJsonAsync<CursorPage<ManagedEntitlementResponse>>(
            test.ResourceUrl + "/entitlements?limit=1&cursor=" + Uri.EscapeDataString(page.NextCursor));

        // Assert
        Assert.NotNull(continuation);
        Assert.Equal(last.PublicId, Assert.Single(continuation.Items).Id);
        Assert.Null(continuation.NextCursor);
    }

    [Theory]
    [InlineData("empty", 200)]
    [InlineData("missing", 404)]
    [InlineData("retired", 404)]
    public async Task List_EmptyOrUnavailableParent_ReturnsDistinctAuthorizedOutcomes(string state, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        if (state == "retired")
        {
            AddEntitlement(test, 1);
            test.Resource.DeletedAt = test.Clock.Now.UtcDateTime;
            await test.Database.Context.SaveChangesAsync();
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        string url = state == "missing" ? $"/api/resources/{Guid.NewGuid()}/entitlements" : test.ResourceUrl + "/entitlements";

        // Act
        using var response = await test.Client.GetAsync(url);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        if (status == 200)
        {
            var page = await response.Content.ReadFromJsonAsync<CursorPage<ManagedEntitlementResponse>>();
            Assert.NotNull(page);
            Assert.Empty(page.Items);
            Assert.Null(page.NextCursor);
        }
        else
        {
            Assert.DoesNotContain("Configuration", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("limit=0")]
    [InlineData("limit=101")]
    [InlineData("cursor=invalid")]
    public async Task List_InvalidPagination_ReturnsBadRequest(string query)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync(test.ResourceUrl + "/entitlements?" + query);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task List_OpenApi_DescribesAdministrativeConfigurationRead()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/resources/{id}/entitlements").GetProperty("get");
        Assert.Equal("Resource.Entitlements.List", operation.GetProperty("operationId").GetString());
        Assert.Contains("resources.read_all", operation.GetProperty("description").GetString(), StringComparison.Ordinal);
        Assert.True(operation.GetProperty("responses").TryGetProperty("404", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("403", out _));
    }

    private static Entitlement AddEntitlement(ResourceTestContext test, int suffix, bool active = true)
    {
        var entitlement = new Entitlement
        {
            PublicId = Guid.Parse("00000000-0000-7000-8000-" + suffix.ToString("D12", CultureInfo.InvariantCulture)),
            Resource = test.Resource,
            Code = "c" + suffix.ToString(CultureInfo.InvariantCulture),
            Name = "Configuration " + suffix.ToString(CultureInfo.InvariantCulture),
            IsActive = active,
            MaxDurationMinutes = 60,
            RequiresApproval = true,
            RequiresTicket = true
        };
        test.Database.Context.Entitlements.Add(entitlement);
        return entitlement;
    }
}
