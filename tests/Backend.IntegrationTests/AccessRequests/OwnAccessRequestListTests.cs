using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.AccessRequests;
using Application.Common.Pagination;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Microsoft.EntityFrameworkCore;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.AccessRequests;

[Collection("Cookie sessions")]
public sealed class OwnAccessRequestListTests(PostgresFixture postgres, RedisFixture redis)
{
    private static readonly string[] PaginationParameters = ["Cursor", "Limit"];
    private static readonly Guid FirstId = Guid.Parse("01900000-0000-7000-8000-000000000001");
    private static readonly Guid SecondId = Guid.Parse("01900000-0000-7000-8000-000000000002");
    private static readonly Guid ThirdId = Guid.Parse("01900000-0000-7000-8000-000000000003");
    private static readonly Guid ForeignId = Guid.Parse("01900000-0000-7000-8000-000000000004");

    [Fact]
    public async Task ListMine_MixedOwnersAndStates_ReturnsOnlySessionOwnersSummaries()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        test.Client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        var entitlement = await SeedEntitlementAsync(test);
        AddRequest(test, entitlement, FirstId);
        AddRequest(test, entitlement, SecondId, state: "Denied");
        AddRequest(test, entitlement, ForeignId, test.Resource.CreatedByPrincipalId);
        await test.Database.Context.SaveChangesAsync();
        int auditCount = await test.Database.Context.AuditEvents.CountAsync();

        // Act
        var page = await test.Client.GetFromJsonAsync<CursorPage<AccessRequestSummaryResponse>>(
            $"/api/access-requests/mine?requesterPrincipalId={test.Resource.CreatedByPrincipalId}");

        // Assert
        Assert.NotNull(page);
        Assert.Equal(new[]
        {
            new AccessRequestSummaryResponse(SecondId, test.Resource.PublicId, "Original target",
                entitlement.PublicId, "Temporary Linux administrator", 30, "Denied", test.Clock.Now),
            new AccessRequestSummaryResponse(FirstId, test.Resource.PublicId, "Original target",
                entitlement.PublicId, "Temporary Linux administrator", 30, "PendingApproval", test.Clock.Now)
        }, page.Items);
        Assert.Null(page.NextCursor);
        Assert.False(page.HasNextPage);
        Assert.Equal(auditCount, await test.Database.Context.AuditEvents.CountAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ListMine_NoOwnRequests_ReturnsEmptyPage(bool foreignRequestExists)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        if (foreignRequestExists)
        {
            var entitlement = await SeedEntitlementAsync(test);
            AddRequest(test, entitlement, ForeignId, test.Resource.CreatedByPrincipalId);
            await test.Database.Context.SaveChangesAsync();
        }

        // Act
        var page = await test.Client.GetFromJsonAsync<CursorPage<AccessRequestSummaryResponse>>("/api/access-requests/mine");

        // Assert
        Assert.NotNull(page);
        Assert.Empty(page.Items);
        Assert.Null(page.NextCursor);
        Assert.False(page.HasNextPage);
    }

    [Fact]
    public async Task ListMine_CursorPages_FiltersOwnershipBeforePagingWithoutDuplicates()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        foreach (var id in new[] { FirstId, SecondId, ThirdId })
        {
            AddRequest(test, entitlement, id);
        }

        AddRequest(test, entitlement, ForeignId, test.Resource.CreatedByPrincipalId);
        await test.Database.Context.SaveChangesAsync();
        var first = await test.Client.GetFromJsonAsync<CursorPage<AccessRequestSummaryResponse>>(
            "/api/access-requests/mine?limit=2");
        Assert.NotNull(first);
        Assert.Equal(new[] { ThirdId, SecondId }, first.Items.Select(item => item.Id));
        Assert.True(first.HasNextPage);
        Assert.NotNull(first.NextCursor);

        // Act
        var second = await test.Client.GetFromJsonAsync<CursorPage<AccessRequestSummaryResponse>>(
            $"/api/access-requests/mine?limit=2&cursor={first.NextCursor}");

        // Assert
        Assert.NotNull(second);
        Assert.Equal(FirstId, Assert.Single(second.Items).Id);
        Assert.Null(second.NextCursor);
        Assert.False(second.HasNextPage);
    }

    [Theory]
    [InlineData("", 20)]
    [InlineData("?limit=1", 1)]
    [InlineData("?limit=100", 100)]
    public async Task ListMine_ValidLimits_BoundsPageAndReportsContinuation(string query, int expectedCount)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        for (int index = 0; index < 101; index++)
        {
            AddRequest(test, entitlement, Guid.CreateVersion7(test.Clock.Now));
        }

        await test.Database.Context.SaveChangesAsync();

        // Act
        var page = await test.Client.GetFromJsonAsync<CursorPage<AccessRequestSummaryResponse>>("/api/access-requests/mine" + query);

        // Assert
        Assert.NotNull(page);
        Assert.Equal(expectedCount, page.Items.Count);
        Assert.True(page.HasNextPage);
        Assert.NotNull(page.NextCursor);
    }

    [Theory]
    [InlineData("inactive-resource")]
    [InlineData("deleted-resource")]
    [InlineData("inactive-entitlement")]
    [InlineData("removed-eligibility")]
    public async Task ListMine_RetiredAccess_RemainsInRequestHistory(string condition)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test, isActive: condition != "inactive-entitlement");
        AddRequest(test, entitlement, FirstId);
        test.Resource.IsActive = condition != "inactive-resource";
        test.Resource.DeletedAt = condition == "deleted-resource" ? test.Clock.Now.UtcDateTime : null;
        if (condition == "removed-eligibility")
        {
            await test.Database.Context.EligibilityRules.ExecuteDeleteAsync();
        }
        await test.Database.Context.SaveChangesAsync();

        // Act
        var page = await test.Client.GetFromJsonAsync<CursorPage<AccessRequestSummaryResponse>>("/api/access-requests/mine");

        // Assert
        Assert.NotNull(page);
        Assert.Equal(FirstId, Assert.Single(page.Items).Id);
    }

    [Theory]
    [InlineData("limit=0")]
    [InlineData("limit=-1")]
    [InlineData("limit=101")]
    [InlineData("limit=text")]
    [InlineData("cursor=broken")]
    [InlineData("cursor=e30")]
    [InlineData("cursor=bnVsbA")]
    public async Task ListMine_InvalidPagination_ReturnsProblemDetails(string query)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();

        // Act
        using var response = await test.Client.GetAsync("/api/access-requests/mine?" + query);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task ListMine_Anonymous_ReturnsUnauthorizedProblem()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/api/access-requests/mine");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task ListMine_OpenApi_DescribesPaginationSummariesAndErrors()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/access-requests/mine").GetProperty("get");
        Assert.Equal("AccessRequest.ListMine", operation.GetProperty("operationId").GetString());
        Assert.Equal(PaginationParameters, operation.GetProperty("parameters").EnumerateArray()
            .Select(parameter => parameter.GetProperty("name").GetString()).Order());
        foreach (string status in new[] { "200", "400", "401", "500" })
        {
            Assert.True(operation.GetProperty("responses").TryGetProperty(status, out _));
        }

        var schema = json.RootElement.GetProperty("components").GetProperty("schemas")
            .GetProperty("AccessRequestSummaryResponse").GetProperty("properties");
        Assert.Equal("uuid", schema.GetProperty("id").GetProperty("format").GetString());
        Assert.Equal("string", schema.GetProperty("resourceName").GetProperty("type").GetString());
        Assert.False(schema.TryGetProperty("requesterPrincipalId", out _));
        Assert.False(schema.TryGetProperty("idempotencyKey", out _));
    }
}
