using System.Data.Common;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.Common.Pagination;
using Application.Principals;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Infrastructure.Principals;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Backend.IntegrationTests.Authorization;

[Collection(StorageCollection4.Name)]
public sealed class ApprovalAuthorityReadTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("admin", true, 200)]
    [InlineData("user", true, 403)]
    [InlineData("approver", true, 403)]
    [InlineData("superadmin", true, 403)]
    [InlineData("", true, 403)]
    [InlineData("admin", false, 401)]
    public async Task List_RequiresExplicitReadPermissionWithoutRecentAuthentication(string role, bool login, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection,
            roles: role.Length == 0 ? [] : [role]);
        var target = await TargetAsync(test);
        if (login)
        {
            await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);
        }

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{target.PublicId}/approval-authority");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        if (status != 200)
        {
            Assert.Null(response.Headers.ETag);
            Assert.DoesNotContain("\"items\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task List_DisabledPrincipal_RetainsInactiveAndRetiredAssignmentsWithPrincipalETag()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var active = AddBinding(test, target.Id, 1);
        var inactive = AddBinding(test, target.Id, 2, active: false);
        var retired = AddBinding(test, target.Id, 3, retired: true);
        test.AddViewBinding(test.Resource);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);
        using var mapping = await test.Client.GetAsync($"/api/principals/{target.PublicId}");

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{target.PublicId}/approval-authority");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await response.Content.ReadFromJsonAsync<CursorPage<ResourceAccessResponse>>();
        Assert.NotNull(page);
        Assert.Equal(3, page.Items.Count);
        Assert.Null(page.NextCursor);
        Assert.Equal(mapping.Headers.ETag, response.Headers.ETag);
        Assert.NotNull(response.Headers.ETag);
        Assert.Equal(new[] { active.PublicId, inactive.PublicId, retired.PublicId }, page.Items.Select(value => value.Id));
        Assert.True(page.Items[0].IsActive);
        Assert.False(page.Items[0].IsRetired);
        Assert.False(page.Items[1].IsActive);
        Assert.True(page.Items[2].IsActive);
        Assert.True(page.Items[2].IsRetired);
        Assert.Equal("Resource 3", page.Items[2].ResourceName);
        Assert.Equal(test.Clock.Now.AddHours(-1), page.Items[0].AssignedAt);
        Assert.Equal(test.Clock.Now, page.Items[0].ModifiedAt);
        Assert.DoesNotContain(page.Items, value => value.ResourceId == test.Resource.PublicId);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(json.RootElement.TryGetProperty("version", out _));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType.StartsWith("approval_authority.")));
    }

    [Fact]
    public async Task List_CursorContinuation_ReturnsEachTargetAssignmentOnce()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var first = AddBinding(test, target.Id, 1);
        var last = AddBinding(test, target.Id, 2, active: false);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        var page = await test.Client.GetFromJsonAsync<CursorPage<ResourceAccessResponse>>($"/api/principals/{target.PublicId}/approval-authority?limit=1");
        Assert.NotNull(page);
        Assert.NotNull(page.NextCursor);
        Assert.Equal(first.PublicId, Assert.Single(page.Items).Id);

        // Act
        var continuation = await test.Client.GetFromJsonAsync<CursorPage<ResourceAccessResponse>>(
            $"/api/principals/{target.PublicId}/approval-authority?limit=1&cursor=" + Uri.EscapeDataString(page.NextCursor));

        // Assert
        Assert.NotNull(continuation);
        Assert.Equal(last.PublicId, Assert.Single(continuation.Items).Id);
        Assert.Null(continuation.NextCursor);
    }

    [Fact]
    public async Task List_NoAssignments_ReturnsEmptyPageWithUsablePrincipalVersion()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        using var mapping = await test.Client.GetAsync($"/api/principals/{target.PublicId}");

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{target.PublicId}/approval-authority");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await response.Content.ReadFromJsonAsync<CursorPage<ResourceAccessResponse>>();
        Assert.NotNull(page);
        Assert.Empty(page.Items);
        Assert.Null(page.NextCursor);
        Assert.NotNull(response.Headers.ETag);
        Assert.Equal(mapping.Headers.ETag, response.Headers.ETag);
    }

    [Theory]
    [InlineData("limit=0")]
    [InlineData("limit=101")]
    [InlineData("cursor=invalid")]
    public async Task List_InvalidPagination_ReturnsValidationProblem(string query)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{target.PublicId}/approval-authority?" + query);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Null(response.Headers.ETag);
    }

    [Fact]
    public async Task List_UnknownPrincipal_ReturnsNotFoundWithoutVersion()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{Guid.NewGuid()}/approval-authority");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Null(response.Headers.ETag);
    }

    [Fact]
    public async Task List_GlobalSplitQueryConfiguration_StillReadsRowsAndVersionInOneStatement()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var binding = AddBinding(test, target.Id, 1);
        await test.Database.Context.SaveChangesAsync();
        var counter = new StatementCounter();
        await using var database = new PamDbContext(new DbContextOptionsBuilder<PamDbContext>()
            .UseNpgsql(test.Database.Context.Database.GetConnectionString(), options => options.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery))
            .UseSnakeCaseNamingConvention().AddInterceptors(counter).Options);
        IApprovalAuthorityService service = new ResourceAccessService(database, test.Clock);

        // Act
        var result = await service.ListAsync(target.PublicId, 20, null);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(binding.PublicId, Assert.Single(result.Page.Items).Id);
        Assert.Equal(target.Version, result.Version);
        Assert.Equal(1, counter.Count);
        Assert.Empty(database.ChangeTracker.Entries());
    }

    [Fact]
    public async Task List_OpenApi_DescribesBoundedRetainedAssignmentsAndErrors()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/principals/{id}/approval-authority").GetProperty("get");
        Assert.Equal("Principal.ApprovalAuthority.List", operation.GetProperty("operationId").GetString());
        Assert.Contains("approval_authority.read", operation.GetProperty("description").GetString(), StringComparison.Ordinal);
        Assert.True(operation.GetProperty("responses").TryGetProperty("200", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("403", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("404", out _));
    }

    [Fact]
    public async Task List_ViewAndAuthorityCollections_SelectOnlyTheirExactRelationshipKind()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var authority = AddBinding(test, target.Id, 1);
        var view = test.AddViewBinding(test.Resource, target.Id);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var authorityResponse = await test.Client.GetAsync($"/api/principals/{target.PublicId}/approval-authority");
        using var viewResponse = await test.Client.GetAsync($"/api/principals/{target.PublicId}/resource-access");

        // Assert
        Assert.Equal(HttpStatusCode.OK, authorityResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, viewResponse.StatusCode);
        var authorityPage = await authorityResponse.Content.ReadFromJsonAsync<CursorPage<ResourceAccessResponse>>();
        var viewPage = await viewResponse.Content.ReadFromJsonAsync<CursorPage<ResourceAccessResponse>>();
        Assert.NotNull(authorityPage);
        Assert.NotNull(viewPage);
        Assert.Equal(authority.PublicId, Assert.Single(authorityPage.Items).Id);
        Assert.Equal(view.PublicId, Assert.Single(viewPage.Items).Id);
        Assert.Equal(authorityResponse.Headers.ETag, viewResponse.Headers.ETag);
    }

    private static Task<Principal> TargetAsync(ResourceTestContext test) =>
        test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Subject == "ivan");

    private static ResourcePrincipalBinding AddBinding(ResourceTestContext test, long principalId, int suffix,
        bool active = true, bool retired = false)
    {
        var resource = new ManagedResource
        {
            PublicId = Guid.Parse("00000000-0000-7000-8000-" + suffix.ToString("D12", CultureInfo.InvariantCulture)),
            Name = "Resource " + suffix.ToString(CultureInfo.InvariantCulture),
            ResourceType = "linux",
            Environment = "dev",
            CreatedByPrincipalId = test.ActorId,
            ModifiedByPrincipalId = test.ActorId,
            CreatedAt = test.Clock.Now.UtcDateTime,
            ModifiedAt = test.Clock.Now.UtcDateTime,
            DeletedAt = retired ? test.Clock.Now.UtcDateTime : null
        };
        test.Database.Context.ManagedResources.Add(resource);
        var binding = new ResourcePrincipalBinding
        {
            PrincipalId = principalId,
            Resource = resource,
            Kind = Application.Authorization.ResourceBindingKind.ApproveRequests,
            IsActive = active,
            AssignedByPrincipalId = test.ActorId,
            ModifiedByPrincipalId = test.ActorId,
            AssignedAt = test.Clock.Now.AddHours(-1).UtcDateTime,
            ModifiedAt = test.Clock.Now.UtcDateTime
        };
        test.Database.Context.ResourcePrincipalBindings.Add(binding);
        return binding;
    }

    private sealed class StatementCounter : DbCommandInterceptor
    {
        public int Count { get; private set; }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Count++;
            return ValueTask.FromResult(result);
        }
    }
}
