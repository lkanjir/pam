using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using Application.Authorization;
using Application.Principals;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Backend.IntegrationTests.Sessions;
using FakeItEasy;
using Infrastructure.Authentication;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Infrastructure.Principals;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Backend.IntegrationTests.Authorization;

[Collection(StorageCollection2.Name)]
public sealed class PrincipalAuthorizationOverviewTests(PostgresFixture postgres, RedisFixture redis)
{
    private static readonly string[] ExpectedRoles = ["approver", "user"];

    [Theory]
    [InlineData("admin", true, 200)]
    [InlineData("user", true, 403)]
    [InlineData("approver", true, 403)]
    [InlineData("superadmin", true, 403)]
    [InlineData("", true, 403)]
    [InlineData("admin", false, 401)]
    public async Task Get_RequiresAdministrativeReadsWithoutRecentAuthentication(string role, bool login, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: role.Split(',', StringSplitOptions.RemoveEmptyEntries));
        var target = await TargetAsync(test);
        if (login)
        {
            await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);
        }

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{target.PublicId}/authorization");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        if (status != 200)
        {
            Assert.Null(response.Headers.ETag);
            Assert.DoesNotContain("\"principal\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData(PamPermissions.PrincipalsRead)]
    [InlineData(PamPermissions.RolesRead)]
    [InlineData(PamPermissions.ResourceAccessRead)]
    [InlineData(PamPermissions.EligibilityRead)]
    [InlineData(PamPermissions.ApprovalAuthorityRead)]
    public async Task Get_AnyRequiredReadDenied_DoesNotReturnPartialAuthorization(string deniedPermission)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, configure: app =>
        {
            var options = app.Services.GetRequiredService<IOptions<AuthorizationOptions>>().Value;
            var policy = options.GetPolicy(deniedPermission) ?? throw new InvalidOperationException("Expected policy is missing.");
            options.AddPolicy(deniedPermission, new AuthorizationPolicyBuilder(policy).RequireAssertion(_ => false).Build());
        });
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{target.PublicId}/authorization");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(response.Headers.ETag);
        Assert.DoesNotContain("\"principal\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Get_RetainedAuthorization_ReturnsExactConfiguredCountsAndUsableCollectionLinks()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "user", "approver", "superadmin");
        var first = AddResource(test, "First");
        var second = AddResource(test, "Second", active: false);
        var retired = AddResource(test, "Retired", retired: true);
        AddBinding(test, target.Id, first, ResourceBindingKind.ViewResource, true);
        AddBinding(test, target.Id, second, ResourceBindingKind.ViewResource, false);
        AddBinding(test, target.Id, retired, ResourceBindingKind.ViewResource, true);
        AddBinding(test, target.Id, first, ResourceBindingKind.ApproveRequests, false);
        AddBinding(test, target.Id, second, ResourceBindingKind.ApproveRequests, true);
        AddBinding(test, target.Id, retired, ResourceBindingKind.ApproveRequests, false);
        AddEligibility(test, target.Id, first, enabled: true);
        AddEligibility(test, target.Id, second, enabled: false);
        AddEligibility(test, target.Id, retired, enabled: true);
        AddBinding(test, test.ActorId, first, ResourceBindingKind.ViewResource, true);
        AddEligibility(test, test.ActorId, first, enabled: true, code: "foreign");
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);
        using var principal = await test.Client.GetAsync($"/api/principals/{target.PublicId}");

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{target.PublicId}/authorization");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var overview = await response.Content.ReadFromJsonAsync<PrincipalAuthorizationOverviewResponse>();
        Assert.NotNull(overview);
        Assert.Equal(target.PublicId, overview.Principal.Id);
        Assert.False(overview.Principal.IsEnabled);
        Assert.Equal(ExpectedRoles, overview.Roles);
        Assert.Equal(new PrincipalAssignmentCounts(2, 1, 1), overview.ResourceAccess);
        Assert.Equal(new PrincipalAssignmentCounts(2, 1, 2), overview.Eligibility);
        Assert.Equal(new PrincipalAssignmentCounts(1, 2, 1), overview.ApprovalAuthority);
        Assert.NotNull(response.Headers.ETag);
        Assert.Equal(principal.Headers.ETag, response.Headers.ETag);
        Assert.NotNull(overview.Links);
        Assert.Equal($"/api/principals/{target.PublicId}/roles", overview.Links.Roles);
        Assert.Equal($"/api/principals/{target.PublicId}/resource-access", overview.Links.ResourceAccess);
        Assert.Equal($"/api/principals/{target.PublicId}/eligibility", overview.Links.Eligibility);
        Assert.Equal($"/api/principals/{target.PublicId}/approval-authority", overview.Links.ApprovalAuthority);
        foreach (string link in new[] { overview.Links.Roles, overview.Links.ResourceAccess, overview.Links.Eligibility, overview.Links.ApprovalAuthority })
        {
            using var collection = await test.Client.GetAsync(link);
            Assert.Equal(HttpStatusCode.OK, collection.StatusCode);
            Assert.Equal(response.Headers.ETag, collection.Headers.ETag);
        }
    }

    [Fact]
    public async Task Get_EmptyAuthorization_ReturnsZeroCountsWithoutInventedAssignments()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{target.PublicId}/authorization");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var overview = await response.Content.ReadFromJsonAsync<PrincipalAuthorizationOverviewResponse>();
        Assert.NotNull(overview);
        Assert.Empty(overview.Roles);
        Assert.Equal(new PrincipalAssignmentCounts(0, 0, 0), overview.ResourceAccess);
        Assert.Equal(new PrincipalAssignmentCounts(0, 0, 0), overview.Eligibility);
        Assert.Equal(new PrincipalAssignmentCounts(0, 0, 0), overview.ApprovalAuthority);
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.AnyAsync());
        Assert.False(await test.Database.Context.EligibilityRules.AnyAsync());
    }

    [Fact]
    public async Task Get_UnknownPrincipal_ReturnsNotFoundWithoutVersion()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{Guid.NewGuid()}/authorization");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Null(response.Headers.ETag);
    }

    [Fact]
    public async Task Get_GlobalSplitQuery_StillUsesOneReadOnlyStatementForStateAndVersion()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var resource = AddResource(test, "Counted");
        AddBinding(test, target.Id, resource, ResourceBindingKind.ViewResource, true);
        await test.Database.Context.SaveChangesAsync();
        var counter = new StatementCounter();
        await using var database = new PamDbContext(new DbContextOptionsBuilder<PamDbContext>()
            .UseNpgsql(test.Database.Context.Database.GetConnectionString(), options => options.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery))
            .UseSnakeCaseNamingConvention().AddInterceptors(counter).Options);
        var service = new PrincipalAdministrationService(database, test.Clock, A.Fake<ISessionTicketStore>());

        // Act
        var overview = await service.GetAuthorizationOverviewAsync(target.PublicId);

        // Assert
        Assert.NotNull(overview);
        Assert.Equal(target.Version, overview.Principal.Version);
        Assert.Equal(new PrincipalAssignmentCounts(1, 0, 0), overview.ResourceAccess);
        Assert.Equal(1, counter.Count);
        Assert.Empty(database.ChangeTracker.Entries());
    }

    [Fact]
    public async Task Get_OpenApi_DescribesCombinedReadRequirementsAndRetainedState()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/principals/{id}/authorization").GetProperty("get");
        Assert.Equal("Principal.Authorization.Get", operation.GetProperty("operationId").GetString());
        Assert.Contains("eligibility.read", operation.GetProperty("description").GetString(), StringComparison.Ordinal);
        Assert.Contains("approval_authority.read", operation.GetProperty("description").GetString(), StringComparison.Ordinal);
        Assert.True(operation.GetProperty("responses").TryGetProperty("403", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("404", out _));
    }

    private static Task<Principal> TargetAsync(ResourceTestContext test) =>
        test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Subject == "ivan");

    private static ManagedResource AddResource(ResourceTestContext test, string name, bool active = true, bool retired = false)
    {
        var resource = new ManagedResource
        {
            Name = name,
            ResourceType = "linux",
            Environment = "dev",
            IsActive = active,
            CreatedByPrincipalId = test.ActorId,
            ModifiedByPrincipalId = test.ActorId,
            CreatedAt = test.Clock.Now.UtcDateTime,
            ModifiedAt = test.Clock.Now.UtcDateTime,
            DeletedAt = retired ? test.Clock.Now.UtcDateTime : null
        };
        test.Database.Context.ManagedResources.Add(resource);
        return resource;
    }

    private static void AddBinding(ResourceTestContext test, long principalId, ManagedResource resource, ResourceBindingKind kind, bool active) =>
        test.Database.Context.ResourcePrincipalBindings.Add(new ResourcePrincipalBinding
        {
            PrincipalId = principalId,
            Resource = resource,
            Kind = kind,
            IsActive = active,
            AssignedByPrincipalId = test.ActorId,
            ModifiedByPrincipalId = test.ActorId,
            AssignedAt = test.Clock.Now.UtcDateTime,
            ModifiedAt = test.Clock.Now.UtcDateTime
        });

    private static void AddEligibility(ResourceTestContext test, long principalId, ManagedResource resource, bool enabled, string code = "read") =>
        test.Database.Context.EligibilityRules.Add(new EligibilityRule
        {
            PrincipalId = principalId,
            IsEnabled = enabled,
            CreatedAt = test.Clock.Now.UtcDateTime,
            Entitlement = new Entitlement
            { Resource = resource, Code = code, Name = code, IsActive = true, MaxDurationMinutes = 60, RequiresApproval = true }
        });

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
