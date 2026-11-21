using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.Common.Pagination;
using Application.Resources;
using Backend.IntegrationTests.Fixtures;
using Infrastructure.Persistence.Entities;

namespace Backend.IntegrationTests.Resources;

[Collection("Cookie sessions")]
public sealed class RequestableResourceTests(PostgresFixture postgres, RedisFixture redis)
{
    [Fact]
    public async Task ListRequestable_WithEligibility_ReturnsPublicIdsAndFormConstraints()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var admin = AddEntitlement(test, test.Resource, "TemporaryLinuxAdmin", true, test.ActorId, true);
        var reader = AddEntitlement(test, test.Resource, "ReadOnly", true, test.ActorId, true);
        await test.Database.Context.SaveChangesAsync();

        // Act
        var page = await test.Client.GetFromJsonAsync<CursorPage<ResourceResponse>>(
            "/api/resources?requestable=true");

        // Assert
        Assert.NotNull(page);
        var resource = Assert.Single(page.Items);
        Assert.Equal(test.Resource.PublicId, resource.Id);
        Assert.Equal("Original target", resource.Name);
        Assert.Equal("Original description", resource.Description);
        Assert.Equal("linux", resource.ResourceType);
        Assert.Equal("dev", resource.Environment);
        Assert.True(resource.IsActive);
        Assert.NotNull(resource.Entitlements);
        Assert.Equal(
            new[]
            {
                new RequestableEntitlementResponse(admin.PublicId, "TemporaryLinuxAdmin", "TemporaryLinuxAdmin",
                    60, true, true),
                new RequestableEntitlementResponse(reader.PublicId, "ReadOnly", "ReadOnly", 120, false, false)
            }.OrderBy(entitlement => entitlement.Id),
            resource.Entitlements);
        Assert.Null(page.NextCursor);
        Assert.False(page.HasNextPage);
    }

    [Theory]
    [InlineData("inactive")]
    [InlineData("disabled-eligibility")]
    [InlineData("other-principal")]
    [InlineData("no-eligibility")]
    public async Task ListRequestable_WithUnavailableEntitlement_OmitsIt(string condition)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var available = AddEntitlement(test, test.Resource, "TemporaryLinuxAdmin", true, test.ActorId, true);
        long? principalId = condition switch
        {
            "other-principal" => test.Resource.CreatedByPrincipalId,
            "no-eligibility" => null,
            _ => test.ActorId
        };
        AddEntitlement(test, test.Resource, "Unavailable", condition != "inactive", principalId,
            condition != "disabled-eligibility");
        await test.Database.Context.SaveChangesAsync();

        // Act
        var page = await test.Client.GetFromJsonAsync<CursorPage<ResourceResponse>>(
            "/api/resources?requestable=true");

        // Assert
        Assert.NotNull(page);
        var resource = Assert.Single(page.Items);
        Assert.NotNull(resource.Entitlements);
        Assert.Equal(available.PublicId, Assert.Single(resource.Entitlements).Id);
    }

    [Theory]
    [InlineData("inactive-resource")]
    [InlineData("deleted-resource")]
    [InlineData("no-entitlements")]
    [InlineData("inactive-entitlement")]
    [InlineData("disabled-eligibility")]
    [InlineData("other-principal")]
    [InlineData("no-eligibility")]
    public async Task ListRequestable_WithoutAvailableEntitlements_ReturnsEmptyPage(string condition)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        test.Resource.IsActive = condition != "inactive-resource";
        // Keep IsActive true for the deleted case to independently prove soft-delete filtering.
        test.Resource.DeletedAt = condition == "deleted-resource" ? test.Clock.Now.UtcDateTime : null;
        if (condition != "no-entitlements")
        {
            long? principalId = condition switch
            {
                "other-principal" => test.Resource.CreatedByPrincipalId,
                "no-eligibility" => null,
                _ => test.ActorId
            };
            AddEntitlement(test, test.Resource, "TemporaryLinuxAdmin", condition != "inactive-entitlement",
                principalId, condition != "disabled-eligibility");
        }

        await test.Database.Context.SaveChangesAsync();

        // Act
        var page = await test.Client.GetFromJsonAsync<CursorPage<ResourceResponse>>(
            $"/api/resources?requestable=true&principalId={test.Resource.CreatedByPrincipalId}");

        // Assert
        Assert.NotNull(page);
        Assert.Empty(page.Items);
        Assert.Null(page.NextCursor);
        Assert.False(page.HasNextPage);
    }

    [Fact]
    public async Task ListRequestable_WithCursor_FiltersBeforePagingWithoutOverlap()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        Guid[] ids =
        [
            Guid.Parse("019a0000-0000-7000-8000-000000000001"),
            Guid.Parse("019a0000-0000-7000-8000-000000000002"),
            Guid.Parse("019a0000-0000-7000-8000-000000000003"),
            Guid.Parse("019a0000-0000-7000-8000-000000000004"),
            Guid.Parse("019a0000-0000-7000-8000-000000000005")
        ];
        foreach (int index in new[] { 4, 2, 0, 3, 1 })
        {
            var resource = new ManagedResource
            {
                PublicId = ids[index],
                Name = $"Target {index}",
                ResourceType = "linux",
                Environment = "dev",
                CreatedByPrincipalId = test.ActorId,
                ModifiedByPrincipalId = test.ActorId,
                CreatedAt = test.Clock.Now.UtcDateTime,
                ModifiedAt = test.Clock.Now.UtcDateTime
            };
            test.Database.Context.ManagedResources.Add(resource);
            AddEntitlement(test, resource, "TemporaryLinuxAdmin", true, test.ActorId, index % 2 == 0);
            AddEntitlement(test, resource, "ReadOnly", true, test.ActorId, index % 2 == 0);
        }

        await test.Database.Context.SaveChangesAsync();
        var first = await test.Client.GetFromJsonAsync<CursorPage<ResourceResponse>>(
            "/api/resources?requestable=true&limit=2");
        Assert.NotNull(first);
        Assert.NotNull(first.NextCursor);

        // Act
        var second = await test.Client.GetFromJsonAsync<CursorPage<ResourceResponse>>(
            $"/api/resources?requestable=true&limit=2&cursor={first.NextCursor}");

        // Assert
        Assert.NotNull(second);
        Assert.Equal(new[] { ids[0], ids[2] }, first.Items.Select(resource => resource.Id));
        Assert.Equal(ids[4], Assert.Single(second.Items).Id);
        Assert.All(first.Items.Concat(second.Items), resource =>
        {
            Assert.NotNull(resource.Entitlements);
            Assert.Equal(2, resource.Entitlements.Count);
        });
        Assert.Null(second.NextCursor);
        Assert.False(second.HasNextPage);
    }

    [Theory]
    [InlineData("")]
    [InlineData("?requestable=false")]
    public async Task List_WithoutRequestableFilter_PreservesManagementResponse(string query)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        test.Resource.IsActive = false;
        AddEntitlement(test, test.Resource, "TemporaryLinuxAdmin", true, test.ActorId, true);
        await test.Database.Context.SaveChangesAsync();

        // Act
        using var response = await test.Client.GetAsync($"/api/resources{query}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var resource = Assert.Single(json.RootElement.GetProperty("items").EnumerateArray());
        Assert.Equal(test.Resource.PublicId, resource.GetProperty("id").GetGuid());
        Assert.False(resource.GetProperty("isActive").GetBoolean());
        Assert.False(resource.TryGetProperty("entitlements", out _));
    }

    [Theory]
    [InlineData("requestable=invalid")]
    [InlineData("requestable=true&limit=0")]
    [InlineData("requestable=true&limit=101")]
    [InlineData("requestable=true&cursor=broken")]
    public async Task ListRequestable_WithInvalidQuery_ReturnsProblemDetails(string query)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();

        // Act
        using var response = await test.Client.GetAsync($"/api/resources?{query}");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task ListRequestable_OpenApi_DescribesFilterAndEntitlementContract()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var parameters = json.RootElement.GetProperty("paths").GetProperty("/api/resources")
            .GetProperty("get").GetProperty("parameters").EnumerateArray();
        var requestable = Assert.Single(parameters, parameter => parameter.GetProperty("name").GetString() == "Requestable");
        Assert.Equal("query", requestable.GetProperty("in").GetString());
        Assert.Equal("boolean", requestable.GetProperty("schema").GetProperty("type").GetString());
        var schemas = json.RootElement.GetProperty("components").GetProperty("schemas");
        Assert.True(schemas.GetProperty("ResourceResponse").GetProperty("properties")
            .TryGetProperty("entitlements", out _));
        var entitlement = schemas.GetProperty("RequestableEntitlementResponse").GetProperty("properties");
        Assert.Equal("uuid", entitlement.GetProperty("id").GetProperty("format").GetString());
        Assert.True(entitlement.TryGetProperty("maxDurationMinutes", out _));
        Assert.True(entitlement.TryGetProperty("requiresApproval", out _));
        Assert.True(entitlement.TryGetProperty("requiresTicket", out _));
    }

    [Fact]
    public async Task ListRequestable_WithoutAuthentication_ReturnsUnauthorized()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/api/resources?requestable=true");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static Entitlement AddEntitlement(
        ResourceTestContext test,
        ManagedResource resource,
        string code,
        bool isActive,
        long? principalId,
        bool eligibilityEnabled)
    {
        if (principalId is not null)
        {
            test.AddViewBinding(resource, principalId);
        }
        var entitlement = new Entitlement
        {
            PublicId = Guid.CreateVersion7(),
            Resource = resource,
            Code = code,
            Name = code,
            MaxDurationMinutes = code == "TemporaryLinuxAdmin" ? 60 : 120,
            RequiresApproval = code == "TemporaryLinuxAdmin",
            RequiresTicket = code == "TemporaryLinuxAdmin",
            IsActive = isActive
        };
        test.Database.Context.Entitlements.Add(entitlement);
        if (principalId is not null)
        {
            test.Database.Context.EligibilityRules.Add(new EligibilityRule
            {
                Entitlement = entitlement,
                PrincipalId = principalId.Value,
                IsEnabled = eligibilityEnabled,
                CreatedAt = test.Clock.Now.UtcDateTime
            });
        }

        return entitlement;
    }
}
