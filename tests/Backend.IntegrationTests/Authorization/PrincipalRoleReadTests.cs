using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.Principals;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Backend.IntegrationTests.Sessions;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Authorization;

[Collection(StorageCollection4.Name)]
public sealed class PrincipalRoleReadTests(PostgresFixture postgres, RedisFixture redis)
{
    private static readonly string[] KnownBundles = ["admin", "approver", "user"];

    [Theory]
    [InlineData("admin", true, 200)]
    [InlineData("user", true, 403)]
    [InlineData("approver", true, 403)]
    [InlineData("superadmin", true, 403)]
    [InlineData("", true, 403)]
    [InlineData("admin", false, 401)]
    public async Task Get_RequiresExplicitRoleReadPermission(string role, bool login, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection,
            roles: role.Length == 0 ? [] : [role]);
        if (login)
        {
            await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);
        }
        Guid id = await test.Database.Context.Principals.Where(value => value.Id == test.ActorId)
            .Select(value => value.PublicId).SingleAsync();

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{id}/roles");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        if (status != 200)
        {
            Assert.DoesNotContain("\"roles\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Get_DisabledTarget_ReturnsOnlyKnownExplicitBundlesWithMatchingPrincipalETag()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await test.Database.Context.Principals.SingleAsync(value => value.Subject == "ivan");
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "user", "admin", "approver", "superadmin");
        await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);
        using var mapping = await test.Client.GetAsync($"/api/principals/{target.PublicId}");

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{target.PublicId}/roles");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<PrincipalRolesResponse>();
        Assert.NotNull(result);
        Assert.Equal(target.PublicId, result.PrincipalId);
        Assert.Equal(KnownBundles, result.Roles);
        Assert.NotNull(response.Headers.ETag);
        Assert.Equal(mapping.Headers.ETag, response.Headers.ETag);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(json.RootElement.TryGetProperty("version", out _));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType.StartsWith("role.")));
    }

    [Fact]
    public async Task Get_RolelessMapping_ReturnsEmptyCollection()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var id = await test.Database.Context.Principals.Where(value => value.Subject == "ivan").Select(value => value.PublicId).SingleAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{id}/roles");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<PrincipalRolesResponse>();
        Assert.NotNull(result);
        Assert.Empty(result.Roles);
        Assert.NotNull(response.Headers.ETag);
    }

    [Fact]
    public async Task Get_UnknownMapping_ReturnsNotFound()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{Guid.NewGuid()}/roles");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Null(response.Headers.ETag);
    }

    [Fact]
    public async Task Get_OpenApi_DescribesBoundedRoleReadAndErrors()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/principals/{id}/roles").GetProperty("get");
        Assert.Equal("Principal.Roles.Get", operation.GetProperty("operationId").GetString());
        Assert.Contains("roles.read", operation.GetProperty("description").GetString(), StringComparison.Ordinal);
        var responses = operation.GetProperty("responses");
        Assert.True(responses.TryGetProperty("200", out _));
        Assert.True(responses.TryGetProperty("401", out _));
        Assert.True(responses.TryGetProperty("403", out _));
        Assert.True(responses.TryGetProperty("404", out _));
    }
}
