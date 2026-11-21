using System.Net;
using System.Net.Http.Json;
using Application.Common.Pagination;
using Application.Principals;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class PrincipalDirectoryTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("admin", true, 200)]
    [InlineData("admin", false, 404)]
    [InlineData("user", true, 403)]
    [InlineData("approver", true, 403)]
    [InlineData("", true, 403)]
    public async Task Get_ExplicitPermissionAndMappingExistence_ControlDisclosure(string role, bool exists, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection,
            roles: role.Length == 0 ? [] : [role]);
        await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);
        var expected = await test.Database.Context.Principals.SingleAsync(principal => principal.Subject == "ivan");

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{(exists ? expected.PublicId : Guid.NewGuid())}");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        if (status == 200)
        {
            var principal = await response.Content.ReadFromJsonAsync<PrincipalResponse>();
            Assert.NotNull(principal);
            Assert.Equal(expected.PublicId, principal.Id);
            Assert.Equal("test-issuer", principal.Issuer);
            Assert.Equal("ivan", principal.Subject);
            Assert.False(principal.IsEnabled);
        }
        else
        {
            Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
            Assert.DoesNotContain("\"subject\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("admin", 200)]
    [InlineData("admin,user", 200)]
    [InlineData("user", 403)]
    [InlineData("approver", 403)]
    [InlineData("user,approver", 403)]
    [InlineData("superadmin", 403)]
    [InlineData("", 403)]
    public async Task List_RequiresDirectoryReadCapability(string roles, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection,
            roles: roles.Split(',', StringSplitOptions.RemoveEmptyEntries));
        await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);

        // Act
        using var response = await test.Client.GetAsync("/api/principals");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        if (status == 200)
        {
            var page = await response.Content.ReadFromJsonAsync<CursorPage<PrincipalResponse>>();
            Assert.NotNull(page);
            Assert.Equal(2, page.Items.Count);
            Assert.Null(page.NextCursor);
            var actor = Assert.Single(page.Items, principal => principal.Subject == "ana");
            Assert.True(actor.IsEnabled);
            Assert.Equal("https://identity.example/realms/pam", actor.Issuer);
            Assert.False(Assert.Single(page.Items, principal => principal.Subject == "ivan").IsEnabled);
        }
        else
        {
            Assert.DoesNotContain("\"subject\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task List_CursorContinuation_ReturnsEachMappingOnceInPublicIdOrder()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        var expected = await test.Database.Context.Principals.OrderBy(principal => principal.PublicId)
            .Select(principal => principal.PublicId).ToArrayAsync();
        using var firstResponse = await test.Client.GetAsync("/api/principals?limit=1");
        firstResponse.EnsureSuccessStatusCode();
        var first = await firstResponse.Content.ReadFromJsonAsync<CursorPage<PrincipalResponse>>();
        Assert.NotNull(first);
        Assert.NotNull(first.NextCursor);

        // Act
        using var response = await test.Client.GetAsync("/api/principals?limit=1&cursor=" + Uri.EscapeDataString(first.NextCursor));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var second = await response.Content.ReadFromJsonAsync<CursorPage<PrincipalResponse>>();
        Assert.NotNull(second);
        Assert.Null(second.NextCursor);
        Assert.Equal(expected, new[] { Assert.Single(first.Items).Id, Assert.Single(second.Items).Id });
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
        using var response = await test.Client.GetAsync("/api/principals?" + query);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task List_PositionPastLastMapping_ReturnsEmptyTerminalPage()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        Guid last = await test.Database.Context.Principals.OrderByDescending(principal => principal.PublicId)
            .Select(principal => principal.PublicId).FirstAsync();
        string cursor = CursorCodec.Encode(new PrincipalCursor(last));

        // Act
        using var response = await test.Client.GetAsync("/api/principals?cursor=" + Uri.EscapeDataString(cursor));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await response.Content.ReadFromJsonAsync<CursorPage<PrincipalResponse>>();
        Assert.NotNull(page);
        Assert.Empty(page.Items);
        Assert.Null(page.NextCursor);
    }
}
