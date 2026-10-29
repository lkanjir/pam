using System.Net;
using System.Net.Http.Json;
using Application.Common.Pagination;
using Application.Resources;
using Backend.IntegrationTests.Fixtures;
using Infrastructure.Persistence.Entities;

namespace Backend.IntegrationTests.Resources;

[Collection("Cookie sessions")]
public sealed class ResourceReadTests(PostgresFixture postgres, RedisFixture redis)
{
    [Fact]
    public async Task List_WithCursor_ReturnsConsecutivePagesWithoutOverlap()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var ids = await SeedOrderedResourcesAsync(test);
        var first = await test.Client.GetFromJsonAsync<CursorPage<ResourceResponse>>("/api/resources?limit=2");
        Assert.NotNull(first);
        Assert.NotNull(first.NextCursor);

        // Act
        var second = await test.Client.GetFromJsonAsync<CursorPage<ResourceResponse>>(
            $"/api/resources?limit=2&cursor={first.NextCursor}");

        // Assert
        Assert.NotNull(second);
        Assert.Equal(ids, first.Items.Concat(second.Items).Select(r => r.Id).ToArray());
        Assert.Equal(2, first.Items.Count);
        Assert.Single(second.Items);
        Assert.False(second.HasNextPage);
        Assert.Null(second.NextCursor);
    }

    [Fact]
    public async Task List_WhenCursorResourceWasDeleted_ContinuesAfterItsPosition()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var ids = await SeedOrderedResourcesAsync(test);
        var first = await test.Client.GetFromJsonAsync<CursorPage<ResourceResponse>>("/api/resources?limit=1");
        Assert.NotNull(first);
        using var deletion = await test.Client.DeleteAsync($"/api/resources/{ids[0]}");
        deletion.EnsureSuccessStatusCode();

        // Act
        var second = await test.Client.GetFromJsonAsync<CursorPage<ResourceResponse>>(
            $"/api/resources?limit=1&cursor={first.NextCursor}");

        // Assert
        Assert.NotNull(second);
        Assert.Equal(ids[1], Assert.Single(second.Items).Id);
    }

    [Theory]
    [InlineData("")]
    [InlineData("broken")]
    [InlineData("e30")]
    public async Task List_WithInvalidCursor_ReturnsBadRequest(string cursor)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();

        // Act
        using var response = await test.Client.GetAsync($"/api/resources?cursor={cursor}");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(101)]
    public async Task List_WithInvalidLimit_ReturnsBadRequest(int limit)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();

        // Act
        using var response = await test.Client.GetAsync($"/api/resources?limit={limit}");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Read_WithoutAuthentication_ReturnsUnauthorized(bool list)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync(list ? "/api/resources" : test.ResourceUrl);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static async Task<Guid[]> SeedOrderedResourcesAsync(ResourceTestContext test)
    {
        test.Resource.DeletedAt = test.Clock.Now.UtcDateTime;
        test.Resource.IsActive = false;
        Guid[] ids =
        [
            Guid.Parse("019a0000-0000-7000-8000-000000000001"),
            Guid.Parse("019a0000-0000-7000-8000-000000000002"),
            Guid.Parse("019a0000-0000-7000-8000-000000000003")
        ];
        foreach (var id in ids)
        {
            test.Database.Context.ManagedResources.Add(new ManagedResource
            {
                PublicId = id,
                Name = id.ToString(),
                ResourceType = "linux",
                Environment = "dev",
                CreatedByPrincipalId = test.ActorId,
                ModifiedByPrincipalId = test.ActorId,
                CreatedAt = test.Clock.Now.UtcDateTime,
                ModifiedAt = test.Clock.Now.UtcDateTime
            });
        }

        await test.Database.Context.SaveChangesAsync();
        return ids;
    }
}
