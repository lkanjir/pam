using System.Net;
using System.Text.Json;
using Backend.IntegrationTests.Fixtures;

namespace Backend.IntegrationTests.Resources;

[Collection("Cookie sessions")]
public sealed class ResourceConcurrencyTests(PostgresFixture postgres, RedisFixture redis)
{
    [Fact]
    public async Task Get_ResourceChanged_ReturnsNewStrongEtagWithoutExposingStorageVersion()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        using var first = await test.Client.GetAsync(test.ResourceUrl);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.NotNull(first.Headers.ETag);
        test.Resource.Name = "Changed target";
        await test.Database.Context.SaveChangesAsync();

        // Act
        using var response = await test.Client.GetAsync(test.ResourceUrl);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        Assert.False(response.Headers.ETag.IsWeak);
        Assert.NotEqual(first.Headers.ETag.Tag, response.Headers.ETag.Tag);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Changed target", json.RootElement.GetProperty("name").GetString());
        Assert.False(json.RootElement.TryGetProperty("version", out _));
    }
}
