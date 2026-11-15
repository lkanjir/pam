using System.Net;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.Errors;

[Collection("Cookie sessions")]
public sealed class ApiCacheControlTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("/api/me")]
    [InlineData("/api/resources")]
    [InlineData("/api/resources?requestable=true")]
    [InlineData("/api/access-requests/mine")]
    [InlineData("/api/auth/antiforgery")]
    public async Task Get_PersonalApiResponse_DisablesCaching(string path)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();

        // Act
        using var response = await test.Client.GetAsync(path);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [Fact]
    public async Task Get_OwnRequestDetails_DisablesCaching()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        using var created = await PostAsync(test, Request(test, entitlement));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.NotNull(created.Headers.Location);

        // Act
        using var response = await test.Client.GetAsync(created.Headers.Location);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
    }
}
