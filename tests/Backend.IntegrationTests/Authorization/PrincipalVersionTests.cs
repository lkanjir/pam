using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.Principals;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class PrincipalVersionTests(PostgresFixture postgres, RedisFixture redis)
{
    [Fact]
    public async Task Get_ChangedMapping_ChangesStrongEtagWithoutExposingStorageVersion()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        Guid principalId = await test.Database.Context.Principals.Where(principal => principal.Subject == "ivan")
            .Select(principal => principal.PublicId).SingleAsync();
        string url = $"/api/principals/{principalId}";
        using var original = await test.Client.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        Assert.NotNull(original.Headers.ETag);
        await test.Database.Context.Principals.Where(principal => principal.PublicId == principalId)
            .ExecuteUpdateAsync(update => update.SetProperty(principal => principal.ModifiedAt, test.Clock.Now.UtcDateTime));

        // Act
        using var response = await test.Client.GetAsync(url);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        Assert.False(response.Headers.ETag.IsWeak);
        Assert.NotEqual(original.Headers.ETag.Tag, response.Headers.ETag.Tag);
        var principal = await response.Content.ReadFromJsonAsync<PrincipalResponse>();
        Assert.NotNull(principal);
        Assert.Equal(principalId, principal.Id);
        Assert.Equal(test.Clock.Now, principal.ModifiedAt);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(json.RootElement.TryGetProperty("version", out _));
        Assert.False(json.RootElement.TryGetProperty("xmin", out _));
    }

    [Theory]
    [InlineData("admin", false, 404)]
    [InlineData("user", true, 403)]
    public async Task Get_UnavailableMapping_EmitsNoConcurrencyToken(string role, bool exists, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: [role]);
        await test.AuthenticateAsync(includeResourceVersion: false);
        Guid principalId = exists ? await test.Database.Context.Principals.Where(principal => principal.Subject == "ivan")
            .Select(principal => principal.PublicId).SingleAsync() : Guid.NewGuid();

        // Act
        using var response = await test.Client.GetAsync($"/api/principals/{principalId}");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Null(response.Headers.ETag);
    }
}
