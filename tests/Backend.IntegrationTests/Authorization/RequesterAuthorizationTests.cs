using System.Net;
using System.Net.Http.Json;
using Application.AccessRequests;
using Application.Common.Pagination;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class RequesterAuthorizationTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("user", 200)]
    [InlineData("admin,user", 200)]
    [InlineData("approver,user", 200)]
    [InlineData("admin", 403)]
    [InlineData("approver", 403)]
    [InlineData("User", 403)]
    [InlineData("", 403)]
    public async Task ListMine_OwnedRequest_RequiresRequesterPermissionDespiteOtherRoles(string roles, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection,
            roles: roles.Split(',', StringSplitOptions.RemoveEmptyEntries));
        var entitlement = await SeedEntitlementAsync(test);
        var request = AddRequest(test, entitlement, Guid.NewGuid());
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync("/api/access-requests/mine");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        if (status == 200)
        {
            var page = await response.Content.ReadFromJsonAsync<CursorPage<AccessRequestSummaryResponse>>();
            Assert.NotNull(page);
            Assert.Equal(request.PublicId, Assert.Single(page.Items).Id);
        }
        else
        {
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.DoesNotContain(request.PublicId.ToString(), await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }
}
