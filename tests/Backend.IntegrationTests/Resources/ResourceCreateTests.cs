using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.Resources;
using Backend.IntegrationTests.Fixtures;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Resources;

[Collection("Cookie sessions")]
public sealed class ResourceCreateTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Create_WithValidRequest_ReturnsAddressableResource(bool isActive)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var request = new CreateResourceRequest
        {
            Name = " New target ",
            ResourceType = " linux ",
            Environment = " dev ",
            IsActive = isActive
        };

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/resources", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<ResourceResponse>();
        Assert.NotNull(result);
        Assert.Equal("New target", result.Name);
        Assert.Equal(isActive, result.IsActive);
        Assert.Equal(test.Clock.Now.UtcDateTime, result.CreatedAt);
        Assert.Equal(result.CreatedAt, result.ModifiedAt);
        Assert.NotNull(response.Headers.Location);
        Assert.EndsWith($"/api/resources/{result.Id}", response.Headers.Location.OriginalString);
        using var get = await test.Client.GetAsync(response.Headers.Location);
        get.EnsureSuccessStatusCode();
        Assert.Equal(result, await get.Content.ReadFromJsonAsync<ResourceResponse>());
    }

    [Fact]
    public async Task Create_WithValidRequest_PersistsAuditLinkedToNewResource()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var request = new CreateResourceRequest { Name = "New target", ResourceType = "linux", Environment = "dev" };

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/resources", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<ResourceResponse>();
        var saved = await test.Database.Context.ManagedResources.AsNoTracking()
            .SingleAsync(r => r.PublicId == result!.Id);
        var audit = await test.Database.Context.AuditEvents.AsNoTracking()
            .SingleAsync(e => e.EventType == "resource.created");
        Assert.True(saved.IsActive);
        Assert.Equal(test.ActorId, saved.CreatedByPrincipalId);
        Assert.Equal(saved.Id, audit.ResourceId);
        Assert.Equal(test.ActorId, audit.ActorPrincipalId);
        Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
        using var snapshot = JsonDocument.Parse(audit.ResourceSnapshot!);
        Assert.Equal(saved.PublicId, snapshot.RootElement.GetProperty("publicId").GetGuid());
        Assert.Equal(test.ActorId, snapshot.RootElement.GetProperty("createdByPrincipalId").GetInt64());
    }

    [Fact]
    public async Task Create_WhenAuditInsertFails_RollsBackResourceInsert()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_create CHECK (event_type <> 'resource.created')");
        var request = new CreateResourceRequest { Name = "New target", ResourceType = "linux", Environment = "dev" };

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/resources", request);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.False(await test.Database.Context.ManagedResources.AnyAsync(r => r.Name == "New target"));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(e => e.EventType == "resource.created"));
    }
}
