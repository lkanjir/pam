using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.Common.Pagination;
using Application.Resources;
using Backend.IntegrationTests.Fixtures;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Resources;

[Collection("Cookie sessions")]
public sealed class ResourceDeleteTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Delete_WithValidRequest_SoftDeletesResource(bool initiallyActive)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        test.Resource.IsActive = initiallyActive;
        await test.Database.Context.SaveChangesAsync();
        test.Clock.Now = test.Clock.Now.AddMinutes(5);

        // Act
        using var response = await test.Client.DeleteAsync(test.ResourceUrl);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
        var saved = await test.ReadResourceAsync();
        Assert.Equal(test.Clock.Now.UtcDateTime, saved.DeletedAt);
        Assert.Equal(saved.DeletedAt, saved.ModifiedAt);
        Assert.Equal(test.ActorId, saved.ModifiedByPrincipalId);
        Assert.False(saved.IsActive);
        Assert.Equal(test.Resource.PublicId, saved.PublicId);
        Assert.Equal(test.Resource.Name, saved.Name);
        Assert.Equal(test.Resource.CreatedAt, saved.CreatedAt);
        Assert.Equal(test.Resource.CreatedByPrincipalId, saved.CreatedByPrincipalId);
    }

    [Fact]
    public async Task Delete_WithValidRequest_PersistsActorAndDeletedResourceSnapshot()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();

        // Act
        using var response = await test.Client.DeleteAsync(test.ResourceUrl);

        // Assert
        response.EnsureSuccessStatusCode();
        var audit = await test.Database.Context.AuditEvents.AsNoTracking()
            .SingleAsync(e => e.EventType == "resource.deleted");
        Assert.Equal(test.ActorId, audit.ActorPrincipalId);
        Assert.Equal(test.Resource.Id, audit.ResourceId);
        Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
        Assert.Equal(test.Clock.Now.UtcDateTime, audit.OccurredAt);
        Assert.Equal("success", audit.Outcome);
        using var actor = JsonDocument.Parse(audit.ActorSnapshot!);
        Assert.Equal(test.ActorId, actor.RootElement.GetProperty("id").GetInt64());
        using var snapshot = JsonDocument.Parse(audit.ResourceSnapshot!);
        Assert.Equal(test.Resource.PublicId, snapshot.RootElement.GetProperty("publicId").GetGuid());
        Assert.Equal(test.Resource.Name, snapshot.RootElement.GetProperty("name").GetString());
        Assert.False(snapshot.RootElement.GetProperty("isActive").GetBoolean());
        Assert.Equal(test.Clock.Now.UtcDateTime, snapshot.RootElement.GetProperty("deletedAt").GetDateTime());
        Assert.Equal(test.Clock.Now.UtcDateTime, snapshot.RootElement.GetProperty("modifiedAt").GetDateTime());
    }

    [Fact]
    public async Task Delete_WithExistingEntitlement_PreservesEntitlement()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = new Entitlement
        {
            ResourceId = test.Resource.Id,
            Code = "linux.admin",
            Name = "Linux administrator",
            MaxDurationMinutes = 60,
            IsActive = true
        };
        test.Database.Context.Entitlements.Add(entitlement);
        await test.Database.Context.SaveChangesAsync();

        // Act
        using var response = await test.Client.DeleteAsync(test.ResourceUrl);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(await test.Database.Context.Entitlements.AsNoTracking()
            .AnyAsync(e => e.Id == entitlement.Id && e.ResourceId == test.Resource.Id));
    }

    [Fact]
    public async Task Delete_WhenResourceDoesNotExist_ReturnsNotFoundWithoutAudit()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();

        // Act
        using var response = await test.Client.DeleteAsync($"/api/resources/{Guid.CreateVersion7()}");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Null((await test.ReadResourceAsync()).DeletedAt);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.deleted"));
    }

    [Fact]
    public async Task Delete_WhenRepeated_PreservesOriginalDeletionWithoutDuplicateAudit()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        using var first = await test.Client.DeleteAsync(test.ResourceUrl);
        first.EnsureSuccessStatusCode();
        var deletedAt = test.Clock.Now.UtcDateTime;
        test.Clock.Now = test.Clock.Now.AddMinutes(1);

        // Act
        using var response = await test.Client.DeleteAsync(test.ResourceUrl);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(deletedAt, (await test.ReadResourceAsync()).DeletedAt);
        Assert.Equal(1, await test.CountAuditEventsAsync("resource.deleted"));
    }

    [Fact]
    public async Task Delete_WithoutAuthentication_LeavesResourceUnchanged()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.DeleteAsync(test.ResourceUrl);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null((await test.ReadResourceAsync()).DeletedAt);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.deleted"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid-token")]
    public async Task Delete_WithoutValidAntiforgeryToken_LeavesResourceUnchanged(string? token)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        test.Client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        if (token is not null)
        {
            test.Client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", token);
        }

        // Act
        using var response = await test.Client.DeleteAsync(test.ResourceUrl);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null((await test.ReadResourceAsync()).DeletedAt);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.deleted"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Read_WhenResourceDeleted_ExcludesResource(bool list)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        using var deletion = await test.Client.DeleteAsync(test.ResourceUrl);
        deletion.EnsureSuccessStatusCode();

        // Act
        using var response = await test.Client.GetAsync(list ? "/api/resources" : test.ResourceUrl);

        // Assert
        if (list)
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var page = await response.Content.ReadFromJsonAsync<CursorPage<ResourceResponse>>();
            Assert.NotNull(page);
            Assert.Empty(page.Items);
            Assert.Null(page.NextCursor);
        }
        else
        {
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
    }

    [Fact]
    public async Task Update_WhenResourceDeleted_DoesNotRestoreResource()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        using var deletion = await test.Client.DeleteAsync(test.ResourceUrl);
        deletion.EnsureSuccessStatusCode();
        var request = new UpdateResourceRequest
        {
            Name = "Restored target",
            ResourceType = "linux",
            Environment = "dev",
            IsActive = true
        };

        // Act
        using var response = await test.Client.PutAsJsonAsync(test.ResourceUrl, request);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var saved = await test.ReadResourceAsync();
        Assert.NotNull(saved.DeletedAt);
        Assert.False(saved.IsActive);
        Assert.Equal(test.Resource.Name, saved.Name);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.updated"));
    }

    [Fact]
    public async Task Delete_WhenAuditInsertFails_RollsBackSoftDeletion()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_delete CHECK (event_type <> 'resource.deleted')");

        // Act
        using var response = await test.Client.DeleteAsync(test.ResourceUrl);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var saved = await test.ReadResourceAsync();
        Assert.Null(saved.DeletedAt);
        Assert.True(saved.IsActive);
        Assert.Equal(test.Resource.ModifiedAt, saved.ModifiedAt);
        Assert.Equal(test.Resource.ModifiedByPrincipalId, saved.ModifiedByPrincipalId);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.deleted"));
    }
}
