using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.Resources;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Infrastructure.Resources;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Backend.IntegrationTests.Resources;

[Collection("Cookie sessions")]
public sealed class ResourceConcurrencyTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData(null, 428)]
    [InlineData("broken", 400)]
    [InlineData("*", 400)]
    [InlineData("W/\"00000001\"", 400)]
    [InlineData("\"00000000\"", 400)]
    [InlineData("\"00000001\",\"00000002\"", 400)]
    public async Task Update_MissingOrInvalidPrecondition_RejectsWithoutChanges(string? tag, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        test.Client.DefaultRequestHeaders.Remove("If-Match");
        if (tag is not null)
        {
            test.Client.DefaultRequestHeaders.TryAddWithoutValidation("If-Match", tag);
        }

        // Act
        using var response = await test.Client.PutAsJsonAsync(test.ResourceUrl, Payload("New target"));

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("Original target", (await test.ReadResourceAsync()).Name);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.updated"));
    }

    [Fact]
    public async Task Update_StaleVersion_PreservesTheOtherWritersChanges()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        test.Resource.Name = "Other writer";
        await test.Database.Context.SaveChangesAsync();

        // Act
        using var response = await test.Client.PutAsJsonAsync(test.ResourceUrl, Payload("Overwritten"));

        // Assert
        Assert.Equal(HttpStatusCode.PreconditionFailed, response.StatusCode);
        Assert.Equal("Other writer", (await test.ReadResourceAsync()).Name);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.updated"));
    }

    [Fact]
    public async Task Update_CurrentVersion_ReturnsNewEtagAndRejectsReuse()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        string original = Assert.Single(test.Client.DefaultRequestHeaders.IfMatch).Tag;

        // Act
        using var updated = await test.Client.PutAsJsonAsync(test.ResourceUrl, Payload("Updated target"));
        using var stale = await test.Client.PutAsJsonAsync(test.ResourceUrl, Payload("Should not replace"));

        // Assert
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        Assert.NotNull(updated.Headers.ETag);
        Assert.NotEqual(original, updated.Headers.ETag.Tag);
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
        Assert.Equal("Updated target", (await test.ReadResourceAsync()).Name);
        Assert.Equal(1, await test.CountAuditEventsAsync("resource.updated"));
    }

    [Fact]
    public async Task Update_ConcurrentWritersAfterReading_RollsBackLosingAuditAndPreventsMixedSnapshots()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var gate = new SaveGate();
        var options = new DbContextOptionsBuilder<PamDbContext>()
            .UseNpgsql(test.Database.Context.Database.GetConnectionString()).UseSnakeCaseNamingConvention()
            .AddInterceptors(gate).Options;
        await using var firstContext = new PamDbContext(options);
        await using var secondContext = new PamDbContext(options);
        var principal = await test.Database.Context.Principals.SingleAsync(item => item.Id == test.ActorId);
        var actor = new PrincipalSnapshot(principal.Id, principal.PublicId, principal.DisplayName, principal.Issuer, principal.Subject);
        var first = new ResourceService(firstContext, test.Clock);
        var second = new ResourceService(secondContext, test.Clock);
        var rename = Payload("Renamed target") with { Description = "Original description" };
        var describe = Payload("Original target") with { Description = "Other description" };

        // Act
        var results = await Task.WhenAll(
            first.UpdateAsync(test.Resource.PublicId, rename, actor, "rename", test.Resource.Version),
            second.UpdateAsync(test.Resource.PublicId, describe, actor, "describe", test.Resource.Version));

        // Assert
        var winner = Assert.Single(results, item => item.Kind == ResourceWriteKind.Succeeded);
        Assert.Single(results, item => item.Kind == ResourceWriteKind.Conflict);
        Assert.NotNull(winner.Resource);
        var saved = await test.ReadResourceAsync();
        Assert.Equal(winner.Resource.Name, saved.Name);
        Assert.Equal(winner.Resource.Description, saved.Description);
        var audit = await test.Database.Context.AuditEvents.SingleAsync(item => item.EventType == "resource.updated");
        using var snapshot = JsonDocument.Parse(audit.ResourceSnapshot!);
        Assert.Equal(saved.Name, snapshot.RootElement.GetProperty("name").GetString());
        Assert.Equal(saved.Description, snapshot.RootElement.GetProperty("description").GetString());
    }

    [Fact]
    public async Task Update_OpenApi_RequiresIfMatchAndDocumentsPreconditionResponses()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/resources/{id}").GetProperty("put");
        var header = Assert.Single(operation.GetProperty("parameters").EnumerateArray(),
            item => item.GetProperty("name").GetString() == "If-Match");
        Assert.Equal("header", header.GetProperty("in").GetString());
        Assert.True(header.GetProperty("required").GetBoolean());
        Assert.True(operation.GetProperty("responses").TryGetProperty("412", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("428", out _));
    }

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

    private static UpdateResourceRequest Payload(string name) => new()
    {
        Name = name,
        Description = "Updated description",
        ResourceType = "linux",
        Environment = "dev",
        IsActive = true
    };

    private sealed class SaveGate : SaveChangesInterceptor
    {
        private readonly TaskCompletionSource _both = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _arrivals;

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (eventData.Context?.ChangeTracker.Entries<ManagedResource>().Any(item => item.State == EntityState.Modified) == true)
            {
                if (Interlocked.Increment(ref _arrivals) == 2)
                {
                    _both.TrySetResult();
                }

                await _both.Task.WaitAsync(TimeSpan.FromSeconds(20), cancellationToken);
            }

            return result;
        }
    }
}
