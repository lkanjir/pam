using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Application.Resources;
using Backend.IntegrationTests.Fixtures;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Resources;

[Collection("Cookie sessions")]
public sealed class ResourceUpdateTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Update_WithValidRequest_ReplacesEditableFields(bool isActive)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var request = ValidRequest();
        request["isActive"] = isActive;
        test.Clock.Now = test.Clock.Now.AddMinutes(5);

        // Act
        using var response = await test.Client.PutAsJsonAsync(test.ResourceUrl, request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<ResourceResponse>();
        var saved = await test.ReadResourceAsync();
        Assert.Equal(new ResourceResponse(
            test.Resource.PublicId, "Updated target", "Updated description", "linux-server", "prod",
            isActive, test.Resource.CreatedAt, test.Clock.Now.UtcDateTime), result);
        Assert.Equal(result, new ResourceResponse(
            saved.PublicId, saved.Name, saved.Description, saved.ResourceType, saved.Environment,
            saved.IsActive, saved.CreatedAt, saved.ModifiedAt));
        Assert.Equal(test.Resource.CreatedByPrincipalId, saved.CreatedByPrincipalId);
        Assert.Equal(test.ActorId, saved.ModifiedByPrincipalId);
        Assert.Null(saved.DeletedAt);
    }

    [Fact]
    public async Task Update_WithoutDescription_ClearsPreviousDescription()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var request = ValidRequest();
        request.Remove("description");

        // Act
        using var response = await test.Client.PutAsJsonAsync(test.ResourceUrl, request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null((await test.ReadResourceAsync()).Description);
    }

    [Fact]
    public async Task Update_WithValidRequest_PersistsActorAndResourceAuditSnapshot()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();

        // Act
        using var response = await test.Client.PutAsJsonAsync(test.ResourceUrl, ValidRequest());

        // Assert
        response.EnsureSuccessStatusCode();
        var audit = await test.Database.Context.AuditEvents.AsNoTracking()
            .SingleAsync(e => e.EventType == "resource.updated");
        Assert.Equal(test.ActorId, audit.ActorPrincipalId);
        Assert.Equal(test.Resource.Id, audit.ResourceId);
        Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
        Assert.Equal(test.Clock.Now.UtcDateTime, audit.OccurredAt);
        Assert.Equal("success", audit.Outcome);
        using var actor = JsonDocument.Parse(audit.ActorSnapshot!);
        Assert.Equal(test.ActorId, actor.RootElement.GetProperty("id").GetInt64());
        using var snapshot = JsonDocument.Parse(audit.ResourceSnapshot!);
        Assert.Equal(test.Resource.PublicId, snapshot.RootElement.GetProperty("publicId").GetGuid());
        Assert.Equal("Updated target", snapshot.RootElement.GetProperty("name").GetString());
        Assert.False(snapshot.RootElement.GetProperty("isActive").GetBoolean());
        Assert.Equal(test.ActorId, snapshot.RootElement.GetProperty("modifiedByPrincipalId").GetInt64());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Update_WhenResourceUnavailable_ReturnsNotFoundWithoutAudit(bool deleted)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        if (deleted)
        {
            test.Resource.DeletedAt = test.Clock.Now.UtcDateTime;
            test.Resource.IsActive = false;
            await test.Database.Context.SaveChangesAsync();
        }
        string url = deleted ? test.ResourceUrl : $"/api/resources/{Guid.CreateVersion7()}";

        // Act
        using var response = await test.Client.PutAsJsonAsync(url, ValidRequest());

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("Original target", (await test.ReadResourceAsync()).Name);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.updated"));
    }

    [Fact]
    public async Task Update_WithoutAuthentication_LeavesResourceUnchanged()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.PutAsJsonAsync(test.ResourceUrl, ValidRequest());

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Original target", (await test.ReadResourceAsync()).Name);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.updated"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid-token")]
    public async Task Update_WithoutValidAntiforgeryToken_LeavesResourceUnchanged(string? token)
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
        using var response = await test.Client.PutAsJsonAsync(test.ResourceUrl, ValidRequest());

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("Original target", (await test.ReadResourceAsync()).Name);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.updated"));
    }

    [Theory]
    [MemberData(nameof(InvalidFields))]
    public async Task Update_WithInvalidFields_ReturnsValidationProblem(string field, string? value)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var request = ValidRequest();
        request[field] = value;

        // Act
        using var response = await test.Client.PutAsJsonAsync(test.ResourceUrl, request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        string propertyName = char.ToUpperInvariant(field[0]) + field[1..];
        Assert.True(problem.RootElement.GetProperty("errors").TryGetProperty(propertyName, out _));
        Assert.Equal(ResourceTestContext.CorrelationId,
            problem.RootElement.GetProperty("correlationId").GetString());
        Assert.Equal("Original target", (await test.ReadResourceAsync()).Name);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.updated"));
    }

    [Theory]
    [InlineData("name")]
    [InlineData("resourceType")]
    [InlineData("environment")]
    [InlineData("isActive")]
    public async Task Update_WithMissingRequiredField_LeavesResourceUnchanged(string field)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var request = ValidRequest();
        request.Remove(field);

        // Act
        using var response = await test.Client.PutAsJsonAsync(test.ResourceUrl, request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("Original target", (await test.ReadResourceAsync()).Name);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.updated"));
    }

    [Fact]
    public async Task Update_WithMalformedJson_LeavesResourceUnchanged()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        using var body = new StringContent("{", Encoding.UTF8, "application/json");

        // Act
        using var response = await test.Client.PutAsync(test.ResourceUrl, body);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("Original target", (await test.ReadResourceAsync()).Name);
    }

    [Fact]
    public async Task Update_WhenAuditInsertFails_RollsBackResourceUpdate()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_update CHECK (event_type <> 'resource.updated')");

        // Act
        using var response = await test.Client.PutAsJsonAsync(test.ResourceUrl, ValidRequest());

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var saved = await test.ReadResourceAsync();
        Assert.Equal(test.Resource.Name, saved.Name);
        Assert.Equal(test.Resource.Description, saved.Description);
        Assert.Equal(test.Resource.IsActive, saved.IsActive);
        Assert.Equal(test.Resource.ModifiedAt, saved.ModifiedAt);
        Assert.Equal(test.Resource.ModifiedByPrincipalId, saved.ModifiedByPrincipalId);
        Assert.Equal(0, await test.CountAuditEventsAsync("resource.updated"));
    }

    public static IEnumerable<object?[]> InvalidFields()
    {
        yield return ["name", null];
        yield return ["name", ""];
        yield return ["name", "   "];
        yield return ["name", new string('a', 201)];
        yield return ["description", new string('a', 2001)];
        yield return ["resourceType", "   "];
        yield return ["resourceType", new string('a', 51)];
        yield return ["environment", "   "];
        yield return ["environment", new string('a', 51)];
    }

    private static Dictionary<string, object?> ValidRequest() => new()
    {
        ["name"] = " Updated target ",
        ["description"] = " Updated description ",
        ["resourceType"] = " linux-server ",
        ["environment"] = " prod ",
        ["isActive"] = false
    };
}
