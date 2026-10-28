using System.Net;
using System.Text.Json;
using Api.Errors;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;

namespace Backend.IntegrationTests.Errors;

public sealed class ErrorHandlingTests
{
    [Theory]
    [InlineData("Development", "text/html")]
    [InlineData("Production", "application/json")]
    [InlineData("Development", "application/xml")]
    public async Task Exception_ReturnsSafeProblemDetails(string environment, string accept)
    {
        // Arrange
        await using var app = await CreateAppAsync(environment);
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Accept.ParseAdd(accept);

        // Act
        using var response = await client.GetAsync("/throw");
        var body = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(body);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.False(document.RootElement.TryGetProperty("code", out _));
        Assert.DoesNotContain("secret-sentinel", body);
        Assert.DoesNotContain("stackTrace", body);
    }

    [Theory]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(405)]
    public async Task EmptyErrorResponse_UsesSharedContract(int status)
    {
        // Arrange
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // Act
        using var response = await client.GetAsync($"/status/{status}");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        // Assert
        Assert.Equal(status, body.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task ProblemResponse_UsesRequestCorrelationId()
    {
        // Arrange
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // Act
        using var response = await client.GetAsync("/throw");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        // Assert
        Assert.Equal("test-correlation", body.RootElement.GetProperty("correlationId").GetString());
    }

    [Fact]
    public async Task ProblemResponse_DisablesCaching()
    {
        // Arrange
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // Act
        using var response = await client.GetAsync("/explicit");

        // Assert
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [Fact]
    public async Task ExplicitProblem_PreservesSpecificErrorCode()
    {
        // Arrange
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // Act
        using var response = await client.GetAsync("/explicit");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        // Assert
        Assert.Equal("invalid_antiforgery_token", body.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task SuccessfulResponse_IsNotReplaced()
    {
        // Arrange
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // Act
        using var response = await client.GetAsync("/success");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ValidationProblem_PreservesFieldErrors()
    {
        // Arrange
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // Act
        using var response = await client.GetAsync("/validation");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        // Assert
        Assert.Equal("Required.", body.RootElement.GetProperty("errors").GetProperty("name")[0].GetString());
    }

    [Fact]
    public async Task UnknownRoute_ReturnsNotFoundProblem()
    {
        // Arrange
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // Act
        using var response = await client.GetAsync("/missing");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(404, body.RootElement.GetProperty("status").GetInt32());
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public async Task MalformedJson_ReturnsBadRequest(string environment)
    {
        // Arrange
        await using var app = await CreateAppAsync(environment);
        using var client = app.GetTestClient();
        using var content = new StringContent("{broken", System.Text.Encoding.UTF8, "application/json");

        // Act
        using var response = await client.PostAsync("/body", content);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(400, body.RootElement.GetProperty("status").GetInt32());
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public async Task InvalidQueryParameter_ReturnsBadRequest(string environment)
    {
        // Arrange
        await using var app = await CreateAppAsync(environment);
        using var client = app.GetTestClient();

        // Act
        using var response = await client.GetAsync("/query?count=abc");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task BadHttpRequestException_PreservesFrameworkStatus()
    {
        // Arrange
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // Act
        using var response = await client.GetAsync("/bad-request");
        var body = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.DoesNotContain("secret-sentinel", body);
    }

    [Theory]
    [InlineData("postgres")]
    [InlineData("redis")]
    public async Task DependencyFailure_ReturnsGenericInternalError(string dependency)
    {
        // Arrange
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // Act
        using var response = await client.GetAsync("/dependency/" + dependency);
        var body = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(body);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal(500, json.RootElement.GetProperty("status").GetInt32());
        Assert.DoesNotContain("secret-sentinel", body);
    }

    public sealed record TestRequest(string Name);

    private static async Task<WebApplication> CreateAppAsync(string environment = "Development")
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment });
        builder.WebHost.UseTestServer();
        builder.Services.AddPamErrorHandling();
        var app = builder.Build();
        app.UsePamErrorHandling();
        app.Use(async (context, next) =>
        {
            context.TraceIdentifier = "test-correlation";
            await next(context);
        });
        app.MapGet("/throw", (Func<IResult>)(() => throw new InvalidOperationException("secret-sentinel")));
        app.MapGet("/dependency/{dependency}", (string dependency) =>
            ThrowDependencyFailure(dependency));
        app.MapGet("/status/{status:int}", (int status) => Results.StatusCode(status));
        app.MapGet("/explicit", () => Results.Problem(statusCode: 400,
            extensions: new Dictionary<string, object?> { ["code"] = "invalid_antiforgery_token" }));
        app.MapGet("/validation", () => Results.ValidationProblem(
            new Dictionary<string, string[]> { ["name"] = ["Required."] }));
        app.MapPost("/body", (TestRequest request) => Results.Ok(request));
        app.MapGet("/query", (int count) => Results.Ok(count));
        app.MapGet("/bad-request", (Func<IResult>)(() =>
            throw new BadHttpRequestException("secret-sentinel", 413)));
        app.MapGet("/success", () => Results.NoContent());
        await app.StartAsync();
        return app;
    }
    private static IResult ThrowDependencyFailure(string dependency) => throw (dependency switch
    {
        "postgres" => new Npgsql.NpgsqlException("secret-sentinel"),
        "redis" => new StackExchange.Redis.RedisConnectionException(
            StackExchange.Redis.ConnectionFailureType.SocketFailure, StackExchange.Redis.CommandFlags.None, "secret-sentinel"),
        _ => new InvalidOperationException("Unexpected test dependency")
    });

}
