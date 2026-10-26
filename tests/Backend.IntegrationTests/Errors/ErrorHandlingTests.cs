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
        Assert.Equal("internal_error", document.RootElement.GetProperty("code").GetString());
        Assert.DoesNotContain("secret-sentinel", body);
        Assert.DoesNotContain("stackTrace", body);
    }

    [Theory]
    [InlineData(400, "bad_request")]
    [InlineData(401, "authentication_required")]
    [InlineData(403, "access_denied")]
    [InlineData(404, "not_found")]
    [InlineData(405, "method_not_allowed")]
    public async Task EmptyErrorResponse_UsesSharedContract(int status, string code)
    {
        // Arrange
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // Act
        using var response = await client.GetAsync($"/status/{status}");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        // Assert
        Assert.Equal(status, body.RootElement.GetProperty("status").GetInt32());
        Assert.Equal(code, body.RootElement.GetProperty("code").GetString());
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
        Assert.Equal("not_found", body.RootElement.GetProperty("code").GetString());
    }

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
        app.MapGet("/status/{status:int}", (int status) => Results.StatusCode(status));
        app.MapGet("/explicit", () => Results.Problem(statusCode: 400,
            extensions: new Dictionary<string, object?> { ["code"] = "invalid_antiforgery_token" }));
        app.MapGet("/validation", () => Results.ValidationProblem(
            new Dictionary<string, string[]> { ["name"] = ["Required."] }));
        app.MapGet("/success", () => Results.NoContent());
        await app.StartAsync();
        return app;
    }
}
