using System.Net;
using Api.Authorization;
using Application.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Backend.IntegrationTests.Authorization;

public sealed class EndpointInventoryTests
{
    [Fact]
    public async Task Start_BusinessPolicyWithoutBootstrapBoundary_RejectsBeforeServing()
    {
        // Arrange
        await using var app = Create();
        app.Services.GetRequiredService<IOptions<AuthorizationOptions>>().Value.AddPolicy(PamPermissions.ResourcesReadAll,
            new AuthorizationPolicyBuilder().RequireAuthenticatedUser().RequireRole("admin").Build());
        app.MapGet("/api/unsafe", () => TypedResults.Ok()).RequireAuthorization(PamPermissions.ResourcesReadAll);

        // Act / Assert
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => app.StartAsync());
        Assert.Contains("bootstrap boundary", error.Message, StringComparison.Ordinal);
        Assert.Contains("/api/unsafe", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("unclassified")]
    [InlineData("authenticated-only")]
    [InlineData("unknown-policy")]
    [InlineData("missing-recent-auth")]
    [InlineData("only-recent-auth")]
    [InlineData("public-business-policy")]
    [InlineData("unknown-conditional-policy")]
    public async Task Start_EndpointWithoutCompleteAuthorization_RejectsBeforeServing(string defect)
    {
        // Arrange
        await using var app = Create();
        var endpoint = app.MapGet("/api/unsafe", () => TypedResults.Ok("must-not-serve"));
        switch (defect)
        {
            case "authenticated-only":
                endpoint.RequireAuthorization();
                break;
            case "unknown-policy":
                endpoint.RequireAuthorization("unregistered.permission");
                break;
            case "missing-recent-auth":
                endpoint.RequireAuthorization(PamPermissions.ResourcesManage);
                break;
            case "only-recent-auth":
                endpoint.RequireAuthorization(PamPolicies.RecentAuthentication);
                break;
            case "public-business-policy":
                endpoint.RequireAuthorization(PamPermissions.ResourcesReadAll).AllowAnonymous();
                break;
            case "unknown-conditional-policy":
                endpoint.RequireAuthorization().WithMetadata(new PamConditionalPermissionMetadata("unregistered.permission"));
                break;
        }

        // Act / Assert
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => app.StartAsync());
        Assert.Contains("/api/unsafe", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("permission")]
    [InlineData("conditional")]
    [InlineData("sensitive")]
    [InlineData("session")]
    [InlineData("public")]
    public async Task Start_ExplicitClassification_PreservesFrameworkEnforcement(string classification)
    {
        // Arrange
        await using var app = Create();
        var endpoint = app.MapGet("/api/classified", () => TypedResults.Ok("public-value"));
        switch (classification)
        {
            case "permission":
                endpoint.RequireAuthorization(PamPermissions.ResourcesReadAll);
                break;
            case "conditional":
                endpoint.RequireAuthorization().WithMetadata(new PamConditionalPermissionMetadata(PamPermissions.RequestsCreate));
                break;
            case "sensitive":
                endpoint.RequireAuthorization(PamPermissions.ResourcesManage, PamPolicies.RecentAuthentication);
                break;
            case "session":
                endpoint.RequireAuthorization().WithMetadata(new PamSessionEndpointMetadata());
                break;
            case "public":
                endpoint.AllowAnonymous();
                break;
        }

        // Act
        await app.StartAsync();
        using var client = app.GetTestClient();
        using var response = await client.GetAsync("/api/classified");

        // Assert
        Assert.Equal(classification == "public" ? HttpStatusCode.OK : HttpStatusCode.Unauthorized, response.StatusCode);
        if (classification == "public")
        {
            Assert.Equal("\"public-value\"", await response.Content.ReadAsStringAsync());
        }
        else
        {
            Assert.DoesNotContain("public-value", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    private static WebApplication Create()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddPamAuthorization();
        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options => options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            });
        return builder.Build();
    }
}
