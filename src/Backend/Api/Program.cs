using Api;
using Api.Authentication;
using Api.Filters;
using Infrastructure;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);

builder.Services.AddInfrastructure(builder.Configuration);
builder.Services.AddSingleton<ITicketStore, RedisTicketStore>();
builder.Services.AddKeycloak(builder.Configuration);
builder.Services.AddPamAuthentication(builder.Environment);
builder.Services.AddPamAntiforgery(builder.Environment);
builder.Services.AddOpenApi();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") });

var api = app.MapGroup("/api").RequireAuthorization().AddEndpointFilter<AntiforgeryFilter>();
api.MapAuthenticationEndpoints();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.Run();