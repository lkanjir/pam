using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Api.Authentication;
using Application.AccessRequests;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Backend.IntegrationTests.Sessions;
using Infrastructure.Persistence.Entities;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.AccessRequests;

[Collection(StorageCollection4.Name)]
public sealed class AccessRequestIdempotencyTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Submit_ReplayAfterResourceAndEligibilityChange_ReturnsOriginalDecision(bool eligible)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test, eligible);
        var request = Request(test, entitlement);
        using var initial = await PostAsync(test, request);
        Assert.Equal(HttpStatusCode.Created, initial.StatusCode);
        var original = await initial.Content.ReadFromJsonAsync<AccessRequestResponse>();
        Assert.NotNull(original);
        test.Resource.IsActive = false;
        test.Resource.DeletedAt = test.Clock.Now.UtcDateTime;
        await test.Database.Context.SaveChangesAsync();
        await test.Database.Context.EligibilityRules.ExecuteUpdateAsync(
            setters => setters.SetProperty(rule => rule.IsEnabled, !eligible));
        test.Clock.Now = test.Clock.Now.AddMinutes(5);
        var normalizedReplay = request with { Justification = " Deploy release ", TicketReference = " INC-1042 " };

        // Act
        using var replay = await PostAsync(test, normalizedReplay);

        // Assert
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(original, await replay.Content.ReadFromJsonAsync<AccessRequestResponse>());
        Assert.Equal(1, await test.Database.Context.AccessRequests.CountAsync());
        Assert.Equal(1, await test.Database.Context.PolicyEvaluations.CountAsync());
        Assert.Equal(2, await test.Database.Context.AuditEvents.CountAsync(item => item.RequestId != null));
    }

    [Theory]
    [InlineData("resource")]
    [InlineData("entitlement")]
    [InlineData("duration")]
    [InlineData("justification")]
    [InlineData("ticket")]
    public async Task Submit_SameKeyWithDifferentPayload_ReturnsConflictWithoutAdditionalRecords(string field)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        var request = Request(test, entitlement);
        using var first = await PostAsync(test, request);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        var changed = field switch
        {
            "resource" => request with { ResourceId = Guid.NewGuid() },
            "entitlement" => request with { EntitlementId = Guid.NewGuid() },
            "duration" => request with { RequestedDurationMinutes = 31 },
            "justification" => request with { Justification = "Different release" },
            _ => request with { TicketReference = "INC-1043" }
        };

        // Act
        using var response = await PostAsync(test, changed);

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("idempotency_conflict", json.RootElement.GetProperty("code").GetString());
        Assert.Equal(1, await test.Database.Context.AccessRequests.CountAsync());
        Assert.Equal(1, await test.Database.Context.PolicyEvaluations.CountAsync());
        Assert.Equal(2, await test.Database.Context.AuditEvents.CountAsync(item => item.RequestId != null));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Submit_ConcurrentSameKey_CommitsOnlyOneRequest(bool differentPayload)
    {
        // Arrange
        int arrivals = 0;
        var bothArrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, app =>
            app.Use(async (context, next) =>
            {
                if (context.Request.Path == "/api/access-requests")
                {
                    if (Interlocked.Increment(ref arrivals) == 2)
                    {
                        bothArrived.SetResult();
                    }

                    await bothArrived.Task.WaitAsync(TimeSpan.FromSeconds(10), context.RequestAborted);
                }

                await next(context);
            }));
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        var request = Request(test, entitlement);
        var second = differentPayload ? request with { RequestedDurationMinutes = 31 } : request;

        // Act
        var responses = await Task.WhenAll(PostAsync(test, request), PostAsync(test, second));

        // Assert
        try
        {
            var created = Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Created);
            var other = Assert.Single(responses, response => response.StatusCode != HttpStatusCode.Created);
            Assert.Equal(differentPayload ? HttpStatusCode.Conflict : HttpStatusCode.OK, other.StatusCode);
            var winner = await created.Content.ReadFromJsonAsync<AccessRequestResponse>();
            Assert.NotNull(winner);
            if (!differentPayload)
            {
                Assert.Equal(winner, await other.Content.ReadFromJsonAsync<AccessRequestResponse>());
            }

            var saved = await test.Database.Context.AccessRequests.AsNoTracking().SingleAsync();
            Assert.Equal(winner.Id, saved.PublicId);
            Assert.Equal(winner.RequestedDurationMinutes, saved.RequestedDurationMinutes);
            Assert.Equal(1, await test.Database.Context.PolicyEvaluations.CountAsync());
            Assert.Equal(2, await test.Database.Context.AuditEvents.CountAsync(item => item.RequestId == saved.Id));
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }
    }

    [Fact]
    public async Task Submit_DifferentPrincipalsWithSameKey_CreatesIndependentRequests()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        var other = new Principal { Issuer = "https://identity.example/realms/pam", Subject = "erin" };
        test.Database.Context.Principals.Add(other);
        await test.Database.Context.SaveChangesAsync();
        await test.Database.Context.Principals.Where(item => item.Id == other.Id)
            .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.IsEnabled, true));
        await SessionTestHost.AssignRolesAsync(test.Database, other.Id, "user");
        test.AddViewBinding(test.Resource, other.Id);
        await test.Database.Context.SaveChangesAsync();
        await using var server = await SessionTestHost.CreateSessionServerAsync(
            test.Database, test.Clock, other.Id.ToString(CultureInfo.InvariantCulture), redis.Connection);
        using var client = server.GetTestClient();
        using var login = await client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        SessionTestHost.UpdateCookie(client, login);
        using var csrf = await client.GetAsync("/api/auth/antiforgery");
        csrf.EnsureSuccessStatusCode();
        SessionTestHost.UpdateCookie(client, csrf);
        var tokens = await csrf.Content.ReadFromJsonAsync<AntiforgeryTokenResponse>();
        Assert.NotNull(tokens);
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", tokens.RequestToken);
        client.DefaultRequestHeaders.Add("Idempotency-Key", "submission-1");
        var request = Request(test, entitlement);
        using var first = await PostAsync(test, request);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        // Act
        using var response = await client.PostAsJsonAsync("/api/access-requests", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<AccessRequestResponse>();
        Assert.NotNull(result);
        Assert.Equal("Denied", result.State);
        var requests = await test.Database.Context.AccessRequests.AsNoTracking().ToListAsync();
        Assert.Equal(2, requests.Count);
        Assert.Equal("PendingApproval", Assert.Single(requests, item => item.RequesterPrincipalId == test.ActorId).State);
        Assert.Equal(result.Id, Assert.Single(requests, item => item.RequesterPrincipalId == other.Id).PublicId);
    }

    [Fact]
    public async Task Submit_RetryAfterFailedTransaction_CanReuseIdempotencyKey()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        var request = Request(test, entitlement);
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_submission CHECK (event_type <> 'policy.evaluated')");
        using var failed = await PostAsync(test, request);
        Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
        await test.Database.Context.Database.ExecuteSqlRawAsync("ALTER TABLE audit_events DROP CONSTRAINT reject_submission");

        // Act
        using var retry = await PostAsync(test, request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, retry.StatusCode);
        Assert.Equal(1, await test.Database.Context.AccessRequests.CountAsync());
        Assert.Equal(1, await test.Database.Context.PolicyEvaluations.CountAsync());
        Assert.Equal(2, await test.Database.Context.AuditEvents.CountAsync(item => item.RequestId != null));
    }
}
