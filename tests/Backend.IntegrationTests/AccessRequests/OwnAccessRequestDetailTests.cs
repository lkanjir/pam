using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.AccessRequests;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.AccessRequests;

[Collection(StorageCollection2.Name)]
public sealed class OwnAccessRequestDetailTests(PostgresFixture postgres, RedisFixture redis)
{
    private static readonly string[] PrivateFields =
        ["requesterPrincipalId", "idempotencyKey", "payloadHash", "inputSnapshot", "actorSnapshot", "metadata", "sessionIdHash"];

    [Theory]
    [InlineData(true, "PendingApproval", "approval_required", "success")]
    [InlineData(false, "Denied", "not_eligible", "denied")]
    public async Task GetMine_SubmissionLocation_ReturnsSavedRequestPolicyAndAudit(
        bool eligible, string state, string reason, string outcome)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test, eligibility: eligible);
        using var submitted = await PostAsync(test, Request(test, entitlement));
        Assert.Equal(HttpStatusCode.Created, submitted.StatusCode);
        Assert.NotNull(submitted.Headers.Location);
        var original = await submitted.Content.ReadFromJsonAsync<AccessRequestResponse>();
        Assert.NotNull(original);
        test.Client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        int auditCount = await test.Database.Context.AuditEvents.CountAsync();
        var auditIds = await test.Database.Context.AuditEvents.Where(item => item.RequestId != null)
            .ToDictionaryAsync(item => item.EventType, item => item.PublicId);

        // Act
        var detail = await test.Client.GetFromJsonAsync<AccessRequestDetailsResponse>(submitted.Headers.Location);

        // Assert
        Assert.NotNull(detail);
        Assert.Equal(original.Id, detail.Id);
        Assert.Equal(test.Resource.PublicId, detail.ResourceId);
        Assert.Equal("Original target", detail.ResourceName);
        Assert.Equal(entitlement.PublicId, detail.EntitlementId);
        Assert.Equal("Temporary Linux administrator", detail.EntitlementName);
        Assert.Equal(30, detail.RequestedDurationMinutes);
        Assert.Equal("Deploy release", detail.Justification);
        Assert.Equal("INC-1042", detail.TicketReference);
        Assert.Equal(state, detail.State);
        Assert.Equal(test.Clock.Now, detail.CreatedAt);
        Assert.Equal(original.PolicyEvaluation, detail.PolicyEvaluation);
        Assert.Equal(reason, detail.PolicyEvaluation.ReasonCode);
        Assert.Collection(detail.AuditEvents,
            created => Assert.Equal(new AccessRequestAuditEventResponse(
                auditIds["access_request.created"], "access_request.created", test.Clock.Now, outcome, reason), created),
            evaluated => Assert.Equal(new AccessRequestAuditEventResponse(
                auditIds["policy.evaluated"], "policy.evaluated", test.Clock.Now, outcome, reason), evaluated));
        Assert.Equal(auditCount, await test.Database.Context.AuditEvents.CountAsync());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task GetMine_RetiredAccessAndChangedEligibility_ReturnsOriginalPolicy(bool initiallyEligible)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test, eligibility: initiallyEligible);
        var original = await SubmitAsync(test, entitlement);
        test.Resource.IsActive = false;
        test.Resource.DeletedAt = test.Clock.Now.UtcDateTime;
        test.Resource.Name = "Retired target";
        await test.Database.Context.Entitlements.Where(item => item.Id == entitlement.Id)
            .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.IsActive, false));
        await test.Database.Context.EligibilityRules.ExecuteUpdateAsync(
            setters => setters.SetProperty(item => item.IsEnabled, !initiallyEligible));
        await test.Database.Context.SaveChangesAsync();
        test.Clock.Now = test.Clock.Now.AddMinutes(1);

        // Act
        var detail = await test.Client.GetFromJsonAsync<AccessRequestDetailsResponse>($"/api/access-requests/{original.Id}");

        // Assert
        Assert.NotNull(detail);
        Assert.Equal("Retired target", detail.ResourceName);
        Assert.Equal(original.State, detail.State);
        Assert.Equal(original.PolicyEvaluation, detail.PolicyEvaluation);
        Assert.Equal(original.CreatedAt, detail.CreatedAt);
        Assert.Equal(2, detail.AuditEvents.Count);
        Assert.Equal(1, await test.Database.Context.PolicyEvaluations.CountAsync());
    }

    [Theory]
    [InlineData("foreign")]
    [InlineData("missing")]
    [InlineData("empty")]
    [InlineData("malformed")]
    public async Task GetMine_ForeignOrUnknownRequest_ReturnsNotFoundWithoutDetails(string condition)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        var original = await SubmitAsync(test, entitlement);
        if (condition == "foreign")
        {
            await test.Database.Context.AccessRequests.ExecuteUpdateAsync(
                setters => setters.SetProperty(item => item.RequesterPrincipalId, test.Resource.CreatedByPrincipalId));
        }

        string id = condition switch
        {
            "foreign" => original.Id.ToString(),
            "empty" => Guid.Empty.ToString(),
            "malformed" => "not-a-guid",
            _ => Guid.NewGuid().ToString()
        };

        // Act
        using var response = await test.Client.GetAsync($"/api/access-requests/{id}");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        string body = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(body);
        Assert.Equal(404, json.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("Not Found", json.RootElement.GetProperty("title").GetString());
        Assert.DoesNotContain("Deploy release", body, StringComparison.Ordinal);
        Assert.False(json.RootElement.TryGetProperty("policyEvaluation", out _));
    }

    [Fact]
    public async Task GetMine_ExtraAndForeignAudits_ReturnsOnlyInitialSafeSummaries()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        var original = await SubmitAsync(test, entitlement);
        long requestId = await test.Database.Context.AccessRequests.Select(item => item.Id).SingleAsync();
        var initialAuditIds = await test.Database.Context.AuditEvents.Where(item => item.RequestId == requestId)
            .Select(item => item.PublicId).ToArrayAsync();
        var other = await SubmitAsync(test, entitlement, "another-request");
        await test.Database.Context.AccessRequests.Where(item => item.PublicId == other.Id).ExecuteUpdateAsync(
            setters => setters.SetProperty(item => item.RequesterPrincipalId, test.Resource.CreatedByPrincipalId));
        await test.Database.Context.AuditEvents.Where(item => item.RequestId != null && item.RequestId != requestId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.OccurredAt, test.Clock.Now.AddMinutes(-2).UtcDateTime));
        await test.Database.Context.AuditEvents.Where(item => item.RequestId == requestId).ExecuteUpdateAsync(
            setters => setters.SetProperty(item => item.Metadata, "{\"secret\":\"private-audit-marker\"}"));
        await test.Database.Context.PolicyEvaluations.Where(item => item.RequestId == requestId).ExecuteUpdateAsync(
            setters => setters.SetProperty(item => item.InputSnapshot, "{\"secret\":\"private-policy-marker\"}"));
        test.Database.Context.AuditEvents.Add(new AuditEvent
        {
            EventType = "connector.internal",
            OccurredAt = test.Clock.Now.AddMinutes(-1).UtcDateTime,
            RequestId = requestId,
            ActorKind = "system",
            CorrelationId = "private-correlation",
            Source = "test",
            Metadata = "{\"secret\":\"private-connector-marker\"}"
        });
        await test.Database.Context.SaveChangesAsync();

        // Act
        using var response = await test.Client.GetAsync($"/api/access-requests/{original.Id}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var detail = await response.Content.ReadFromJsonAsync<AccessRequestDetailsResponse>();
        Assert.NotNull(detail);
        Assert.Equal(initialAuditIds.Order(), detail.AuditEvents.Select(item => item.Id).Order());
        string body = await response.Content.ReadAsStringAsync();
        foreach (string field in PrivateFields)
        {
            Assert.DoesNotContain($"\"{field}\"", body, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("private-", body, StringComparison.Ordinal);
        Assert.DoesNotContain("connector.internal", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetMine_Anonymous_ReturnsUnauthorizedProblem()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync($"/api/access-requests/{Guid.NewGuid()}");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GetMine_OpenApi_DescribesOwnedDetailsPolicyAuditAndErrors()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/access-requests/{requestId}").GetProperty("get");
        Assert.Equal("AccessRequest.GetById", operation.GetProperty("operationId").GetString());
        var parameter = Assert.Single(operation.GetProperty("parameters").EnumerateArray());
        Assert.Equal("requestId", parameter.GetProperty("name").GetString());
        Assert.Equal("uuid", parameter.GetProperty("schema").GetProperty("format").GetString());
        foreach (string status in new[] { "200", "401", "404", "500" })
        {
            Assert.True(operation.GetProperty("responses").TryGetProperty(status, out _));
        }

        var schemas = json.RootElement.GetProperty("components").GetProperty("schemas");
        var detail = schemas.GetProperty("AccessRequestDetailsResponse").GetProperty("properties");
        Assert.Equal("uuid", detail.GetProperty("id").GetProperty("format").GetString());
        Assert.True(detail.TryGetProperty("policyEvaluation", out _));
        Assert.True(detail.TryGetProperty("auditEvents", out _));
        var audit = schemas.GetProperty("AccessRequestAuditEventResponse").GetProperty("properties");
        Assert.Equal("uuid", audit.GetProperty("id").GetProperty("format").GetString());
        Assert.Equal("date-time", audit.GetProperty("occurredAt").GetProperty("format").GetString());
        Assert.False(audit.TryGetProperty("metadata", out _));
        Assert.False(audit.TryGetProperty("actorSnapshot", out _));
    }

    private static async Task<AccessRequestResponse> SubmitAsync(
        ResourceTestContext test, Entitlement entitlement, string key = "submission-1")
    {
        using var response = await PostAsync(test, Request(test, entitlement), key);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var request = await response.Content.ReadFromJsonAsync<AccessRequestResponse>();
        Assert.NotNull(request);
        return request;
    }
}
