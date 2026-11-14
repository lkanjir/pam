using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Application.AccessRequests;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Microsoft.EntityFrameworkCore;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.AccessRequests;

[Collection("Cookie sessions")]
public sealed class AccessRequestSubmissionTests(PostgresFixture postgres, RedisFixture redis)
{
    private static readonly string[] DuplicateIdempotencyKeys = ["first-key", "second-key"];

    [Theory]
    [InlineData(1)]
    [InlineData(30)]
    [InlineData(60)]
    public async Task Submit_EligibleRequest_PersistsPendingDecisionAndCorrelatedAudit(int minutes)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        var request = Request(test, entitlement) with
        {
            RequestedDurationMinutes = minutes,
            Justification = " Deploy release ",
            TicketReference = " INC-1042 "
        };

        // Act
        using var response = await PostAsync(test, request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<AccessRequestResponse>();
        Assert.NotNull(result);
        Assert.EndsWith($"/api/access-requests/{result.Id}", response.Headers.Location?.OriginalString);
        Assert.NotEqual(Guid.Empty, result.Id);
        Assert.Equal(test.Resource.PublicId, result.ResourceId);
        Assert.Equal(entitlement.PublicId, result.EntitlementId);
        Assert.Equal(minutes, result.RequestedDurationMinutes);
        Assert.Equal("Deploy release", result.Justification);
        Assert.Equal("INC-1042", result.TicketReference);
        Assert.Equal("PendingApproval", result.State);
        Assert.Equal(test.Clock.Now, result.CreatedAt);
        Assert.Equal(TimeSpan.Zero, result.CreatedAt.Offset);
        Assert.Equal("sprint1.eligibility", result.PolicyEvaluation.PolicyCode);
        Assert.Equal(1, result.PolicyEvaluation.PolicyVersion);
        Assert.Equal("PendingApproval", result.PolicyEvaluation.Decision);
        Assert.Equal("approval_required", result.PolicyEvaluation.ReasonCode);
        Assert.Equal("The request requires manual approval.", result.PolicyEvaluation.Explanation);
        Assert.Equal(test.Clock.Now, result.PolicyEvaluation.EvaluatedAt);

        var saved = await test.Database.Context.AccessRequests.AsNoTracking().SingleAsync();
        Assert.Equal(result.Id, saved.PublicId);
        Assert.Equal(test.ActorId, saved.RequesterPrincipalId);
        Assert.Equal(entitlement.Id, saved.EntitlementId);
        Assert.Equal(minutes, saved.RequestedDurationMinutes);
        Assert.Equal("Deploy release", saved.Justification);
        Assert.Equal("INC-1042", saved.TicketReference);
        Assert.Equal("PendingApproval", saved.State);
        Assert.Equal("submission-1", saved.IdempotencyKey);
        Assert.Equal(test.Clock.Now.UtcDateTime, saved.CreatedAt);
        var evaluation = await test.Database.Context.PolicyEvaluations.AsNoTracking().SingleAsync();
        Assert.Equal(result.PolicyEvaluation.Id, evaluation.PublicId);
        Assert.Equal(saved.Id, evaluation.RequestId);
        Assert.Equal("PendingApproval", evaluation.Decision);
        Assert.Equal("sprint1.eligibility", evaluation.PolicyCode);
        Assert.Equal(1, evaluation.PolicyVersion);
        using var evidence = JsonDocument.Parse(Assert.IsType<string>(evaluation.InputSnapshot));
        Assert.True(evidence.RootElement.GetProperty("isEligible").GetBoolean());
        Assert.True(evidence.RootElement.GetProperty("ticketPresent").GetBoolean());
        Assert.Equal(minutes, evidence.RootElement.GetProperty("requestedDurationMinutes").GetInt32());
        Assert.Equal(60, evidence.RootElement.GetProperty("maxDurationMinutes").GetInt32());

        var audits = await test.Database.Context.AuditEvents.AsNoTracking()
            .Where(item => item.RequestId == saved.Id).ToListAsync();
        var created = Assert.Single(audits, audit => audit.EventType == "access_request.created");
        var evaluated = Assert.Single(audits, audit => audit.EventType == "policy.evaluated");
        Assert.Equal(2, audits.Count);
        Assert.Null(created.CausationId);
        Assert.Equal(created.PublicId, evaluated.CausationId);
        Assert.All(audits, audit =>
        {
            Assert.Equal(test.ActorId, audit.ActorPrincipalId);
            Assert.Equal(test.ActorId, audit.SubjectPrincipalId);
            Assert.Equal(test.Resource.Id, audit.ResourceId);
            Assert.Equal(entitlement.Id, audit.EntitlementId);
            Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
            Assert.Equal(test.Clock.Now.UtcDateTime, audit.OccurredAt);
            Assert.Equal(1, audit.SchemaVersion);
            Assert.Equal("pam.api", audit.Source);
            Assert.Equal("success", audit.Outcome);
            using var actor = JsonDocument.Parse(Assert.IsType<string>(audit.ActorSnapshot));
            Assert.Equal(test.ActorId, actor.RootElement.GetProperty("id").GetInt64());
            using var resource = JsonDocument.Parse(Assert.IsType<string>(audit.ResourceSnapshot));
            Assert.Equal(test.Resource.PublicId, resource.RootElement.GetProperty("publicId").GetGuid());
            using var rights = JsonDocument.Parse(Assert.IsType<string>(audit.EntitlementSnapshot));
            Assert.Equal(entitlement.PublicId, rights.RootElement.GetProperty("publicId").GetGuid());
        });
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("disabled")]
    [InlineData("other-principal")]
    public async Task Submit_IneligibleRequest_PersistsDeniedDecisionWithoutSuccessAudit(string eligibility)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test,
            eligibility == "missing" ? null : eligibility != "disabled",
            principalId: eligibility == "other-principal" ? test.Resource.CreatedByPrincipalId : test.ActorId);

        // Act
        using var response = await PostAsync(test, Request(test, entitlement));

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<AccessRequestResponse>();
        Assert.NotNull(result);
        Assert.Equal("Denied", result.State);
        Assert.Equal("Denied", result.PolicyEvaluation.Decision);
        Assert.Equal("not_eligible", result.PolicyEvaluation.ReasonCode);
        Assert.Equal("The requester is not eligible for this entitlement.", result.PolicyEvaluation.Explanation);
        Assert.Equal("Denied", await test.Database.Context.AccessRequests.Select(item => item.State).SingleAsync());
        Assert.Equal("Denied", await test.Database.Context.PolicyEvaluations.Select(item => item.Decision).SingleAsync());
        var audits = await test.Database.Context.AuditEvents.Where(item => item.RequestId != null).ToListAsync();
        Assert.Equal(2, audits.Count);
        Assert.All(audits, audit =>
        {
            Assert.Equal("denied", audit.Outcome);
            Assert.Equal("not_eligible", audit.ReasonCode);
        });
    }

    [Fact]
    public async Task Submit_OptionalTicketAndNoApprovalFlag_StillQueuesManualApproval()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test, requiresTicket: false, requiresApproval: false);
        var request = Request(test, entitlement) with { TicketReference = " " };

        // Act
        using var response = await PostAsync(test, request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<AccessRequestResponse>();
        Assert.NotNull(result);
        Assert.Equal("PendingApproval", result.State);
        Assert.Null(result.TicketReference);
    }

    [Theory]
    [InlineData("unknown-resource")]
    [InlineData("unknown-entitlement")]
    [InlineData("mismatched-resource")]
    [InlineData("inactive-resource")]
    [InlineData("deleted-resource")]
    [InlineData("inactive-entitlement")]
    public async Task Submit_UnavailableResourceOrEntitlement_ReturnsValidationErrorWithoutPersistence(string condition)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test, isActive: condition != "inactive-entitlement");
        var request = Request(test, entitlement);
        if (condition is "unknown-resource" or "mismatched-resource")
        {
            if (condition == "mismatched-resource")
            {
                using var other = await test.Client.PostAsJsonAsync("/api/resources", new
                {
                    name = "Other target",
                    resourceType = "linux",
                    environment = "dev"
                });
                other.EnsureSuccessStatusCode();
                var resource = await other.Content.ReadFromJsonAsync<Application.Resources.ResourceResponse>();
                Assert.NotNull(resource);
                request = request with { ResourceId = resource.Id };
            }
            else
            {
                request = request with { ResourceId = Guid.NewGuid() };
            }
        }

        if (condition == "unknown-entitlement")
        {
            request = request with { EntitlementId = Guid.NewGuid() };
        }

        test.Resource.IsActive = condition != "inactive-resource";
        test.Resource.DeletedAt = condition == "deleted-resource" ? test.Clock.Now.UtcDateTime : null;
        await test.Database.Context.SaveChangesAsync();

        // Act
        using var response = await PostAsync(test, request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(json.RootElement.GetProperty("errors").TryGetProperty("EntitlementId", out _));
        await AssertNoRequestsAsync(test);
    }

    [Theory]
    [InlineData("missing-resource")]
    [InlineData("empty-resource")]
    [InlineData("missing-entitlement")]
    [InlineData("malformed-id")]
    [InlineData("zero-duration")]
    [InlineData("negative-duration")]
    [InlineData("over-duration")]
    [InlineData("missing-justification")]
    [InlineData("null-justification")]
    [InlineData("blank-justification")]
    [InlineData("long-justification")]
    [InlineData("missing-ticket")]
    [InlineData("blank-ticket")]
    [InlineData("long-ticket")]
    public async Task Submit_InvalidPayload_ReturnsBadRequestWithoutPersistence(string condition)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        var payload = Payload(test, entitlement);
        switch (condition)
        {
            case "missing-resource":
                payload.Remove("resourceId");
                break;
            case "empty-resource":
                payload["resourceId"] = Guid.Empty;
                break;
            case "missing-entitlement":
                payload.Remove("entitlementId");
                break;
            case "malformed-id":
                payload["entitlementId"] = "invalid";
                break;
            case "zero-duration":
                payload["requestedDurationMinutes"] = 0;
                break;
            case "negative-duration":
                payload["requestedDurationMinutes"] = -1;
                break;
            case "over-duration":
                payload["requestedDurationMinutes"] = 61;
                break;
            case "missing-justification":
                payload.Remove("justification");
                break;
            case "null-justification":
                payload["justification"] = null;
                break;
            case "blank-justification":
                payload["justification"] = " ";
                break;
            case "long-justification":
                payload["justification"] = new string('x', 2001);
                break;
            case "missing-ticket":
                payload.Remove("ticketReference");
                break;
            case "blank-ticket":
                payload["ticketReference"] = " ";
                break;
            case "long-ticket":
                payload["ticketReference"] = new string('x', 101);
                break;
        }

        // Act
        using var response = await PostAsync(test, payload);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        await AssertNoRequestsAsync(test);
    }

    [Fact]
    public async Task Submit_TextAtMaximumLengths_AcceptsPayload()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        var request = Request(test, entitlement) with
        {
            Justification = new string('j', 2000),
            TicketReference = new string('t', 100)
        };

        // Act
        using var response = await PostAsync(test, request, new string('k', 128));

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<AccessRequestResponse>();
        Assert.NotNull(result);
        Assert.Equal(request.Justification, result.Justification);
        Assert.Equal(request.TicketReference, result.TicketReference);
    }

    [Fact]
    public async Task Submit_ClientSuppliedIdentityAndState_UsesSessionAndServerValues()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        var payload = Payload(test, entitlement);
        payload["requesterPrincipalId"] = test.Resource.CreatedByPrincipalId;
        payload["requesterId"] = Guid.NewGuid();
        payload["state"] = "Approved";
        payload["approvalResult"] = true;
        payload["createdAt"] = test.Clock.Now.AddYears(-1);

        // Act
        using var response = await PostAsync(test, payload);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var saved = await test.Database.Context.AccessRequests.AsNoTracking().SingleAsync();
        Assert.Equal(test.ActorId, saved.RequesterPrincipalId);
        Assert.Equal("PendingApproval", saved.State);
        Assert.Equal(test.Clock.Now.UtcDateTime, saved.CreatedAt);
    }

    [Theory]
    [InlineData("anonymous")]
    [InlineData("missing-csrf")]
    [InlineData("invalid-csrf")]
    public async Task Submit_WithoutAuthenticationOrAntiforgery_RejectsWithoutPersistence(string condition)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        if (condition != "anonymous")
        {
            await test.AuthenticateAsync();
            test.Client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
            if (condition == "invalid-csrf")
            {
                test.Client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", "invalid");
            }
        }

        var entitlement = await SeedEntitlementAsync(test);

        // Act
        using var response = await PostAsync(test, Request(test, entitlement));

        // Assert
        Assert.Equal(condition == "anonymous" ? HttpStatusCode.Unauthorized : HttpStatusCode.BadRequest,
            response.StatusCode);
        await AssertNoRequestsAsync(test);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("has space")]
    [InlineData("over-limit")]
    public async Task Submit_InvalidIdempotencyKey_ReturnsBadRequestWithoutPersistence(string? key)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        string? header = key == "over-limit" ? new string('k', 129) : key;

        // Act
        using var response = await PostAsync(test, Request(test, entitlement), header);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertNoRequestsAsync(test);
    }

    [Fact]
    public async Task Submit_MultipleIdempotencyHeaders_ReturnsBadRequestWithoutPersistence()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);
        using var message = new HttpRequestMessage(HttpMethod.Post, "/api/access-requests")
        {
            Content = JsonContent.Create(Request(test, entitlement))
        };
        message.Headers.Add("Idempotency-Key", DuplicateIdempotencyKeys);

        // Act
        using var response = await test.Client.SendAsync(message);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertNoRequestsAsync(test);
    }

    [Fact]
    public async Task Submit_NonAsciiIdempotencyKey_ReturnsBadRequestWithoutPersistence()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        var entitlement = await SeedEntitlementAsync(test);

        // Act
        using var response = await PostAsync(test, Request(test, entitlement), "cl\u00e9");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertNoRequestsAsync(test);
    }

    [Fact]
    public async Task Submit_MalformedJson_ReturnsProblemDetailsWithoutPersistence()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync();
        using var message = new HttpRequestMessage(HttpMethod.Post, "/api/access-requests")
        {
            Content = new StringContent("{", Encoding.UTF8, "application/json")
        };
        message.Headers.Add("Idempotency-Key", "malformed-request");

        // Act
        using var response = await test.Client.SendAsync(message);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        await AssertNoRequestsAsync(test);
    }

    [Fact]
    public async Task Submit_OpenApi_DescribesHeaderResponsesAndPolicySchema()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/access-requests").GetProperty("post");
        Assert.Equal("AccessRequest.Create", operation.GetProperty("operationId").GetString());
        var key = Assert.Single(operation.GetProperty("parameters").EnumerateArray(),
            item => item.GetProperty("name").GetString() == "Idempotency-Key");
        Assert.Equal("header", key.GetProperty("in").GetString());
        Assert.True(key.GetProperty("required").GetBoolean());
        Assert.Equal(128, key.GetProperty("schema").GetProperty("maxLength").GetInt32());
        foreach (string status in new[] { "201", "400", "401", "403", "500" })
        {
            Assert.Contains(status, operation.GetProperty("responses").EnumerateObject().Select(item => item.Name));
        }

        var schema = json.RootElement.GetProperty("components").GetProperty("schemas")
            .GetProperty("AccessRequestResponse").GetProperty("properties");
        Assert.Equal("uuid", schema.GetProperty("id").GetProperty("format").GetString());
        Assert.True(schema.TryGetProperty("policyEvaluation", out _));
        Assert.False(schema.TryGetProperty("requesterPrincipalId", out _));
    }
}
