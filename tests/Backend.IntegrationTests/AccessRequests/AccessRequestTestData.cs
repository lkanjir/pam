using System.Net.Http.Json;
using Application.AccessRequests;
using Backend.IntegrationTests.Resources;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.AccessRequests;

internal static class AccessRequestTestData
{
    public static AccessRequest AddRequest(
        ResourceTestContext test,
        Entitlement entitlement,
        Guid publicId,
        long? requesterId = null,
        string state = "PendingApproval")
    {
        var request = new AccessRequest(AccessRequestStates.Parse(state))
        {
            PublicId = publicId,
            RequesterPrincipalId = requesterId ?? test.ActorId,
            Entitlement = entitlement,
            RequestedDurationMinutes = 30,
            Justification = "Deploy release",
            TicketReference = "INC-1042",
            IdempotencyKey = publicId.ToString(),
            CreatedAt = test.Clock.Now.UtcDateTime
        };
        test.Database.Context.AccessRequests.Add(request);
        return request;
    }

    public static async Task<Entitlement> SeedEntitlementAsync(
        ResourceTestContext test,
        bool? eligibility = true,
        bool isActive = true,
        bool requiresTicket = true,
        bool requiresApproval = true,
        long? principalId = null)
    {
        var entitlement = new Entitlement
        {
            Resource = test.Resource,
            Code = "TemporaryLinuxAdmin",
            Name = "Temporary Linux administrator",
            MaxDurationMinutes = 60,
            RequiresApproval = requiresApproval,
            RequiresTicket = requiresTicket,
            IsActive = isActive
        };
        test.Database.Context.Entitlements.Add(entitlement);
        if (eligibility is not null)
        {
            test.Database.Context.EligibilityRules.Add(new EligibilityRule
            {
                PrincipalId = principalId ?? test.ActorId,
                Entitlement = entitlement,
                IsEnabled = eligibility.Value,
                CreatedAt = test.Clock.Now.UtcDateTime
            });
        }

        await test.Database.Context.SaveChangesAsync();
        return entitlement;
    }

    public static CreateAccessRequestRequest Request(ResourceTestContext test, Entitlement entitlement) => new()
    {
        ResourceId = test.Resource.PublicId,
        EntitlementId = entitlement.PublicId,
        RequestedDurationMinutes = 30,
        Justification = "Deploy release",
        TicketReference = "INC-1042"
    };

    public static Dictionary<string, object?> Payload(ResourceTestContext test, Entitlement entitlement) => new()
    {
        ["resourceId"] = test.Resource.PublicId,
        ["entitlementId"] = entitlement.PublicId,
        ["requestedDurationMinutes"] = 30,
        ["justification"] = "Deploy release",
        ["ticketReference"] = "INC-1042"
    };

    public static async Task<HttpResponseMessage> PostAsync(
        ResourceTestContext test,
        object payload,
        string? key = "submission-1")
    {
        using var message = new HttpRequestMessage(HttpMethod.Post, "/api/access-requests")
        {
            Content = JsonContent.Create(payload)
        };
        if (key is not null)
        {
            message.Headers.TryAddWithoutValidation("Idempotency-Key", key);
        }

        return await test.Client.SendAsync(message);
    }

    public static async Task AssertNoRequestsAsync(ResourceTestContext test)
    {
        Assert.Equal(0, await test.Database.Context.AccessRequests.CountAsync());
        Assert.Equal(0, await test.Database.Context.PolicyEvaluations.CountAsync());
        Assert.Equal(0, await test.Database.Context.AuditEvents.CountAsync(
            item => item.EventType == "access_request.created" || item.EventType == "policy.evaluated"));
    }
}
