using System.Text.Json;
using Application.AccessRequests;
using Application.Sessions;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.AccessRequests;

public sealed class AccessRequestService(PamDbContext dbContext, TimeProvider timeProvider) : IAccessRequestService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<AccessRequestSubmissionResult> SubmitAsync(
        CreateAccessRequestRequest request,
        string idempotencyKey,
        PrincipalSnapshot requester,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        var normalized = request with
        {
            Justification = request.Justification.Trim(),
            TicketReference = string.IsNullOrWhiteSpace(request.TicketReference) ? null : request.TicketReference.Trim()
        };

        await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);

        var principal = await dbContext.Principals
            .Where(principal => principal.Id == requester.Id)
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        if (principal is null || !principal.IsEnabled || principal.PublicId != requester.PublicId
            || principal.Issuer != requester.Issuer || principal.Subject != requester.Subject)
        {
            return new(AccessRequestSubmissionKind.Forbidden);
        }

        var entitlement = await dbContext.Entitlements
            .Where(item => item.PublicId == normalized.EntitlementId && item.IsActive
                && item.Resource.PublicId == normalized.ResourceId && item.Resource.IsActive)
            .Select(item => new RequestEntitlement(
                item.Id, item.PublicId, item.Code, item.Name,
                item.MaxDurationMinutes, item.RequiresApproval, item.RequiresTicket,
                item.ResourceId, item.Resource.PublicId, item.Resource.Name,
                item.Resource.ResourceType, item.Resource.Environment,
                item.EligibilityRules.Any(rule => rule.PrincipalId == requester.Id && rule.IsEnabled)))
            .SingleOrDefaultAsync(cancellationToken);
        if (entitlement is null)
        {
            return new(AccessRequestSubmissionKind.Invalid)
            {
                Errors = new Dictionary<string, string[]>
                {
                    [nameof(request.EntitlementId)] = ["Select an active entitlement on the selected active resource."]
                }
            };
        }

        var decision = AccessRequestPolicy.Evaluate(
            normalized, entitlement.MaxDurationMinutes, entitlement.RequiresTicket, entitlement.IsEligible);
        if (decision.Outcome == AccessRequestOutcome.Invalid)
        {
            return new(AccessRequestSubmissionKind.Invalid) { Errors = decision.Errors };
        }

        var now = timeProvider.GetUtcNow();
        string state = decision.Outcome.ToString();
        var accessRequest = new AccessRequest
        {
            PublicId = Guid.CreateVersion7(now),
            RequesterPrincipalId = requester.Id,
            EntitlementId = entitlement.Id,
            RequestedDurationMinutes = normalized.RequestedDurationMinutes,
            Justification = normalized.Justification,
            TicketReference = normalized.TicketReference,
            State = state,
            IdempotencyKey = idempotencyKey,
            CreatedAt = now.UtcDateTime
        };
        string inputSnapshot = JsonSerializer.Serialize(new
        {
            requesterId = requester.PublicId,
            resourceId = entitlement.ResourcePublicId,
            entitlementId = entitlement.PublicId,
            normalized.RequestedDurationMinutes,
            entitlement.MaxDurationMinutes,
            entitlement.RequiresApproval,
            entitlement.RequiresTicket,
            ticketPresent = normalized.TicketReference is not null,
            entitlement.IsEligible
        }, JsonOptions);
        var evaluation = new PolicyEvaluation
        {
            PublicId = Guid.CreateVersion7(now),
            Request = accessRequest,
            PolicyCode = AccessRequestPolicy.Code,
            PolicyVersion = AccessRequestPolicy.Version,
            Decision = state,
            ReasonCode = decision.ReasonCode,
            Explanation = decision.Explanation,
            InputSnapshot = inputSnapshot,
            EvaluatedAt = now.UtcDateTime
        };
        var createdEvent = CreateAuditEvent(
            "access_request.created", accessRequest, entitlement, requester, decision,
            now.UtcDateTime, correlationId, JsonSerializer.Serialize(new
            {
                requestId = accessRequest.PublicId,
                accessRequest.RequestedDurationMinutes,
                state
            }, JsonOptions));
        var evaluatedEvent = CreateAuditEvent(
            "policy.evaluated", accessRequest, entitlement, requester, decision,
            now.UtcDateTime, correlationId, JsonSerializer.Serialize(new
            {
                requestId = accessRequest.PublicId,
                policyEvaluationId = evaluation.PublicId,
                evaluation.PolicyCode,
                evaluation.PolicyVersion,
                evaluation.Decision,
                evaluation.Explanation
            }, JsonOptions), createdEvent.PublicId);

        dbContext.AccessRequests.Add(accessRequest);
        dbContext.PolicyEvaluations.Add(evaluation);
        dbContext.AuditEvents.AddRange(createdEvent, evaluatedEvent);
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new(AccessRequestSubmissionKind.Created)
        {
            Request = new AccessRequestResponse(
                accessRequest.PublicId, entitlement.ResourcePublicId, entitlement.PublicId,
                accessRequest.RequestedDurationMinutes, accessRequest.Justification, accessRequest.TicketReference,
                state, now, new PolicyEvaluationResponse(
                    evaluation.PublicId, evaluation.PolicyCode, evaluation.PolicyVersion, state,
                    decision.ReasonCode, decision.Explanation, now))
        };
    }

    private static AuditEvent CreateAuditEvent(
        string eventType,
        AccessRequest request,
        RequestEntitlement entitlement,
        PrincipalSnapshot requester,
        AccessRequestPolicyResult decision,
        DateTime occurredAt,
        string correlationId,
        string metadata,
        Guid? causationId = null) => new()
        {
            PublicId = Guid.CreateVersion7(new DateTimeOffset(occurredAt, TimeSpan.Zero)),
            EventType = eventType,
            SchemaVersion = 1,
            OccurredAt = occurredAt,
            ActorKind = "principal",
            ActorPrincipalId = requester.Id,
            SubjectPrincipalId = requester.Id,
            ActorSnapshot = JsonSerializer.Serialize(requester, JsonOptions),
            SubjectSnapshot = JsonSerializer.Serialize(requester, JsonOptions),
            ResourceId = entitlement.ResourceId,
            ResourceSnapshot = JsonSerializer.Serialize(new
            {
                publicId = entitlement.ResourcePublicId,
                name = entitlement.ResourceName,
                entitlement.ResourceType,
                entitlement.Environment
            }, JsonOptions),
            EntitlementId = entitlement.Id,
            EntitlementSnapshot = JsonSerializer.Serialize(new
            {
                entitlement.PublicId,
                entitlement.Code,
                entitlement.Name,
                entitlement.MaxDurationMinutes,
                entitlement.RequiresApproval,
                entitlement.RequiresTicket
            }, JsonOptions),
            Request = request,
            CorrelationId = correlationId,
            CausationId = causationId,
            Source = "pam.api",
            Outcome = decision.Outcome == AccessRequestOutcome.Denied ? "denied" : "success",
            ReasonCode = decision.ReasonCode,
            Metadata = metadata
        };

    private sealed record RequestEntitlement(
        long Id,
        Guid PublicId,
        string Code,
        string Name,
        int MaxDurationMinutes,
        bool RequiresApproval,
        bool RequiresTicket,
        long ResourceId,
        Guid ResourcePublicId,
        string ResourceName,
        string ResourceType,
        string Environment,
        bool IsEligible);
}
