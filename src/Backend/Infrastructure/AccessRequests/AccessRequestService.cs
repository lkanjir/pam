using System.Text.Json;
using Application.AccessRequests;
using Application.Common.Pagination;
using Application.Sessions;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.AccessRequests;

public sealed class AccessRequestService(PamDbContext dbContext, TimeProvider timeProvider) : IAccessRequestService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<CursorPage<AccessRequestSummaryResponse>> ListMineAsync(
        long principalId,
        int limit,
        AccessRequestCursor? cursor,
        CancellationToken cancellationToken = default)
    {
        // Request history remains visible after a resource is retired or soft-deleted.
        var requests = dbContext.AccessRequests.IgnoreQueryFilters()
            .Where(request => request.RequesterPrincipalId == principalId);
        if (cursor is not null)
        {
            Guid lastPublicId = cursor.LastPublicId;
            requests = requests.Where(request => request.PublicId.CompareTo(lastPublicId) < 0);
        }

        var items = await requests.OrderByDescending(request => request.PublicId)
            .Select(request => new AccessRequestSummaryResponse(
                request.PublicId, request.Entitlement.Resource.PublicId, request.Entitlement.Resource.Name,
                request.Entitlement.PublicId, request.Entitlement.Name, request.RequestedDurationMinutes,
                request.State, new DateTimeOffset(request.CreatedAt, TimeSpan.Zero)))
            .Take(limit + 1)
            .ToListAsync(cancellationToken);

        bool hasNextPage = items.Count > limit;
        if (hasNextPage)
        {
            items.RemoveAt(limit);
        }

        string? nextCursor = hasNextPage ? CursorCodec.Encode(new AccessRequestCursor(items[^1].Id)) : null;
        return new CursorPage<AccessRequestSummaryResponse>(items, nextCursor);
    }

    public async Task<AccessRequestDetailsResponse?> GetMineAsync(
        Guid publicId,
        long principalId,
        CancellationToken cancellationToken = default)
    {
        var response = await (from request in dbContext.AccessRequests.IgnoreQueryFilters()
                              join entitlement in dbContext.Entitlements on request.EntitlementId equals entitlement.Id
                              join resource in dbContext.ManagedResources on entitlement.ResourceId equals resource.Id
                              join evaluation in dbContext.PolicyEvaluations on request.Id equals evaluation.RequestId
                              where request.PublicId == publicId && request.RequesterPrincipalId == principalId
                              select new AccessRequestDetailsResponse(
                                  request.PublicId, resource.PublicId, resource.Name, entitlement.PublicId, entitlement.Name,
                                  request.RequestedDurationMinutes, request.Justification, request.TicketReference,
                                  request.State, new DateTimeOffset(request.CreatedAt, TimeSpan.Zero),
                                  new PolicyEvaluationResponse(
                                      evaluation.PublicId, evaluation.PolicyCode, evaluation.PolicyVersion,
                                      evaluation.Decision, evaluation.ReasonCode ?? string.Empty,
                                      evaluation.Explanation ?? string.Empty,
                                      new DateTimeOffset(evaluation.EvaluatedAt, TimeSpan.Zero)),
                                  Array.Empty<AccessRequestAuditEventResponse>()))
            .SingleOrDefaultAsync(cancellationToken);
        if (response is null)
        {
            return null;
        }

        var events = await (from audit in dbContext.AuditEvents
                            join request in dbContext.AccessRequests on audit.RequestId equals request.Id
                            where request.PublicId == publicId && request.RequesterPrincipalId == principalId
                                && (audit.EventType == "access_request.created" || audit.EventType == "policy.evaluated")
                            orderby audit.OccurredAt, audit.Id
                            select new AccessRequestAuditEventResponse(
                                audit.PublicId, audit.EventType, new DateTimeOffset(audit.OccurredAt, TimeSpan.Zero),
                                audit.Outcome, audit.ReasonCode))
            .Take(2)
            .ToListAsync(cancellationToken);

        return response with { AuditEvents = events };
    }

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
        string payloadHash = AccessRequestFingerprint.CreateV1(normalized);

        await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);

        // Serialize submissions only for this requester, across API replicas. Check the key after acquiring
        // the row lock, so a concurrent identical submission observes the committed winner without retries
        // or provider-exception classification. The unique database index remains the final constraint.
        var principal = await dbContext.Principals
            .FromSql($"SELECT * FROM principals WHERE id = {requester.Id} FOR UPDATE")
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        if (principal is null || !principal.IsEnabled || principal.PublicId != requester.PublicId
            || principal.Issuer != requester.Issuer || principal.Subject != requester.Subject)
        {
            return new(AccessRequestSubmissionKind.Forbidden);
        }

        var previous = await FindPreviousAsync(requester.Id, idempotencyKey, cancellationToken);
        if (previous is not null)
        {
            return AccessRequestFingerprint.IsMatch(previous.PayloadHash, payloadHash)
                ? new(AccessRequestSubmissionKind.Replayed) { Request = previous.Response }
                : new(AccessRequestSubmissionKind.Conflict);
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
        if (decision.Decision is not { } policyDecision)
        {
            return new(AccessRequestSubmissionKind.Invalid) { Errors = decision.Errors };
        }

        var now = timeProvider.GetUtcNow();
        var initialState = policyDecision.InitialState();
        string state = initialState.ToCode();
        var accessRequest = new AccessRequest(initialState)
        {
            PublicId = Guid.CreateVersion7(now),
            RequesterPrincipalId = requester.Id,
            EntitlementId = entitlement.Id,
            RequestedDurationMinutes = normalized.RequestedDurationMinutes,
            Justification = normalized.Justification,
            TicketReference = normalized.TicketReference,
            IdempotencyKey = idempotencyKey,
            PayloadHash = payloadHash,
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
        var evaluation = new PolicyEvaluation(policyDecision)
        {
            PublicId = Guid.CreateVersion7(now),
            Request = accessRequest,
            PolicyCode = AccessRequestPolicy.Code,
            PolicyVersion = AccessRequestPolicy.Version,
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
                    evaluation.PublicId, evaluation.PolicyCode, evaluation.PolicyVersion, evaluation.Decision,
                    decision.ReasonCode, decision.Explanation, now))
        };
    }

    private Task<PreviousSubmission?> FindPreviousAsync(
        long principalId,
        string key,
        CancellationToken cancellationToken)
    {
        // Replays use persisted decisions even if the resource was later retired or eligibility changed.
        return (from request in dbContext.AccessRequests.IgnoreQueryFilters()
                join entitlement in dbContext.Entitlements on request.EntitlementId equals entitlement.Id
                join resource in dbContext.ManagedResources on entitlement.ResourceId equals resource.Id
                join evaluation in dbContext.PolicyEvaluations on request.Id equals evaluation.RequestId
                where request.RequesterPrincipalId == principalId && request.IdempotencyKey == key
                select new PreviousSubmission(request.PayloadHash, new AccessRequestResponse(
                    request.PublicId, resource.PublicId, entitlement.PublicId,
                    request.RequestedDurationMinutes, request.Justification, request.TicketReference,
                    AccessRequestPolicyDecisions.Parse(evaluation.Decision).InitialState().ToCode(),
                    new DateTimeOffset(request.CreatedAt, TimeSpan.Zero),
                    new PolicyEvaluationResponse(
                        evaluation.PublicId, evaluation.PolicyCode, evaluation.PolicyVersion,
                        evaluation.Decision, evaluation.ReasonCode ?? string.Empty,
                        evaluation.Explanation ?? string.Empty,
                        new DateTimeOffset(evaluation.EvaluatedAt, TimeSpan.Zero)))))
            .SingleOrDefaultAsync(cancellationToken);
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
            Outcome = decision.Decision == AccessRequestPolicyDecision.Deny ? "denied" : "success",
            ReasonCode = decision.ReasonCode,
            Metadata = metadata
        };

    private sealed record PreviousSubmission(string? PayloadHash, AccessRequestResponse Response);

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
