namespace Application.AccessRequests;

/// <summary>An owned request, its saved policy decision and its initial submission audit events.</summary>
public sealed record AccessRequestDetailsResponse(
    Guid Id,
    Guid ResourceId,
    string ResourceName,
    Guid EntitlementId,
    string EntitlementName,
    int RequestedDurationMinutes,
    string Justification,
    string? TicketReference,
    string State,
    DateTimeOffset CreatedAt,
    PolicyEvaluationResponse PolicyEvaluation,
    IReadOnlyList<AccessRequestAuditEventResponse> AuditEvents);

/// <summary>A safe submission audit summary without internal IDs, snapshots or raw metadata.</summary>
public sealed record AccessRequestAuditEventResponse(
    Guid Id,
    string EventType,
    DateTimeOffset OccurredAt,
    string? Outcome,
    string? ReasonCode);
