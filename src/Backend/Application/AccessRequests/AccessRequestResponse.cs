namespace Application.AccessRequests;

/// <summary>A persisted access request and its initial policy evaluation.</summary>
public sealed record AccessRequestResponse(
    Guid Id,
    Guid ResourceId,
    Guid EntitlementId,
    int RequestedDurationMinutes,
    string Justification,
    string? TicketReference,
    string State,
    DateTimeOffset CreatedAt,
    PolicyEvaluationResponse PolicyEvaluation);

/// <summary>The versioned, safe explanation of the initial access-request decision.</summary>
public sealed record PolicyEvaluationResponse(
    Guid Id,
    string PolicyCode,
    int PolicyVersion,
    string Decision,
    string ReasonCode,
    string Explanation,
    DateTimeOffset EvaluatedAt);
