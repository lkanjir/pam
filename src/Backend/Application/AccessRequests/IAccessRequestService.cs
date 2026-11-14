using Application.Sessions;

namespace Application.AccessRequests;

public enum AccessRequestSubmissionKind
{
    Created,
    Invalid,
    Forbidden
}

public sealed record AccessRequestSubmissionResult(AccessRequestSubmissionKind Kind)
{
    public AccessRequestResponse? Request { get; init; }
    public Dictionary<string, string[]> Errors { get; init; } = [];
}

public interface IAccessRequestService
{
    Task<AccessRequestSubmissionResult> SubmitAsync(
        CreateAccessRequestRequest request,
        string idempotencyKey,
        PrincipalSnapshot requester,
        string correlationId,
        CancellationToken cancellationToken = default);
}
