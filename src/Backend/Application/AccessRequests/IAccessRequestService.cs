using Application.Common.Pagination;
using Application.Sessions;

namespace Application.AccessRequests;

public enum AccessRequestSubmissionKind
{
    Created,
    Replayed,
    Invalid,
    Conflict,
    Forbidden
}

public sealed record AccessRequestSubmissionResult(AccessRequestSubmissionKind Kind)
{
    public AccessRequestResponse? Request { get; init; }
    public Dictionary<string, string[]> Errors { get; init; } = [];
}

public interface IAccessRequestService
{
    Task<AccessRequestDetailsResponse?> GetMineAsync(
        Guid publicId,
        long principalId,
        CancellationToken cancellationToken = default);

    Task<CursorPage<AccessRequestSummaryResponse>> ListMineAsync(
        long principalId,
        int limit,
        AccessRequestCursor? cursor,
        CancellationToken cancellationToken = default);

    Task<AccessRequestSubmissionResult> SubmitAsync(
        CreateAccessRequestRequest request,
        string idempotencyKey,
        PrincipalSnapshot requester,
        string correlationId,
        CancellationToken cancellationToken = default);
}
