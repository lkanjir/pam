using Application.Authorization;
using Application.Resources;

namespace Application.Principals;

public interface IApprovalAuthorityService
{
    Task<ResourceAccessPage?> ListAsync(Guid principalId, int limit, ResourceCursor? cursor,
        CancellationToken cancellationToken = default);
    Task<ResourceAccessWriteResult> AssignAsync(Guid principalId, Guid resourceId, ChangeResourceAccessRequest request,
        AdministrativeActor actor, uint expectedVersion, string correlationId, CancellationToken cancellationToken = default);
}
