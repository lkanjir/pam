using Application.Authorization;

namespace Application.Principals;

public interface IApprovalAuthorityService
{
    Task<ResourceAccessWriteResult> AssignAsync(Guid principalId, Guid resourceId, ChangeResourceAccessRequest request,
        AdministrativeActor actor, uint expectedVersion, string correlationId, CancellationToken cancellationToken = default);
}
