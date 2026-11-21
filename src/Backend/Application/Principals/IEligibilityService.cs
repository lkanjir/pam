using Application.Authorization;
using Application.Resources;

namespace Application.Principals;

public interface IEligibilityService
{
    Task<EligibilityPage?> ListAsync(Guid principalId, int limit, EntitlementCursor? cursor,
        CancellationToken cancellationToken = default);
    Task<EligibilityWriteResult> AssignAsync(Guid principalId, Guid resourceId, Guid entitlementId,
        ChangeEligibilityRequest request, AdministrativeActor actor, uint expectedVersion, string correlationId,
        CancellationToken cancellationToken = default);
}
