using Application.Resources;

namespace Application.Principals;

public interface IEligibilityService
{
    Task<EligibilityPage?> ListAsync(Guid principalId, int limit, EntitlementCursor? cursor,
        CancellationToken cancellationToken = default);
}
