using Application.Resources;

namespace Application.Principals;

public interface IResourceAccessService
{
    Task<ResourceAccessPage?> ListAsync(Guid principalId, int limit, ResourceCursor? cursor,
        CancellationToken cancellationToken = default);
}
