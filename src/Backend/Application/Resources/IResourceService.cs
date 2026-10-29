using Application.Common.Pagination;
using Application.Sessions;

namespace Application.Resources;

public interface IResourceService
{
    Task<ResourceResponse?> GetByIdAsync(Guid publicId, CancellationToken cancellationToken = default);

    Task<ResourceResponse> CreateAsync(
        CreateResourceRequest request,
        PrincipalSnapshot actor,
        string correlationId,
        CancellationToken cancellationToken = default);

    Task<ResourceResponse?> UpdateAsync(
        Guid publicId,
        UpdateResourceRequest request,
        PrincipalSnapshot actor,
        string correlationId,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(
        Guid publicId,
        PrincipalSnapshot actor,
        string correlationId,
        CancellationToken cancellationToken = default);

    Task<CursorPage<ResourceResponse>> ListAsync(
        int limit,
        ResourceCursor? cursor,
        CancellationToken cancellationToken = default);
}
