using Application.Authorization;
using Application.Common.Pagination;

namespace Application.Resources;

public interface IResourceService
{
    Task<ResourceResponse?> GetByIdAsync(Guid publicId, CancellationToken cancellationToken = default);

    Task<ResourceWriteResult> CreateAsync(
        CreateResourceRequest request,
        AdministrativeActor actor,
        string correlationId,
        CancellationToken cancellationToken = default);

    Task<ResourceWriteResult> UpdateAsync(
        Guid publicId,
        UpdateResourceRequest request,
        AdministrativeActor actor,
        string correlationId,
        uint expectedVersion,
        CancellationToken cancellationToken = default);

    Task<ResourceWriteKind> DeleteAsync(
        Guid publicId,
        AdministrativeActor actor,
        string correlationId,
        uint expectedVersion,
        CancellationToken cancellationToken = default);

    Task<CursorPage<ResourceResponse>> ListAsync(
        int limit,
        ResourceCursor? cursor,
        CancellationToken cancellationToken = default);

    Task<CursorPage<ResourceResponse>> ListRequestableAsync(
        long principalId,
        int limit,
        ResourceCursor? cursor,
        CancellationToken cancellationToken = default);
}
