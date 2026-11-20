using Application.Authorization;
using Application.Common.Pagination;
using Application.Sessions;

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
        PrincipalSnapshot actor,
        string correlationId,
        uint expectedVersion,
        CancellationToken cancellationToken = default);

    Task<ResourceWriteKind> DeleteAsync(
        Guid publicId,
        PrincipalSnapshot actor,
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
