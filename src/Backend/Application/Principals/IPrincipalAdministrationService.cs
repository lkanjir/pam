using Application.Authorization;
using Application.Common.Pagination;

namespace Application.Principals;

public interface IPrincipalAdministrationService
{
    Task<CursorPage<PrincipalResponse>> ListAsync(int limit, PrincipalCursor? cursor, CancellationToken cancellationToken = default);
    Task<PrincipalResponse?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<PrincipalWriteResult> CreateAsync(CreatePrincipalRequest request, AdministrativeActor actor,
        string correlationId, CancellationToken cancellationToken = default);
}
