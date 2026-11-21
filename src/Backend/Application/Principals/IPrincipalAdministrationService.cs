using Application.Common.Pagination;

namespace Application.Principals;

public interface IPrincipalAdministrationService
{
    Task<CursorPage<PrincipalResponse>> ListAsync(int limit, PrincipalCursor? cursor, CancellationToken cancellationToken = default);
    Task<PrincipalResponse?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
}
