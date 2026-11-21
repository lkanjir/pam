using Application.Authorization;

namespace Application.Principals;

public interface IPrincipalRoleService
{
    Task<PrincipalRolesResponse?> GetAsync(Guid principalId, CancellationToken cancellationToken = default);
    Task<PrincipalRoleWriteResult> AssignAsync(Guid principalId, string roleCode, ChangePrincipalRoleRequest request,
        AdministrativeActor actor, uint expectedVersion, string correlationId, CancellationToken cancellationToken = default);
    Task<PrincipalRoleWriteResult> RemoveAsync(Guid principalId, string roleCode, ChangePrincipalRoleRequest request,
        AdministrativeActor actor, uint expectedVersion, string correlationId, CancellationToken cancellationToken = default);
}
