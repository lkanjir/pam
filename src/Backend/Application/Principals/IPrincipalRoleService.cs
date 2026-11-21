namespace Application.Principals;

public interface IPrincipalRoleService
{
    Task<PrincipalRolesResponse?> GetAsync(Guid principalId, CancellationToken cancellationToken = default);
}
