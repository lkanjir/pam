using Application.Authorization;
using Application.Principals;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Principals;

public sealed class PrincipalRoleService(PamDbContext database) : IPrincipalRoleService
{
    public Task<PrincipalRolesResponse?> GetAsync(Guid principalId, CancellationToken cancellationToken = default) =>
        database.Principals.AsNoTracking().Where(principal => principal.PublicId == principalId)
            .Select(principal => new PrincipalRolesResponse(principal.PublicId,
                principal.RoleAssignments.Where(assignment => assignment.Role.Code == PamRoleCodes.Admin
                    || assignment.Role.Code == PamRoleCodes.User || assignment.Role.Code == PamRoleCodes.Approver)
                    .OrderBy(assignment => assignment.Role.Code).Select(assignment => assignment.Role.Code).ToList())
            { Version = principal.Version }).SingleOrDefaultAsync(cancellationToken);
}
