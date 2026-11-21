using Application.Authorization;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Authorization;

internal static class AdministrativeAuthorization
{
    public static async Task<bool> LockAdministrationGuardAsync(PamDbContext database, CancellationToken cancellationToken) =>
        await database.PamRoles.FromSql($"SELECT * FROM pam_roles WHERE code = {PamRoleCodes.Admin} FOR UPDATE")
            .AsNoTracking().Select(role => role.Id).SingleOrDefaultAsync(cancellationToken) != 0;

    public static Task<bool> WouldRemoveLastAdminAsync(PamDbContext database, long targetId, CancellationToken cancellationToken) =>
        database.PamRoleAssignments.AnyAsync(assignment => assignment.PrincipalId == targetId
            && assignment.Principal.IsEnabled && assignment.Role.Code == PamRoleCodes.Admin
            && !database.PamInstallations.Any(installation => installation.BootstrapPrincipalId == targetId)
            && !database.Principals.Any(principal => principal.Id != targetId && principal.IsEnabled
                && !database.PamInstallations.Any(installation => installation.BootstrapPrincipalId == principal.Id)
                && principal.RoleAssignments.Any(role => role.Role.Code == PamRoleCodes.Admin)), cancellationToken);

    public static Task<bool> IsBootstrapPrincipalAsync(PamDbContext database, long principalId, CancellationToken cancellationToken) =>
        database.PamInstallations.AnyAsync(installation => installation.BootstrapPrincipalId == principalId, cancellationToken);

    public static async Task<AdministrativeDecision> CheckAsync(PamDbContext database, TimeProvider clock,
        AdministrativeActor actor, string permission, CancellationToken cancellationToken)
    {
        // The caller owns the transaction. Authorization readers share this lock;
        // role/status writers take its exclusive counterpart before changing grants.
        var principal = await database.Principals
            .FromSql($"SELECT *, xmin FROM principals WHERE id = {actor.Principal.Id} FOR SHARE")
            .AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        if (principal is null || !principal.IsEnabled || principal.PublicId != actor.Principal.PublicId
            || principal.Issuer != actor.Principal.Issuer || principal.Subject != actor.Principal.Subject)
        {
            return AdministrativeDecision.Forbidden;
        }

        var roles = PamPermissionRoles.For(permission);
        var installation = await database.PamInstallations.Where(value => value.BootstrapPrincipalId == principal.Id)
            .Select(value => new { value.CompletedAt }).SingleOrDefaultAsync(cancellationToken);
        if (installation is not null && (installation.CompletedAt is not null || !BootstrapPermissions.Allows(permission)))
        {
            return AdministrativeDecision.Forbidden;
        }
        if (!await database.PamRoleAssignments.AnyAsync(assignment => assignment.PrincipalId == principal.Id
            && roles.Contains(assignment.Role.Code), cancellationToken))
        {
            return AdministrativeDecision.Forbidden;
        }

        return RecentAuthentication.IsSatisfied(actor.AuthenticatedAt, clock.GetUtcNow())
            ? AdministrativeDecision.Allowed : AdministrativeDecision.RecentAuthenticationRequired;
    }
}

internal enum AdministrativeDecision
{
    Allowed,
    Forbidden,
    RecentAuthenticationRequired
}
