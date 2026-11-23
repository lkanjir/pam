using Application.Identity;
using Infrastructure.Persistence;
using Infrastructure.Persistence.RawDatabaseTypes;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Identity;

public sealed class PrincipalIdentityReader(PamDbContext dbContext) : IPrincipalIdentityReader
{
    public async Task<PrincipalIdentity?> FindAsync(string issuer, string subject,
        CancellationToken cancellationToken = default)
    {
        var rows = await dbContext.Database.SqlQuery<PrincipalRoleRow>(
            $"""
                 WITH matched_principals  AS (
                     SELECT p.id, p.public_id, p.display_name,
                         p.is_enabled AND (i.completed_at IS NULL) AS is_enabled,
                         i.bootstrap_principal_id IS NOT NULL AS is_bootstrap
                     FROM principals p
                     LEFT JOIN pam_installation i ON i.bootstrap_principal_id = p.id
                     WHERE p.issuer = {issuer} AND p.subject = {subject}
                 )
                 SELECT 
                     p.id,
                     p.public_id,
                     p.display_name,
                     p.is_enabled,
                     p.is_bootstrap,
                     r.code AS role_code
                 FROM matched_principals p
                 LEFT JOIN pam_role_assignments a ON a.principal_id = p.id
                 LEFT JOIN pam_roles r ON r.id = a.role_id
                 ORDER BY r.code                    
             """).ToListAsync(cancellationToken);

        if (rows.Count == 0)
        {
            return null;
        }

        var principal = rows[0];
        var roles = rows.Select(row => row.RoleCode).OfType<string>().ToArray();

        return new PrincipalIdentity(principal.Id, principal.PublicId, principal.DisplayName, principal.IsEnabled,
            roles)
        { IsBootstrap = principal.IsBootstrap };
    }
}
