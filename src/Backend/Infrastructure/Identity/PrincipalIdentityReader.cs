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
                     SELECT id, public_id, display_name, is_enabled
                     FROM principals
                     WHERE issuer = {issuer} AND subject = {subject}
                 )
                 SELECT 
                     p.id AS "Id",
                     p.public_id AS "PublicId",
                     p.display_name AS "DisplayName",
                     p.is_enabled AS "IsEnabled",
                     r.code AS "RoleCode"
                 FROM matched_principals p
                 LEFT JOIN pam_role_assignments a ON a.principal_id = p.id
                 LEFT JOIN pam_roles r ON r.id = a.role_id
                 ORDER BY r.code                    
             """).ToListAsync(cancellationToken);

        if (rows.Count == 0) return null;

        var principal = rows[0];
        var roles = rows.Select(row => row.RoleCode).OfType<string>().ToArray();

        return new PrincipalIdentity(principal.Id, principal.PublicId, principal.DisplayName, principal.IsEnabled,
            roles);
    }
}