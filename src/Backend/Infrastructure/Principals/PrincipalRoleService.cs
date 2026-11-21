using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Application.Authorization;
using Application.Principals;
using Infrastructure.Authentication;
using Infrastructure.Authorization;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Infrastructure.Sessions;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Principals;

public sealed class PrincipalRoleService(PamDbContext database, TimeProvider clock, ISessionTicketStore tickets) : IPrincipalRoleService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<PrincipalRoleWriteResult> AssignAsync(Guid principalId, string roleCode, ChangePrincipalRoleRequest request,
        AdministrativeActor actor, uint expectedVersion, string correlationId, CancellationToken cancellationToken = default)
    {
        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        if (!await AdministrativeAuthorization.LockAdministrationGuardAsync(database, cancellationToken))
        {
            return new(PrincipalWriteKind.Forbidden);
        }
        var principals = await database.Principals.FromSql(
            $"SELECT *, xmin FROM principals WHERE id = {actor.Principal.Id} OR public_id = {principalId} ORDER BY id FOR UPDATE")
            .AsNoTracking().ToListAsync(cancellationToken);
        var decision = await AdministrativeAuthorization.CheckAsync(database, clock, actor, PamPermissions.RolesAssign, cancellationToken);
        if (decision != AdministrativeDecision.Allowed)
        {
            return new(decision == AdministrativeDecision.Forbidden
                ? PrincipalWriteKind.Forbidden : PrincipalWriteKind.RecentAuthenticationRequired);
        }
        var target = principals.SingleOrDefault(principal => principal.PublicId == principalId);
        if (target is null)
        {
            return new(PrincipalWriteKind.NotFound);
        }
        if (target.Id == actor.Principal.Id)
        {
            return new(PrincipalWriteKind.SelfChangeForbidden);
        }
        if (roleCode is not (PamRoleCodes.User or PamRoleCodes.Approver or PamRoleCodes.Admin)
            || !Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true))
        {
            return new(PrincipalWriteKind.InvalidRequest);
        }
        if (target.Version != expectedVersion)
        {
            return new(PrincipalWriteKind.PreconditionFailed);
        }
        if (!target.IsEnabled)
        {
            return new(PrincipalWriteKind.TargetDisabled);
        }
        var before = await GetAsync(principalId, cancellationToken)
            ?? throw new InvalidOperationException("Locked principal was not found.");
        if (before.Roles.Contains(roleCode, StringComparer.Ordinal))
        {
            return new(PrincipalWriteKind.Succeeded, before);
        }
        var now = clock.GetUtcNow();
        if (!await PrincipalSessionRevocation.RevokeBeforeRestorationAsync(database, tickets, clock, target.Id,
            now, correlationId, cancellationToken))
        {
            return new(PrincipalWriteKind.SessionCleanupPending);
        }
        var role = await database.PamRoles.SingleOrDefaultAsync(value => value.Code == roleCode, cancellationToken);
        if (role is null)
        {
            // Fixed catalog only: the administration guard serializes first use of a bundle.
            // This creates its descriptor, never a user-selected custom permission set.
            role = new PamRole { Code = roleCode, CreatedAt = now.UtcDateTime, CreatedByPrincipalId = actor.Principal.Id };
            database.PamRoles.Add(role);
        }
        database.PamRoleAssignments.Add(new PamRoleAssignment
        {
            PrincipalId = target.Id,
            Role = role,
            AssignedAt = now.UtcDateTime,
            AssignedByPrincipalId = actor.Principal.Id
        });
        int changed = await database.Principals.Where(value => value.Id == target.Id && value.Version == expectedVersion)
            .ExecuteUpdateAsync(update => update.SetProperty(value => value.ModifiedAt, now.UtcDateTime), cancellationToken);
        if (changed != 1)
        {
            return new(PrincipalWriteKind.PreconditionFailed);
        }
        await database.SaveChangesAsync(cancellationToken);
        var after = await GetAsync(principalId, cancellationToken)
            ?? throw new InvalidOperationException("Locked principal was not found.");
        database.AuditEvents.Add(new AuditEvent
        {
            EventType = "role.assigned",
            SchemaVersion = 1,
            OccurredAt = now.UtcDateTime,
            ActorKind = "principal",
            ActorPrincipalId = actor.Principal.Id,
            SubjectPrincipalId = target.Id,
            ActorSnapshot = JsonSerializer.Serialize(actor.Principal, JsonOptions),
            SubjectSnapshot = JsonSerializer.Serialize(new { target.PublicId, target.Issuer, target.Subject, target.DisplayName }, JsonOptions),
            Metadata = JsonSerializer.Serialize(new { roleCode, before = before.Roles, after = after.Roles, reason = request.Reason.Trim() }, JsonOptions),
            CorrelationId = correlationId,
            Source = "pam.api",
            Outcome = "success",
            ReasonCode = "role_assigned"
        });
        await database.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(PrincipalWriteKind.Succeeded, after);
    }

    public Task<PrincipalRolesResponse?> GetAsync(Guid principalId, CancellationToken cancellationToken = default) =>
        database.Principals.AsNoTracking().Where(principal => principal.PublicId == principalId)
            .Select(principal => new PrincipalRolesResponse(principal.PublicId,
                principal.RoleAssignments.Where(assignment => assignment.Role.Code == PamRoleCodes.Admin
                    || assignment.Role.Code == PamRoleCodes.User || assignment.Role.Code == PamRoleCodes.Approver)
                    .OrderBy(assignment => assignment.Role.Code).Select(assignment => assignment.Role.Code).ToList())
            { Version = principal.Version }).SingleOrDefaultAsync(cancellationToken);
}
