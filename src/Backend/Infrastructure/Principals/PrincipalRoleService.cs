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

    public Task<PrincipalRoleWriteResult> AssignAsync(Guid principalId, string roleCode, ChangePrincipalRoleRequest request,
        AdministrativeActor actor, uint expectedVersion, string correlationId, CancellationToken cancellationToken = default) =>
        SetAssignedAsync(principalId, roleCode, request, actor, expectedVersion, correlationId, true, cancellationToken);

    public Task<PrincipalRoleWriteResult> RemoveAsync(Guid principalId, string roleCode, ChangePrincipalRoleRequest request,
        AdministrativeActor actor, uint expectedVersion, string correlationId, CancellationToken cancellationToken = default) =>
        SetAssignedAsync(principalId, roleCode, request, actor, expectedVersion, correlationId, false, cancellationToken);

    private async Task<PrincipalRoleWriteResult> SetAssignedAsync(Guid principalId, string roleCode, ChangePrincipalRoleRequest request,
        AdministrativeActor actor, uint expectedVersion, string correlationId, bool assigned, CancellationToken cancellationToken)
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
        if (!assigned && await AdministrativeAuthorization.IsBootstrapPrincipalAsync(database, actor.Principal.Id, cancellationToken))
        {
            return new(PrincipalWriteKind.Forbidden);
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
        if (await AdministrativeAuthorization.IsBootstrapPrincipalAsync(database, target.Id, cancellationToken))
        {
            return new(PrincipalWriteKind.BootstrapProtected);
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
        if (assigned && !target.IsEnabled)
        {
            return new(PrincipalWriteKind.TargetDisabled);
        }
        var before = await GetAsync(principalId, cancellationToken)
            ?? throw new InvalidOperationException("Locked principal was not found.");
        if (before.Roles.Contains(roleCode, StringComparer.Ordinal) == assigned)
        {
            return new(PrincipalWriteKind.Succeeded, before);
        }
        if (!assigned && roleCode == PamRoleCodes.Admin
            && await AdministrativeAuthorization.WouldRemoveLastAdminAsync(database, target.Id, cancellationToken))
        {
            return new(PrincipalWriteKind.LastAdmin);
        }
        var now = clock.GetUtcNow();
        if (assigned)
        {
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
        }
        else
        {
            await database.PamRoleAssignments.Where(value => value.PrincipalId == target.Id && value.Role.Code == roleCode)
                .ExecuteDeleteAsync(cancellationToken);
            var requesterRoles = PamPermissionRoles.For(PamPermissions.RequestsCreate);
            if (requesterRoles.Contains(roleCode, StringComparer.Ordinal)
                && !before.Roles.Any(code => code != roleCode && requesterRoles.Contains(code, StringComparer.Ordinal)))
            {
                await PrincipalAssignmentDeactivation.EligibilityAsync(database, target, actor, now, request.Reason.Trim(), correlationId, "supporting_role_removed", cancellationToken);
            }
            var readRoles = ResourceBindingRoles.For(ResourceBindingKind.ViewResource);
            if (readRoles.Contains(roleCode, StringComparer.Ordinal)
                && !before.Roles.Any(code => code != roleCode && readRoles.Contains(code, StringComparer.Ordinal)))
            {
                await PrincipalAssignmentDeactivation.ResourceBindingsAsync(database, target, actor, now, request.Reason.Trim(), correlationId, ResourceBindingKind.ViewResource, "supporting_role_removed", cancellationToken);
            }
            var approvalRoles = ResourceBindingRoles.For(ResourceBindingKind.ApproveRequests);
            if (approvalRoles.Contains(roleCode, StringComparer.Ordinal)
                && !before.Roles.Any(code => code != roleCode && approvalRoles.Contains(code, StringComparer.Ordinal)))
            {
                await PrincipalAssignmentDeactivation.ResourceBindingsAsync(database, target, actor, now, request.Reason.Trim(), correlationId, ResourceBindingKind.ApproveRequests, "supporting_role_removed", cancellationToken);
            }
        }
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
            EventType = assigned ? "role.assigned" : "role.removed",
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
            ReasonCode = assigned ? "role_assigned" : "role_removed"
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
