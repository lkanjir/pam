using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Application.Authorization;
using Application.Common.Pagination;
using Application.Principals;
using Application.Resources;
using Infrastructure.Authorization;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Principals;

public sealed class EligibilityService(PamDbContext database, TimeProvider clock) : IEligibilityService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public Task<EligibilityWriteResult> AssignAsync(Guid principalId, Guid resourceId, Guid entitlementId,
        ChangeEligibilityRequest request, AdministrativeActor actor, uint expectedVersion, string correlationId,
        CancellationToken cancellationToken = default) =>
        SetAssignedAsync(principalId, resourceId, entitlementId, request, actor, expectedVersion, correlationId, true, cancellationToken);

    public Task<EligibilityWriteResult> RevokeAsync(Guid principalId, Guid resourceId, Guid entitlementId,
        ChangeEligibilityRequest request, AdministrativeActor actor, uint expectedVersion, string correlationId,
        CancellationToken cancellationToken = default) =>
        SetAssignedAsync(principalId, resourceId, entitlementId, request, actor, expectedVersion, correlationId, false, cancellationToken);

    private async Task<EligibilityWriteResult> SetAssignedAsync(Guid principalId, Guid resourceId, Guid entitlementId,
        ChangeEligibilityRequest request, AdministrativeActor actor, uint expectedVersion, string correlationId,
        bool assigned, CancellationToken cancellationToken)
    {
        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        var principals = await database.Principals.FromSql(
            $"SELECT *, xmin FROM principals WHERE id = {actor.Principal.Id} OR public_id = {principalId} ORDER BY id FOR UPDATE")
            .AsNoTracking().ToListAsync(cancellationToken);
        var decision = await AdministrativeAuthorization.CheckAsync(database, clock, actor, PamPermissions.EligibilityAssign, cancellationToken);
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
        if (!Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true))
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
        if (assigned)
        {
            var requesterRoles = PamPermissionRoles.For(PamPermissions.RequestsCreate);
            if (!await database.PamRoleAssignments.AnyAsync(assignment => assignment.PrincipalId == target.Id
                && requesterRoles.Contains(assignment.Role.Code), cancellationToken))
            {
                return new(PrincipalWriteKind.TargetMissingCapability);
            }
        }
        var resource = await database.ManagedResources.FromSql(
            $"SELECT *, xmin FROM managed_resources WHERE public_id = {resourceId} FOR UPDATE")
            .IgnoreQueryFilters().AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        if (resource is null || (assigned && resource.DeletedAt != null))
        {
            return new(PrincipalWriteKind.NotFound);
        }
        var entitlement = await database.Entitlements.IgnoreQueryFilters().AsNoTracking()
            .SingleOrDefaultAsync(value => value.PublicId == entitlementId && value.ResourceId == resource.Id, cancellationToken);
        if (entitlement is null)
        {
            return new(PrincipalWriteKind.NotFound);
        }
        var rule = await database.EligibilityRules.IgnoreQueryFilters().AsNoTracking()
            .SingleOrDefaultAsync(value => value.PrincipalId == target.Id && value.EntitlementId == entitlement.Id, cancellationToken);
        if ((rule is { IsEnabled: true }) == assigned)
        {
            return new(PrincipalWriteKind.Succeeded, target.Version);
        }
        var now = clock.GetUtcNow();
        Guid eligibilityId = rule?.PublicId ?? Guid.CreateVersion7(now);
        if (rule is null)
        {
            database.EligibilityRules.Add(new EligibilityRule
            {
                PublicId = eligibilityId,
                PrincipalId = target.Id,
                EntitlementId = entitlement.Id,
                IsEnabled = true,
                CreatedAt = now.UtcDateTime
            });
        }
        else
        {
            int ruleChanged = await database.EligibilityRules.IgnoreQueryFilters().Where(value => value.Id == rule.Id)
                .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, assigned), cancellationToken);
            if (ruleChanged != 1)
            {
                return new(PrincipalWriteKind.PreconditionFailed);
            }
        }
        int changed = await database.Principals.Where(value => value.Id == target.Id && value.Version == expectedVersion)
            .ExecuteUpdateAsync(update => update.SetProperty(value => value.ModifiedAt, now.UtcDateTime), cancellationToken);
        if (changed != 1)
        {
            return new(PrincipalWriteKind.PreconditionFailed);
        }
        database.AuditEvents.Add(new AuditEvent
        {
            EventType = assigned ? "eligibility.granted" : "eligibility.revoked",
            SchemaVersion = 1,
            OccurredAt = now.UtcDateTime,
            ActorKind = "principal",
            ActorPrincipalId = actor.Principal.Id,
            SubjectPrincipalId = target.Id,
            ResourceId = resource.Id,
            EntitlementId = entitlement.Id,
            ActorSnapshot = JsonSerializer.Serialize(actor.Principal, JsonOptions),
            SubjectSnapshot = JsonSerializer.Serialize(new { target.PublicId, target.Issuer, target.Subject, target.DisplayName }, JsonOptions),
            ResourceSnapshot = JsonSerializer.Serialize(new { resource.PublicId, resource.Name, resource.IsActive }, JsonOptions),
            EntitlementSnapshot = JsonSerializer.Serialize(new { entitlement.PublicId, entitlement.Code, entitlement.Name, entitlement.IsActive }, JsonOptions),
            Metadata = JsonSerializer.Serialize(new { eligibilityId, before = !assigned, after = assigned, reason = request.Reason.Trim() }, JsonOptions),
            CorrelationId = correlationId,
            Source = "pam.api",
            Outcome = "success",
            ReasonCode = assigned ? "eligibility_granted" : "eligibility_revoked"
        });
        await database.SaveChangesAsync(cancellationToken);
        uint version = await database.Principals.Where(value => value.Id == target.Id).Select(value => value.Version).SingleAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(PrincipalWriteKind.Succeeded, version);
    }

    public async Task<EligibilityPage?> ListAsync(Guid principalId, int limit, EntitlementCursor? cursor,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, 100);
        // Administration retains disabled rules and retired parents for explicit review/removal.
        var rules = from rule in database.EligibilityRules.IgnoreQueryFilters()
                    join entitlement in database.Entitlements.IgnoreQueryFilters() on rule.EntitlementId equals entitlement.Id
                    join resource in database.ManagedResources.IgnoreQueryFilters() on entitlement.ResourceId equals resource.Id
                    select new { Rule = rule, Entitlement = entitlement, Resource = resource };
        if (cursor is not null)
        {
            Guid lastId = cursor.LastPublicId;
            rules = rules.Where(item => item.Entitlement.PublicId.CompareTo(lastId) > 0);
        }
        var result = await database.Principals.AsNoTracking().AsSingleQuery().Where(principal => principal.PublicId == principalId)
            .Select(principal => new
            {
                principal.Version,
                Items = rules.Where(item => item.Rule.PrincipalId == principal.Id)
                    .OrderBy(item => item.Entitlement.PublicId).Take(limit + 1)
                    .Select(item => new EligibilityResponse(item.Rule.PublicId, item.Resource.PublicId, item.Resource.Name,
                        item.Entitlement.PublicId, item.Entitlement.Code, item.Entitlement.Name, item.Rule.IsEnabled,
                        item.Resource.IsActive, item.Resource.DeletedAt != null, item.Entitlement.IsActive,
                        new DateTimeOffset(item.Rule.CreatedAt, TimeSpan.Zero))).ToList()
            }).SingleOrDefaultAsync(cancellationToken);
        if (result is null)
        {
            return null;
        }
        bool hasMore = result.Items.Count > limit;
        if (hasMore)
        {
            result.Items.RemoveAt(limit);
        }
        return new(new(result.Items, hasMore ? CursorCodec.Encode(new EntitlementCursor(result.Items[^1].EntitlementId)) : null), result.Version);
    }
}
