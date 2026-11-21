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

public sealed class ResourceAccessService(PamDbContext database, TimeProvider clock) : IResourceAccessService, IApprovalAuthorityService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public Task<ResourceAccessWriteResult> AssignAsync(Guid principalId, Guid resourceId, ChangeResourceAccessRequest request,
        AdministrativeActor actor, uint expectedVersion, string correlationId, CancellationToken cancellationToken = default) =>
        SetAssignedAsync(principalId, resourceId, request, actor, expectedVersion, correlationId, ResourceBindingKind.ViewResource, true, cancellationToken);

    public Task<ResourceAccessWriteResult> RevokeAsync(Guid principalId, Guid resourceId, ChangeResourceAccessRequest request,
        AdministrativeActor actor, uint expectedVersion, string correlationId, CancellationToken cancellationToken = default) =>
        SetAssignedAsync(principalId, resourceId, request, actor, expectedVersion, correlationId, ResourceBindingKind.ViewResource, false, cancellationToken);

    Task<ResourceAccessWriteResult> IApprovalAuthorityService.AssignAsync(Guid principalId, Guid resourceId,
        ChangeResourceAccessRequest request, AdministrativeActor actor, uint expectedVersion, string correlationId,
        CancellationToken cancellationToken) =>
        SetAssignedAsync(principalId, resourceId, request, actor, expectedVersion, correlationId, ResourceBindingKind.ApproveRequests, true, cancellationToken);

    private async Task<ResourceAccessWriteResult> SetAssignedAsync(Guid principalId, Guid resourceId, ChangeResourceAccessRequest request,
        AdministrativeActor actor, uint expectedVersion, string correlationId, ResourceBindingKind kind, bool assigned,
        CancellationToken cancellationToken)
    {
        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        var principals = await database.Principals.FromSql(
            $"SELECT *, xmin FROM principals WHERE id = {actor.Principal.Id} OR public_id = {principalId} ORDER BY id FOR UPDATE")
            .AsNoTracking().ToListAsync(cancellationToken);
        string permission = kind == ResourceBindingKind.ViewResource ? PamPermissions.ResourceAccessAssign : PamPermissions.ApprovalAuthorityAssign;
        var decision = await AdministrativeAuthorization.CheckAsync(database, clock, actor, permission, cancellationToken);
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
        if (kind == ResourceBindingKind.ApproveRequests && target.Id == actor.Principal.Id)
        {
            return new(PrincipalWriteKind.SelfChangeForbidden);
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
            var supportedRoles = ResourceBindingRoles.For(kind);
            if (!await database.PamRoleAssignments.AnyAsync(assignment => assignment.PrincipalId == target.Id
                && supportedRoles.Contains(assignment.Role.Code), cancellationToken))
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
        var binding = await database.ResourcePrincipalBindings.IgnoreQueryFilters().AsNoTracking()
            .SingleOrDefaultAsync(value => value.PrincipalId == target.Id && value.ResourceId == resource.Id
                && value.Kind == kind, cancellationToken);
        if ((binding is { IsActive: true }) == assigned)
        {
            return new(PrincipalWriteKind.Succeeded, target.Version);
        }
        var now = clock.GetUtcNow();
        Guid bindingId = binding?.PublicId ?? Guid.CreateVersion7(now);
        if (binding is null)
        {
            database.ResourcePrincipalBindings.Add(new ResourcePrincipalBinding
            {
                PublicId = bindingId,
                PrincipalId = target.Id,
                ResourceId = resource.Id,
                Kind = kind,
                AssignedAt = now.UtcDateTime,
                AssignedByPrincipalId = actor.Principal.Id,
                ModifiedAt = now.UtcDateTime,
                ModifiedByPrincipalId = actor.Principal.Id
            });
        }
        else
        {
            int bindingChanged = await database.ResourcePrincipalBindings.IgnoreQueryFilters()
                .Where(value => value.Id == binding.Id && value.Version == binding.Version)
                .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsActive, assigned)
                    .SetProperty(value => value.ModifiedAt, now.UtcDateTime)
                    .SetProperty(value => value.ModifiedByPrincipalId, actor.Principal.Id), cancellationToken);
            if (bindingChanged != 1)
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
            EventType = (kind == ResourceBindingKind.ViewResource ? "resource_access" : "approval_authority")
                + (assigned ? ".granted" : ".revoked"),
            SchemaVersion = 1,
            OccurredAt = now.UtcDateTime,
            ActorKind = "principal",
            ActorPrincipalId = actor.Principal.Id,
            SubjectPrincipalId = target.Id,
            ResourceId = resource.Id,
            ActorSnapshot = JsonSerializer.Serialize(actor.Principal, JsonOptions),
            SubjectSnapshot = JsonSerializer.Serialize(new { target.PublicId, target.Issuer, target.Subject, target.DisplayName }, JsonOptions),
            ResourceSnapshot = JsonSerializer.Serialize(new { resource.PublicId, resource.Name, resource.IsActive }, JsonOptions),
            Metadata = JsonSerializer.Serialize(new { bindingId, before = !assigned, after = assigned, reason = request.Reason.Trim() }, JsonOptions),
            CorrelationId = correlationId,
            Source = "pam.api",
            Outcome = "success",
            ReasonCode = kind == ResourceBindingKind.ViewResource
                ? assigned ? "visibility_granted" : "visibility_revoked"
                : assigned ? "approval_authority_granted" : "approval_authority_revoked"
        });
        await database.SaveChangesAsync(cancellationToken);
        uint version = await database.Principals.Where(value => value.Id == target.Id).Select(value => value.Version).SingleAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(PrincipalWriteKind.Succeeded, version);
    }

    public Task<ResourceAccessPage?> ListAsync(Guid principalId, int limit, ResourceCursor? cursor,
        CancellationToken cancellationToken = default) =>
        ListBindingsAsync(principalId, limit, cursor, ResourceBindingKind.ViewResource, cancellationToken);

    Task<ResourceAccessPage?> IApprovalAuthorityService.ListAsync(Guid principalId, int limit, ResourceCursor? cursor,
        CancellationToken cancellationToken) =>
        ListBindingsAsync(principalId, limit, cursor, ResourceBindingKind.ApproveRequests, cancellationToken);

    private async Task<ResourceAccessPage?> ListBindingsAsync(Guid principalId, int limit, ResourceCursor? cursor,
        ResourceBindingKind kind, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, 100);
        // Administrative inspection deliberately retains retired parents and inactive bindings.
        var bindings = from binding in database.ResourcePrincipalBindings.IgnoreQueryFilters()
                       join resource in database.ManagedResources.IgnoreQueryFilters() on binding.ResourceId equals resource.Id
                       where binding.Kind == kind
                       select new { Binding = binding, Resource = resource };
        if (cursor is not null)
        {
            Guid lastId = cursor.LastPublicId;
            bindings = bindings.Where(item => item.Resource.PublicId.CompareTo(lastId) > 0);
        }
        // One SQL statement gives the page and its parent version the same MVCC snapshot.
        var result = await database.Principals.AsNoTracking().AsSingleQuery().Where(principal => principal.PublicId == principalId)
            .Select(principal => new
            {
                principal.Version,
                Items = bindings.Where(item => item.Binding.PrincipalId == principal.Id)
                    .OrderBy(item => item.Resource.PublicId).Take(limit + 1)
                    .Select(item => new ResourceAccessResponse(item.Binding.PublicId, item.Resource.PublicId,
                        item.Resource.Name, item.Binding.IsActive, item.Resource.DeletedAt != null,
                        new DateTimeOffset(item.Binding.AssignedAt, TimeSpan.Zero),
                        new DateTimeOffset(item.Binding.ModifiedAt, TimeSpan.Zero))).ToList()
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
        return new(new(result.Items, hasMore ? CursorCodec.Encode(new ResourceCursor(result.Items[^1].ResourceId)) : null), result.Version);
    }
}
