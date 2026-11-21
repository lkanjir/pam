using System.Text.Json;
using Application.Authorization;
using Application.Common.Pagination;
using Application.Resources;
using Application.Sessions;
using Infrastructure.Authorization;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Resources;

public sealed class ResourceService(PamDbContext dbContext, TimeProvider timeProvider) : IResourceService
{
    private static readonly JsonSerializerOptions AuditJsonOptions = new(JsonSerializerDefaults.Web);

    public Task<ResourceResponse?> GetByIdAsync(Guid publicId, CancellationToken cancellationToken = default) =>
        Project(dbContext.ManagedResources.Where(resource => resource.PublicId == publicId))
            .SingleOrDefaultAsync(cancellationToken);

    public Task<ResourceResponse?> GetScopedByIdAsync(Guid publicId, long principalId, CancellationToken cancellationToken = default) =>
        Project(ResourceScopedAuthorization.VisibleResources(dbContext, principalId).Where(resource => resource.PublicId == publicId))
            .SingleOrDefaultAsync(cancellationToken);

    private static IQueryable<ResourceResponse> Project(IQueryable<ManagedResource> resources) =>
        resources.AsNoTracking().Select(resource => new ResourceResponse(
            resource.PublicId, resource.Name, resource.Description, resource.ResourceType, resource.Environment,
            resource.IsActive, resource.CreatedAt, resource.ModifiedAt)
        { Version = resource.Version });

    public async Task<ResourceWriteResult> CreateAsync(
        CreateResourceRequest request,
        AdministrativeActor actor,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
        var authorization = await AdministrativeAuthorization.CheckAsync(
            dbContext, timeProvider, actor, PamPermissions.ResourcesManage, cancellationToken);
        if (authorization != AdministrativeDecision.Allowed)
        {
            return new(authorization == AdministrativeDecision.Forbidden
                ? ResourceWriteKind.Forbidden : ResourceWriteKind.RecentAuthenticationRequired);
        }

        var now = timeProvider.GetUtcNow();

        var resource = new ManagedResource
        {
            PublicId = Guid.CreateVersion7(now),
            Name = request.Name.Trim(),
            Description = request.Description?.Trim(),
            ResourceType = request.ResourceType.Trim(),
            Environment = request.Environment.Trim(),
            IsActive = request.IsActive,
            CreatedAt = now.UtcDateTime,
            CreatedByPrincipalId = actor.Principal.Id,
            ModifiedAt = now.UtcDateTime,
            ModifiedByPrincipalId = actor.Principal.Id
        };

        dbContext.ManagedResources.Add(resource);
        dbContext.AuditEvents.Add(CreateAuditEvent(
            "resource.created", resource, actor.Principal, now.UtcDateTime, correlationId));

        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new(ResourceWriteKind.Succeeded, new ResourceResponse(
            resource.PublicId,
            resource.Name,
            resource.Description,
            resource.ResourceType,
            resource.Environment,
            resource.IsActive,
            resource.CreatedAt,
            resource.ModifiedAt));
    }

    public async Task<ResourceWriteResult> UpdateAsync(
        Guid publicId,
        UpdateResourceRequest request,
        AdministrativeActor actor,
        string correlationId,
        uint expectedVersion,
        CancellationToken cancellationToken = default)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
        var authorization = await AdministrativeAuthorization.CheckAsync(
            dbContext, timeProvider, actor, PamPermissions.ResourcesManage, cancellationToken);
        if (authorization != AdministrativeDecision.Allowed)
        {
            return new(authorization == AdministrativeDecision.Forbidden
                ? ResourceWriteKind.Forbidden : ResourceWriteKind.RecentAuthenticationRequired);
        }

        var resource = await dbContext.ManagedResources
            .SingleOrDefaultAsync(resource => resource.PublicId == publicId, cancellationToken);

        if (resource is null)
        {
            return new(ResourceWriteKind.NotFound);
        }

        if (resource.Version != expectedVersion)
        {
            return new(ResourceWriteKind.Conflict);
        }

        var now = timeProvider.GetUtcNow();
        resource.Name = request.Name.Trim();
        resource.Description = request.Description?.Trim();
        resource.ResourceType = request.ResourceType.Trim();
        resource.Environment = request.Environment.Trim();
        resource.IsActive = request.IsActive;
        resource.ModifiedAt = now.UtcDateTime;
        resource.ModifiedByPrincipalId = actor.Principal.Id;
        dbContext.Entry(resource).Property(item => item.ModifiedAt).IsModified = true;

        dbContext.AuditEvents.Add(CreateAuditEvent(
            "resource.updated", resource, actor.Principal, now.UtcDateTime, correlationId));

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            return new(ResourceWriteKind.Conflict);
        }

        await transaction.CommitAsync(cancellationToken);

        return new(ResourceWriteKind.Succeeded, new ResourceResponse(
            resource.PublicId,
            resource.Name,
            resource.Description,
            resource.ResourceType,
            resource.Environment,
            resource.IsActive,
            resource.CreatedAt,
            resource.ModifiedAt)
        {
            Version = resource.Version
        });
    }

    public async Task<ResourceWriteKind> DeleteAsync(
        Guid publicId,
        AdministrativeActor actor,
        string correlationId,
        uint expectedVersion,
        CancellationToken cancellationToken = default)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
        var authorization = await AdministrativeAuthorization.CheckAsync(
            dbContext, timeProvider, actor, PamPermissions.ResourcesManage, cancellationToken);
        if (authorization != AdministrativeDecision.Allowed)
        {
            return authorization == AdministrativeDecision.Forbidden
                ? ResourceWriteKind.Forbidden : ResourceWriteKind.RecentAuthenticationRequired;
        }

        var resource = await dbContext.ManagedResources
            .SingleOrDefaultAsync(resource => resource.PublicId == publicId, cancellationToken);

        if (resource is null)
        {
            return ResourceWriteKind.NotFound;
        }

        if (resource.Version != expectedVersion)
        {
            return ResourceWriteKind.Conflict;
        }

        var now = timeProvider.GetUtcNow();
        resource.DeletedAt = now.UtcDateTime;
        resource.IsActive = false;
        resource.ModifiedAt = now.UtcDateTime;
        resource.ModifiedByPrincipalId = actor.Principal.Id;

        dbContext.AuditEvents.Add(CreateAuditEvent(
            "resource.deleted", resource, actor.Principal, now.UtcDateTime, correlationId));

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            return ResourceWriteKind.Conflict;
        }

        await transaction.CommitAsync(cancellationToken);
        return ResourceWriteKind.Succeeded;
    }

    public async Task<CursorPage<ResourceResponse>> ListAsync(
        int limit,
        ResourceCursor? cursor,
        CancellationToken cancellationToken = default)
    {
        var resources = dbContext.ManagedResources.AsNoTracking();

        if (cursor is not null)
        {
            Guid lastPublicId = cursor.LastPublicId;

            resources = resources.Where(
                resource => resource.PublicId.CompareTo(lastPublicId) > 0);
        }

        var items = await resources
            .OrderBy(resource => resource.PublicId)
            .Select(resource => new ResourceResponse(
                resource.PublicId,
                resource.Name,
                resource.Description,
                resource.ResourceType,
                resource.Environment,
                resource.IsActive,
                resource.CreatedAt,
                resource.ModifiedAt))
            .Take(limit + 1)
            .ToListAsync(cancellationToken);

        bool hasNextPage = items.Count > limit;

        if (hasNextPage)
        {
            items.RemoveAt(limit);
        }

        string? nextCursor = hasNextPage
            ? CursorCodec.Encode(new ResourceCursor(items[^1].Id))
            : null;

        return new CursorPage<ResourceResponse>(items, nextCursor);
    }

    public async Task<CursorPage<ResourceResponse>> ListRequestableAsync(
        long principalId,
        int limit,
        ResourceCursor? cursor,
        CancellationToken cancellationToken = default)
    {
        var entitlements = dbContext.Entitlements.Where(entitlement => entitlement.IsActive
            && entitlement.EligibilityRules.Any(rule => rule.PrincipalId == principalId && rule.IsEnabled));

        var resources = ResourceScopedAuthorization.RequesterResources(dbContext, principalId).Where(resource => resource.IsActive
            && entitlements.Any(entitlement => entitlement.ResourceId == resource.Id));

        if (cursor is not null)
        {
            Guid lastPublicId = cursor.LastPublicId;
            resources = resources.Where(resource => resource.PublicId.CompareTo(lastPublicId) > 0);
        }

        var items = await resources
            .OrderBy(resource => resource.PublicId)
            .Take(limit + 1)
            .Select(resource => new ResourceResponse(
                resource.PublicId,
                resource.Name,
                resource.Description,
                resource.ResourceType,
                resource.Environment,
                resource.IsActive,
                resource.CreatedAt,
                resource.ModifiedAt)
            {
                Entitlements = entitlements
                    .Where(entitlement => entitlement.ResourceId == resource.Id)
                    .OrderBy(entitlement => entitlement.PublicId)
                    .Select(entitlement => new RequestableEntitlementResponse(
                        entitlement.PublicId,
                        entitlement.Code,
                        entitlement.Name,
                        entitlement.MaxDurationMinutes,
                        entitlement.RequiresApproval,
                        entitlement.RequiresTicket))
                    .ToList()
            })
            .ToListAsync(cancellationToken);

        bool hasNextPage = items.Count > limit;
        if (hasNextPage)
        {
            items.RemoveAt(limit);
        }

        string? nextCursor = hasNextPage
            ? CursorCodec.Encode(new ResourceCursor(items[^1].Id))
            : null;

        return new CursorPage<ResourceResponse>(items, nextCursor);
    }

    private static AuditEvent CreateAuditEvent(
        string eventType,
        ManagedResource resource,
        PrincipalSnapshot actor,
        DateTime occurredAt,
        string correlationId) => new()
        {
            EventType = eventType,
            SchemaVersion = 1,
            OccurredAt = occurredAt,
            ActorKind = "principal",
            ActorPrincipalId = actor.Id,
            ActorSnapshot = JsonSerializer.Serialize(actor, AuditJsonOptions),
            Resource = resource,
            ResourceSnapshot = JsonSerializer.Serialize(
            new
            {
                publicId = resource.PublicId,
                name = resource.Name,
                description = resource.Description,
                resourceType = resource.ResourceType,
                environment = resource.Environment,
                isActive = resource.IsActive,
                createdAt = resource.CreatedAt,
                createdByPrincipalId = resource.CreatedByPrincipalId,
                modifiedAt = resource.ModifiedAt,
                modifiedByPrincipalId = resource.ModifiedByPrincipalId,
                deletedAt = resource.DeletedAt
            },
            AuditJsonOptions),
            CorrelationId = correlationId,
            Source = "pam.api",
            Outcome = "success"
        };
}
