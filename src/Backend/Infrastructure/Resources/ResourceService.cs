using System.Text.Json;
using Application.Common.Pagination;
using Application.Resources;
using Application.Sessions;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Resources;

public sealed class ResourceService(PamDbContext dbContext, TimeProvider timeProvider) : IResourceService
{
    private static readonly JsonSerializerOptions AuditJsonOptions = new(JsonSerializerDefaults.Web);

    public Task<ResourceResponse?> GetByIdAsync(Guid publicId, CancellationToken cancellationToken = default)
    {
        return dbContext.ManagedResources.AsNoTracking().Where(resource => resource.PublicId == publicId)
            .Select(resource => new ResourceResponse(
                resource.PublicId,
                resource.Name,
                resource.Description,
                resource.ResourceType,
                resource.Environment,
                resource.IsActive,
                resource.CreatedAt,
                resource.ModifiedAt))
            .SingleOrDefaultAsync(cancellationToken);
    }

    public async Task<ResourceResponse> CreateAsync(
        CreateResourceRequest request,
        PrincipalSnapshot actor,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
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
            CreatedByPrincipalId = actor.Id,
            ModifiedAt = now.UtcDateTime,
            ModifiedByPrincipalId = actor.Id
        };

        dbContext.ManagedResources.Add(resource);
        dbContext.AuditEvents.Add(CreateAuditEvent(
            "resource.created", resource, actor, now.UtcDateTime, correlationId));

        await dbContext.SaveChangesAsync(cancellationToken);

        return new ResourceResponse(
            resource.PublicId,
            resource.Name,
            resource.Description,
            resource.ResourceType,
            resource.Environment,
            resource.IsActive,
            resource.CreatedAt,
            resource.ModifiedAt);
    }

    public async Task<ResourceResponse?> UpdateAsync(
        Guid publicId,
        UpdateResourceRequest request,
        PrincipalSnapshot actor,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        var resource = await dbContext.ManagedResources
            .SingleOrDefaultAsync(resource => resource.PublicId == publicId, cancellationToken);

        if (resource is null)
        {
            return null;
        }

        var now = timeProvider.GetUtcNow();
        resource.Name = request.Name.Trim();
        resource.Description = request.Description?.Trim();
        resource.ResourceType = request.ResourceType.Trim();
        resource.Environment = request.Environment.Trim();
        resource.IsActive = request.IsActive;
        resource.ModifiedAt = now.UtcDateTime;
        resource.ModifiedByPrincipalId = actor.Id;

        dbContext.AuditEvents.Add(CreateAuditEvent(
            "resource.updated", resource, actor, now.UtcDateTime, correlationId));

        await dbContext.SaveChangesAsync(cancellationToken);

        return new ResourceResponse(
            resource.PublicId,
            resource.Name,
            resource.Description,
            resource.ResourceType,
            resource.Environment,
            resource.IsActive,
            resource.CreatedAt,
            resource.ModifiedAt);
    }

    public async Task<bool> DeleteAsync(
        Guid publicId,
        PrincipalSnapshot actor,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        var resource = await dbContext.ManagedResources
            .SingleOrDefaultAsync(resource => resource.PublicId == publicId, cancellationToken);

        if (resource is null)
        {
            return false;
        }

        var now = timeProvider.GetUtcNow();
        resource.DeletedAt = now.UtcDateTime;
        resource.IsActive = false;
        resource.ModifiedAt = now.UtcDateTime;
        resource.ModifiedByPrincipalId = actor.Id;

        dbContext.AuditEvents.Add(CreateAuditEvent(
            "resource.deleted", resource, actor, now.UtcDateTime, correlationId));

        await dbContext.SaveChangesAsync(cancellationToken);

        return true;
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
