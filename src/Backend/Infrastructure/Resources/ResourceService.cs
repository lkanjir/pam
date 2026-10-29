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

        var audit = new AuditEvent
        {
            EventType = "resource.created",
            SchemaVersion = 1,
            OccurredAt = now.UtcDateTime,
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
                    createdAt = now.UtcDateTime,
                    modifiedAt = now.UtcDateTime,
                },
                AuditJsonOptions),
            CorrelationId = correlationId,
            Source = "pam.api",
            Outcome = "success"
        };

        dbContext.ManagedResources.Add(resource);
        dbContext.AuditEvents.Add(audit);

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
}
