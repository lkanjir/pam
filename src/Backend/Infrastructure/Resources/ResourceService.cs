using Application.Resources;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Resources;

public class ResourceService(PamDbContext dbContext) : IResourceService
{
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
}
