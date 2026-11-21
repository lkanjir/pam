using Application.Authorization;
using Application.Common.Pagination;
using Application.Principals;
using Application.Resources;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Principals;

public sealed class ResourceAccessService(PamDbContext database) : IResourceAccessService
{
    public async Task<ResourceAccessPage?> ListAsync(Guid principalId, int limit, ResourceCursor? cursor,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, 100);
        // Administrative inspection deliberately retains retired parents and inactive bindings.
        var bindings = from binding in database.ResourcePrincipalBindings.IgnoreQueryFilters()
                       join resource in database.ManagedResources.IgnoreQueryFilters() on binding.ResourceId equals resource.Id
                       where binding.Kind == ResourceBindingKind.ViewResource
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
