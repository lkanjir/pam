using Application.Common.Pagination;
using Application.Principals;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Principals;

public sealed class PrincipalAdministrationService(PamDbContext database) : IPrincipalAdministrationService
{
    public Task<PrincipalResponse?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        database.Principals.AsNoTracking().Where(principal => principal.PublicId == id)
            .Select(principal => new PrincipalResponse(principal.PublicId, principal.Issuer, principal.Subject,
                principal.DisplayName, principal.IsEnabled, new DateTimeOffset(principal.CreatedAt, TimeSpan.Zero),
                new DateTimeOffset(principal.ModifiedAt, TimeSpan.Zero)))
            .SingleOrDefaultAsync(cancellationToken);

    public async Task<CursorPage<PrincipalResponse>> ListAsync(int limit, PrincipalCursor? cursor,
        CancellationToken cancellationToken = default)
    {
        var query = database.Principals.AsNoTracking();
        if (cursor is not null)
        {
            Guid lastId = cursor.LastPublicId;
            query = query.Where(principal => principal.PublicId.CompareTo(lastId) > 0);
        }
        var items = await query.OrderBy(principal => principal.PublicId).Take(limit + 1)
            .Select(principal => new PrincipalResponse(principal.PublicId, principal.Issuer, principal.Subject,
                principal.DisplayName, principal.IsEnabled, new DateTimeOffset(principal.CreatedAt, TimeSpan.Zero),
                new DateTimeOffset(principal.ModifiedAt, TimeSpan.Zero)))
            .ToListAsync(cancellationToken);
        bool hasMore = items.Count > limit;
        if (hasMore)
        {
            items.RemoveAt(limit);
        }
        return new(items, hasMore ? CursorCodec.Encode(new PrincipalCursor(items[^1].Id)) : null);
    }
}
