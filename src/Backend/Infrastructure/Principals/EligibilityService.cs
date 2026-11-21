using Application.Common.Pagination;
using Application.Principals;
using Application.Resources;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Principals;

public sealed class EligibilityService(PamDbContext database) : IEligibilityService
{
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
