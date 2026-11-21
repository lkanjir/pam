using System.ComponentModel.DataAnnotations;

namespace Application.Resources;

/// <summary>Bounded ascending entitlement public-ID pagination within one managed resource.</summary>
public sealed record EntitlementListQuery([property: Range(1, 100)] int Limit = 20, EntitlementCursor? Cursor = null);
