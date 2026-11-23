using System.ComponentModel.DataAnnotations;
using Application.Resources;

namespace Application.Principals;

/// <summary>Ascending entitlement public-ID cursor pagination for a principal's eligibility rules.</summary>
public sealed record EligibilityListQuery([property: Range(1, 100)] int Limit = 20, EntitlementCursor? Cursor = null);
