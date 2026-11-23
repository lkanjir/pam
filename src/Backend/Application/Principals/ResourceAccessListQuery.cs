using System.ComponentModel.DataAnnotations;
using Application.Resources;

namespace Application.Principals;

/// <summary>Ascending resource public-ID cursor pagination for a principal's view assignments.</summary>
public sealed record ResourceAccessListQuery([property: Range(1, 100)] int Limit = 20, ResourceCursor? Cursor = null);
