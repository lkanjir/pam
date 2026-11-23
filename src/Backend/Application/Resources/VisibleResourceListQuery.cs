using System.ComponentModel.DataAnnotations;

namespace Application.Resources;

/// <summary>Bounded ascending public-ID pagination for resources in the caller's current scope.</summary>
public sealed record VisibleResourceListQuery([property: Range(1, 100)] int Limit = 20, ResourceCursor? Cursor = null);
