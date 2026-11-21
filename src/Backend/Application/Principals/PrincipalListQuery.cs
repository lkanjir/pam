using System.ComponentModel.DataAnnotations;

namespace Application.Principals;

/// <summary>Bounded forward-only pagination of PAM identity mappings.</summary>
public sealed record PrincipalListQuery([property: Range(1, 100)] int Limit = 20, PrincipalCursor? Cursor = null);
