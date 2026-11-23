namespace Api.Authorization;

/// <summary>Names the operation policies selected by a handler's conditional authorization branches.</summary>
public sealed record PamConditionalPermissionMetadata(params string[] Permissions);
