namespace Domain;

public sealed class PamRoleAssignment
{
    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public long PrincipalId { get; init; }
    public int RoleId { get; init; }
    public DateTime AssignedAt { get; init; }
    public long AssignedByPrincipalId { get; init; }
}
