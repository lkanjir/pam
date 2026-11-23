namespace Application.Principals;

/// <summary>An explicit resource assignment retained by a principal, including inactive or retired relationships.</summary>
public sealed record ResourceAccessResponse(Guid Id, Guid ResourceId, string ResourceName, bool IsActive,
    bool IsRetired, DateTimeOffset AssignedAt, DateTimeOffset ModifiedAt);
