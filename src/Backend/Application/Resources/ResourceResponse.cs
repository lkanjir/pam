namespace Application.Resources;

public sealed record ResourceResponse(
    Guid Id,
    string Name,
    string? Description,
    string ResourceType,
    string Environment,
    bool IsActive,
    DateTime CreatedAt,
    DateTime ModifiedAt);
