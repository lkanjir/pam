namespace Api.Authentication;

public sealed record CurrentUserResponse(Guid Id, string DisplayName, List<string> Roles);