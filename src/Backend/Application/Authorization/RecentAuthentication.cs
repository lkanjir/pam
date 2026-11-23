namespace Application.Authorization;

public static class RecentAuthentication
{
    public static TimeSpan MaximumAge { get; } = TimeSpan.FromMinutes(10);
    public static TimeSpan FutureClockSkew { get; } = TimeSpan.FromSeconds(60);

    public static bool IsSatisfied(DateTimeOffset? authenticatedAt, DateTimeOffset now)
    {
        if (authenticatedAt is not { } authenticationTime)
        {
            return false;
        }

        var age = now - authenticationTime;
        return age >= -FutureClockSkew && age <= MaximumAge;
    }
}
