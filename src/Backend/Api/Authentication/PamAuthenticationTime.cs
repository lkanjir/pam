using System.Globalization;
using System.Security.Claims;

namespace Api.Authentication;

public static class PamAuthenticationTime
{
    public static DateTimeOffset? Read(ClaimsPrincipal principal, string claimType = PamClaimTypes.AuthenticationTime)
    {
        var claims = principal.FindAll(claimType).Take(2).ToArray();
        if (claims.Length != 1 || !long.TryParse(claims[0].Value, NumberStyles.None, CultureInfo.InvariantCulture, out long seconds)
            || seconds < 0 || seconds > DateTimeOffset.MaxValue.ToUnixTimeSeconds())
        {
            return null;
        }

        return DateTimeOffset.FromUnixTimeSeconds(seconds);
    }
}
