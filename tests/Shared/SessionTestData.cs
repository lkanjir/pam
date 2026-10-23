using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;

namespace Backend.Tests.Support;

internal sealed class TestTimeProvider : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 10, 23, 12, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => Now;
}

internal static class SessionTestData
{
    public static AuthenticationTicket Ticket(DateTimeOffset now, string principalId = "42") => new(
        new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, principalId),
            new Claim("pam_public_id", "019a0000-0000-7000-8000-000000000001"),
            new Claim("name", "Ana Horvat"),
            new Claim("pam_issuer", "https://identity.example/realms/pam"),
            new Claim("sub", "ana"),
            new Claim("sid", "idp-session")
        ], "Cookies", "name", "pam_role")),
        new AuthenticationProperties { IssuedUtc = now, ExpiresUtc = now.AddMinutes(30) },
        "Cookies");

    public static string Hash(string id) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(id)));
    public static string RedisKey(string id) => "pam:session:" + Hash(id);
}
