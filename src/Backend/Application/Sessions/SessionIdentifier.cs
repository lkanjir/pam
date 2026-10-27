using System.Security.Cryptography;
using System.Text;

namespace Application.Sessions;

public static class SessionIdentifier
{
    public static string Hash(string sessionId) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sessionId)));

    public static bool IsValid(string? sessionId) =>
        sessionId is { Length: 64 } && sessionId.All(char.IsAsciiHexDigitUpper);
}
