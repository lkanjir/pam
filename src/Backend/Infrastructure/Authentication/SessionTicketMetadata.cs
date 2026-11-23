namespace Infrastructure.Authentication;

/// <summary>Non-secret binding metadata carried by the framework's protected authentication ticket.</summary>
public static class SessionTicketMetadata
{
    public const string SessionIdHash = "pam:session-id-hash";
}
