namespace Application.Sessions;

public enum SessionEndReason
{
    Logout,
    Reauthentication,
    AccessChanged
}

public static class SessionEndReasonExtensions
{
    // Persist stable codes, independent of enum names or numeric values.
    public static string ToCode(this SessionEndReason reason) => reason switch
    {
        SessionEndReason.Logout => "logout",
        SessionEndReason.Reauthentication => "reauthentication",
        SessionEndReason.AccessChanged => "access_changed",
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, "Unknown session end reason.")
    };
}
