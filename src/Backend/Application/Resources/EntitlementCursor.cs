using System.Diagnostics.CodeAnalysis;
using Application.Common.Pagination;

namespace Application.Resources;

public sealed record EntitlementCursor(Guid LastPublicId)
{
    public static bool TryParse(string value, [NotNullWhen(true)] out EntitlementCursor? cursor)
    {
        cursor = null;
        if (!CursorCodec.TryDecode<EntitlementCursor>(value, out var decoded) || decoded.LastPublicId == Guid.Empty)
        {
            return false;
        }
        cursor = decoded;
        return true;
    }
}
