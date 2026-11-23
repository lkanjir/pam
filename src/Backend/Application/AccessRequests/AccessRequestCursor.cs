using System.Diagnostics.CodeAnalysis;
using Application.Common.Pagination;

namespace Application.AccessRequests;

public sealed record AccessRequestCursor(Guid LastPublicId)
{
    public static bool TryParse(string value, [NotNullWhen(true)] out AccessRequestCursor? cursor)
    {
        cursor = null;
        if (!CursorCodec.TryDecode<AccessRequestCursor>(value, out var decoded)
            || decoded.LastPublicId == Guid.Empty)
        {
            return false;
        }

        cursor = decoded;
        return true;
    }
}
