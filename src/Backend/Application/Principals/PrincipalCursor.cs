using System.Diagnostics.CodeAnalysis;
using Application.Common.Pagination;

namespace Application.Principals;

public sealed record PrincipalCursor(Guid LastPublicId)
{
    public static bool TryParse(string value, [NotNullWhen(true)] out PrincipalCursor? cursor)
    {
        cursor = null;
        if (!CursorCodec.TryDecode<PrincipalCursor>(value, out var decoded) || decoded.LastPublicId == Guid.Empty)
        {
            return false;
        }
        cursor = decoded;
        return true;
    }
}
