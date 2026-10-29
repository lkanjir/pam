using System.Diagnostics.CodeAnalysis;
using Application.Common.Pagination;

namespace Application.Resources;

public sealed record ResourceCursor(Guid LastPublicId)
{
    public static bool TryParse(
        string value,
        [NotNullWhen(true)] out ResourceCursor? cursor)
    {
        cursor = null;

        if (!CursorCodec.TryDecode<ResourceCursor>(value, out var decoded)
            || decoded.LastPublicId == Guid.Empty)
        {
            return false;
        }

        cursor = decoded;
        return true;
    }
}
