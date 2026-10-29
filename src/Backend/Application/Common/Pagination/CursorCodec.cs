using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace Application.Common.Pagination;

public static class CursorCodec
{
    private const int MaxTokenLength = 2048;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static string Encode<T>(T cursor)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(cursor, JsonOptions);
        return Base64Url.EncodeToString(json);
    }

    public static bool TryDecode<T>(string token, [NotNullWhen(true)] out T? cursor) where T : class
    {
        cursor = null;

        if (string.IsNullOrWhiteSpace(token) || token.Length > MaxTokenLength)
        {
            return false;
        }

        try
        {
            byte[] json = Base64Url.DecodeFromChars(token);

            cursor = JsonSerializer.Deserialize<T>(json, JsonOptions);

            return cursor is not null;
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return false;
        }
    }

}
