using System.Globalization;

namespace Api.Resources;

public static class ResourceEtags
{
    public static string Format(uint version) => $"\"{version.ToString("x8", CultureInfo.InvariantCulture)}\"";

}
