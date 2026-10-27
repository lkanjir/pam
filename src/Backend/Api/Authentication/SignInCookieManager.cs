using Microsoft.AspNetCore.Authentication.Cookies;

namespace Api.Authentication;

// The issuing scheme must allocate a fresh session, even if the reading scheme
// already authenticated this request. All response-cookie behavior stays standard.
internal sealed class SignInCookieManager(ICookieManager inner) : ICookieManager
{
    public string? GetRequestCookie(HttpContext context, string key) => null;

    public void AppendResponseCookie(HttpContext context, string key, string? value, CookieOptions options) =>
        inner.AppendResponseCookie(context, key, value, options);

    public void DeleteCookie(HttpContext context, string key, CookieOptions options) =>
        inner.DeleteCookie(context, key, options);
}
