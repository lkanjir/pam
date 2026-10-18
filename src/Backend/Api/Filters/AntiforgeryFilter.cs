using Microsoft.AspNetCore.Antiforgery;

namespace Api.Filters;

public sealed class AntiforgeryFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var httpContext = context.HttpContext;
        var method = httpContext.Request.Method;

        if (HttpMethods.IsGet(method)
            || HttpMethods.IsHead(method)
            || HttpMethods.IsOptions(method)
            || HttpMethods.IsTrace(method))
            return await next(context);

        try
        {
            await antiforgery.ValidateRequestAsync(httpContext);
        }
        catch (AntiforgeryValidationException)
        {
            httpContext.Response.Headers.CacheControl = "no-store";
            return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Invalid antiforgery token.");
        }

        return await next(context);
    }
}