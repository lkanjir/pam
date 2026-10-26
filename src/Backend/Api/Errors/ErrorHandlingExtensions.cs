namespace Api.Errors;

public static class ErrorHandlingExtensions
{
    public static IServiceCollection AddPamErrorHandling(this IServiceCollection services)
    {
        services.AddSingleton<IProblemDetailsWriter, PamProblemDetailsWriter>();
        services.AddProblemDetails();
        services.AddExceptionHandler<PamExceptionHandler>();
        return services;
    }

    public static IApplicationBuilder UsePamErrorHandling(this IApplicationBuilder app)
    {
        app.UseExceptionHandler();
        app.UseStatusCodePages();
        return app;
    }
}
