using Microsoft.Extensions.Hosting;
using Migrator;

var builder = Host.CreateApplicationBuilder(args);
using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cancellation.Cancel();
};

return await DevelopmentMigrator.RunAsync(
    builder.Configuration, builder.Environment.EnvironmentName,
    Console.Out, Console.Error, cancellation.Token);
