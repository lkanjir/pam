using Api;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddPamApi(builder.Configuration, builder.Environment);

var app = builder.Build();
app.UsePamApi();
app.Run();
