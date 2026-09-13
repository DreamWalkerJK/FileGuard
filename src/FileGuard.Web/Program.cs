var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://localhost:5080");
var app = builder.Build();
app.MapGet("/", () => "FileGuard initialization");
app.Run();
