using System.Security.Claims;
using System.Text.Json;
using FileGuard.Core;
using FileGuard.Web;
using FileGuard.Web.Components;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

var startup = WebStartup.Parse(args);
var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [], ApplicationName = typeof(Program).Assembly.GetName().Name, ContentRootPath = AppContext.BaseDirectory });
builder.Configuration.AddInMemoryCollection(startup.Configuration);
builder.WebHost.UseUrls(startup.Urls);
builder.WebHost.UseStaticWebAssets();
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 8 * 1024 * 1024);
builder.Logging.ClearProviders(); // Request/exception logging can expose local file paths.
builder.Services.AddRazorComponents();
builder.Services.AddAntiforgery(options => { options.Cookie.Name = "FileGuard.Csrf"; options.Cookie.SameSite = SameSiteMode.Strict; options.HeaderName = "X-FileGuard-CSRF"; });
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
{
    options.Cookie.Name = "FileGuard.Session"; options.Cookie.HttpOnly = true; options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = false; options.LoginPath = "/login";
    options.Events.OnValidatePrincipal = context =>
    {
        if (context.Principal?.FindFirst("startup")?.Value != context.HttpContext.RequestServices.GetRequiredService<StartupCredential>().InstanceId) context.RejectPrincipal();
        return Task.CompletedTask;
    };
});
builder.Services.AddAuthorization();
builder.Services.AddSingleton(provider => WebStartup.LoadSettings(provider.GetRequiredService<IConfiguration>()));
builder.Services.AddSingleton(provider => new FileGuardStore(provider.GetRequiredService<GuardSettings>().DataDirectory));
builder.Services.AddSingleton<Scanner>();
builder.Services.AddSingleton<ManifestService>();
builder.Services.AddSingleton<CleanupService>();
builder.Services.AddSingleton<WebWorkspace>();
builder.Services.AddSingleton<StartupCredential>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<WebWorkspace>());
var app = builder.Build();
app.Services.GetRequiredService<FileGuardStore>().Initialize();
_ = app.Services.GetRequiredService<StartupCredential>();
app.Use(async (context, next) =>
{
    if (!WebBoundary.IsLocalRequest(context)) { context.Response.StatusCode = 403; return; }
    context.Response.Headers["X-Content-Type-Options"] = "nosniff"; context.Response.Headers["Referrer-Policy"] = "same-origin";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    context.Response.Headers.CacheControl = "no-store";
    await next();
});
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.Use(async (context, next) =>
{
    var anonymous = context.Request.Path == "/login" || context.Request.Path == "/auth/login";
    if (!anonymous && context.User.Identity?.IsAuthenticated != true)
    {
        if (context.Request.Method == "GET" && !context.Request.Path.StartsWithSegments("/api")) context.Response.Redirect("/login");
        else context.Response.StatusCode = 401;
        return;
    }
    if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
    {
        if (!WebBoundary.IsSameOrigin(context)) { context.Response.StatusCode = 403; return; }
        try { await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context); }
        catch (AntiforgeryValidationException) { context.Response.StatusCode = 400; return; }
    }
    try { await next(); }
    catch (Exception exception) when (exception is GuardException or ArgumentException or FormatException or OverflowException or IOException or JsonException or InvalidOperationException or UnauthorizedAccessException)
    {
        context.Response.StatusCode = 400;
        if (context.Request.Path.StartsWithSegments("/api") || context.Request.Method == "GET") await context.Response.WriteAsJsonAsync(new { schemaVersion = 1, error = "操作被拒绝。请检查允许根目录、文件状态及输入格式。" });
        else context.Response.Redirect("/?notice=" + Uri.EscapeDataString("操作被拒绝：检查根目录是否启用、文件是否变化、输入格式和权限。详细文件错误可在扫描与操作历史中查看。"));
    }
});
app.UseAntiforgery();
app.MapPost("/auth/login", async (HttpContext context, StartupCredential credential) =>
{
    var form = await context.Request.ReadFormAsync();
    if (!credential.Consume(form["token"].ToString())) return Results.Redirect("/login?failed=true");
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "local-owner"), new Claim("startup", credential.InstanceId)], CookieAuthenticationDefaults.AuthenticationScheme)));
    return Results.Redirect("/");
});
app.MapPost("/auth/logout", async (HttpContext context) => { await context.SignOutAsync(); return Results.Redirect("/login"); });
app.MapGet("/api/scans/{id}", (string id, WebWorkspace workspace) => Results.Json(new { schemaVersion = 1, scan = workspace.Store.GetScan(id), progress = workspace.ProgressFor(id) }, JsonDefaults.Options));
app.MapPost("/actions/roots", async (HttpContext context, WebWorkspace workspace) =>
{
    var form = await context.Request.ReadFormAsync(); workspace.SetRoots(form["roots"].Select(x => int.Parse(x!)).ToArray());
    return Results.Redirect("/?tab=settings&notice=" + Uri.EscapeDataString("允许目录已更新。"));
});
app.MapPost("/actions/scans", async (HttpContext context, WebWorkspace workspace) =>
{
    var form = await context.Request.ReadFormAsync();
    var id = workspace.Queue(new ScanOptions
    {
        Roots = form["roots"].Select(x => workspace.Root(int.Parse(x!))).ToArray(),
        Include = WebWorkspace.Split(form["include"]), Exclude = WebWorkspace.Split(form["exclude"]), Extensions = WebWorkspace.Split(form["extensions"]),
        MinSize = WebWorkspace.OptionalLong(form["minSize"]), MaxSize = WebWorkspace.OptionalLong(form["maxSize"]),
        ModifiedAfter = WebWorkspace.OptionalDate(form["modifiedAfter"]), ModifiedBefore = WebWorkspace.OptionalDate(form["modifiedBefore"]),
        Concurrency = Math.Clamp(int.TryParse(form["concurrency"], out var value) ? value : workspace.Settings.Concurrency, 1, 16),
        ChannelCapacity = workspace.Settings.ChannelCapacity, BytesPerSecond = workspace.Settings.BytesPerSecond
    });
    return Results.Redirect("/?tab=scans&scan=" + id);
});
app.MapPost("/actions/scans/{id}/cancel", (string id, WebWorkspace workspace) => { workspace.Cancel(id); return Results.Redirect("/?tab=scans&scan=" + id); });
app.MapPost("/actions/scans/{id}/retry", (string id, WebWorkspace workspace) => Results.Redirect("/?tab=scans&scan=" + workspace.Retry(id)));
app.MapPost("/actions/plans", async (HttpContext context, WebWorkspace workspace) =>
{
    var form = await context.Request.ReadFormAsync();
    workspace.DemandEnabledRoots(workspace.Store.GetScan(form["scan"].ToString()).Options.Roots);
    var plan = workspace.Cleanup.CreatePlan(form["scan"].ToString(), new PlanOptions
    {
        Rule = Enum.Parse<KeepRule>(form["rule"].ToString()), PreferredDirectory = form["preferredDirectory"].ToString(),
        KeepPaths = form["keepPaths"].SelectMany(value => (value ?? "").Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToArray(), ValidForHours = 24
    });
    return Results.Redirect("/?tab=plans&plan=" + plan.Id);
});
app.MapPost("/actions/plans/{id}/apply", async (string id, HttpContext context, WebWorkspace workspace) =>
{
    var form = await context.Request.ReadFormAsync();
    if (form["confirm"] != id) return Results.BadRequest(new { schemaVersion = 1, error = "请输入完整计划 ID 确认执行。" });
    workspace.DemandOperationsEnabled(workspace.Store.GetPlan(id).Operations);
    await workspace.Cleanup.ApplyAsync(id, true, context.RequestAborted);
    return Results.Redirect("/?tab=quarantine&notice=" + Uri.EscapeDataString("计划已处理。请核对每个文件的实际操作状态。"));
});
app.MapPost("/actions/quarantine/{id}/restore", async (string id, HttpContext context, WebWorkspace workspace) =>
{
    var form = await context.Request.ReadFormAsync();
    if (form["confirm"] != id) return Results.BadRequest(new { schemaVersion = 1, error = "请确认操作 ID。" });
    workspace.DemandOperationsEnabled([workspace.Store.GetOperation(id)]);
    var result = await workspace.Cleanup.RestoreAsync(id, true, context.RequestAborted);
    return Results.Redirect("/?tab=quarantine&notice=" + Uri.EscapeDataString(result.Detail));
});
app.MapPost("/actions/quarantine/{id}/purge", async (string id, HttpContext context, WebWorkspace workspace) =>
{
    var form = await context.Request.ReadFormAsync();
    if (form["confirm"] != id || form["permanent"] != "PERMANENT") return Results.BadRequest(new { schemaVersion = 1, error = "永久清除需要操作 ID 和第二次 PERMANENT 确认。" });
    workspace.DemandOperationsEnabled([workspace.Store.GetOperation(id)]);
    var result = await workspace.Cleanup.PurgeAsync(id, true, true, context.RequestAborted);
    return Results.Redirect("/?tab=quarantine&notice=" + Uri.EscapeDataString(result.Detail));
});
app.MapPost("/actions/recover", async (HttpContext context, WebWorkspace workspace) =>
{
    var form = await context.Request.ReadFormAsync();
    if (form["confirm"] != "RECOVER") return Results.BadRequest(new { schemaVersion = 1, error = "恢复中断操作会更新记录或撤销已验证的部分副本。审查预览后输入 RECOVER 确认。" });
    workspace.DemandOperationsEnabled(workspace.RecoveryCandidates());
    await workspace.Cleanup.RecoverAsync(context.RequestAborted);
    return Results.Redirect("/?tab=quarantine&notice=" + Uri.EscapeDataString("已处理中断操作。NeedsReview 项需要根据恢复手册人工核对。"));
});
app.MapPost("/actions/manifests/create", async (HttpContext context, WebWorkspace workspace) =>
{
    var form = await context.Request.ReadFormAsync();
    var manifest = await workspace.Manifests.CreateAsync(workspace.Root(int.Parse(form["root"].ToString())), context.RequestAborted);
    return Results.File(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(manifest, JsonDefaults.Options).Replace("\r\n", "\n", StringComparison.Ordinal) + "\n"), "application/json", "fileguard-manifest.json");
});
app.MapPost("/actions/manifests/verify", async (HttpContext context, WebWorkspace workspace) =>
{
    var form = await context.Request.ReadFormAsync();
    var document = await WebWorkspace.ReadManifest(form.Files.GetFile("manifest"), context.RequestAborted);
    var result = await workspace.Manifests.VerifyAsync(workspace.Root(int.Parse(form["root"].ToString())), document, context.RequestAborted);
    return Results.Redirect("/?tab=manifests&result=" + workspace.SaveResult(result));
});
app.MapPost("/actions/manifests/diff", async (HttpContext context, WebWorkspace workspace) =>
{
    var form = await context.Request.ReadFormAsync();
    var before = await WebWorkspace.ReadManifest(form.Files.GetFile("before"), context.RequestAborted);
    var after = await WebWorkspace.ReadManifest(form.Files.GetFile("after"), context.RequestAborted);
    return Results.Redirect("/?tab=manifests&result=" + workspace.SaveResult(workspace.Manifests.Diff(before, after)));
});
app.MapGet("/api/results/{id}", (string id, WebWorkspace workspace) => workspace.Result(id) is { } result ? Results.Json(new { schemaVersion = 1, result }, JsonDefaults.Options) : Results.NotFound());
app.MapRazorComponents<App>();
app.Run();
public partial class Program { }
