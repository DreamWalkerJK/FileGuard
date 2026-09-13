using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using FileGuard.Core;
using FileGuard.Web;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace FileGuard.Tests;

public sealed class WebTests
{
    [Fact]
    public async Task UnauthorizedRequestsAndUntrustedHostAreRejected()
    {
        using var fixture = new WebFixture();
        using var client = fixture.Client();
        Assert.Equal(HttpStatusCode.Redirect, (await client.GetAsync("/")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/scans/unknown")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/actions/scans", new FormUrlEncodedContent([]))).StatusCode);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/login"); request.Headers.Host = "attacker.example";
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(request)).StatusCode);
        var login = await fixture.Html(client, "/login");
        Assert.Contains("一次性启动凭据", WebUtility.HtmlDecode(login));
        Assert.DoesNotContain(fixture.Root, login);
    }

    [Fact]
    public async Task LoginRequiresOriginAndCsrfAndStartupCredentialCanOnlyBeConsumedOnce()
    {
        using var fixture = new WebFixture(); using var client = fixture.Client();
        var token = fixture.StartupToken;
        using var missingCsrf = new HttpRequestMessage(HttpMethod.Post, "/auth/login") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token }) };
        missingCsrf.Headers.Add("Origin", "http://localhost");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(missingCsrf)).StatusCode);
        var csrf = await fixture.Csrf(client, "/login");
        Assert.Equal(HttpStatusCode.Forbidden, (await fixture.Post(client, "/auth/login", csrf, new() { ["token"] = token }, "http://attacker.example")).StatusCode);
        var response = await fixture.Post(client, "/auth/login", csrf, new() { ["token"] = token });
        Assert.Equal("/", response.Headers.Location?.OriginalString);
        Assert.False(System.IO.File.Exists(fixture.TokenPath));
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), cookie => cookie.Contains("FileGuard.Session") && cookie.Contains("httponly", StringComparison.OrdinalIgnoreCase) && cookie.Contains("samesite=strict", StringComparison.OrdinalIgnoreCase));
        using var second = fixture.Client();
        var replay = await fixture.Post(second, "/auth/login", await fixture.Csrf(second, "/login"), new() { ["token"] = token });
        Assert.Equal("/login?failed=true", replay.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task AuthenticatedMutationsRequireCsrfAndCannotExpandStartupAllowlist()
    {
        using var fixture = new WebFixture(); using var client = await fixture.Login();
        using var missing = new HttpRequestMessage(HttpMethod.Post, "/actions/roots") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["roots"] = "0" }) };
        missing.Headers.Add("Origin", "http://localhost");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(missing)).StatusCode);
        var csrf = await fixture.Csrf(client);
        var invalid = await fixture.Post(client, "/actions/scans", csrf, new() { ["roots"] = fixture.Parent });
        Assert.Equal(HttpStatusCode.Redirect, invalid.StatusCode);
        Assert.Equal(0, fixture.Store.ListScans().Total);
        await fixture.Post(client, "/actions/roots", csrf, new() { ["roots"] = "99" });
        Assert.True(fixture.Workspace.Enabled(0));
        await fixture.Post(client, "/actions/roots", csrf, []);
        Assert.False(fixture.Workspace.Enabled(0));
        await fixture.Post(client, "/actions/scans", csrf, new() { ["roots"] = "0" });
        Assert.Equal(0, fixture.Store.ListScans().Total);
        Assert.Empty(fixture.Store.GetSetting<string[]>("web-enabled-roots")!);
        await fixture.Post(client, "/actions/roots", csrf, new() { ["roots"] = "0" });
        Assert.True(fixture.Workspace.Enabled(0));
        Assert.Equal(HttpStatusCode.Forbidden, (await fixture.Post(client, "/actions/roots", csrf, [], "null")).StatusCode);
    }

    [Fact]
    public async Task WebUsesSharedCoreForScanPlanQuarantineRestoreAndManifestDifferences()
    {
        if (!OperatingSystem.IsWindows()) return; // Destructive capability is deliberately conservative outside Windows.
        using var fixture = new WebFixture(); using var client = await fixture.Login();
        var csrf = await fixture.Csrf(client);
        var queued = await fixture.Post(client, "/actions/scans", csrf, new() { ["roots"] = "0", ["concurrency"] = "2" });
        var scanId = WebFixture.Query(queued, "scan");
        var scan = await fixture.Finished(scanId);
        Assert.Equal(ScanState.Completed, scan.State); Assert.Equal(2, scan.FileCount);
        var duplicates = fixture.Workspace.Duplicates(scanId); Assert.Single(duplicates);
        Assert.Contains("重复组", WebUtility.HtmlDecode(await fixture.Html(client, "/?tab=duplicates&scan=" + scanId)));
        var planned = await fixture.Post(client, "/actions/plans", csrf, new() { ["scan"] = scanId, ["rule"] = "Explicit", ["keepPaths"] = fixture.File("a.txt") });
        var planId = WebFixture.Query(planned, "plan"); var plan = fixture.Store.GetPlan(planId); var operation = Assert.Single(plan.Operations);
        var preview = await fixture.Html(client, "/?tab=plans&plan=" + planId);
        Assert.Contains(operation.Candidate.FullPath, WebUtility.HtmlDecode(preview)); Assert.True(System.IO.File.Exists(operation.Candidate.FullPath));
        Assert.Equal(HttpStatusCode.BadRequest, (await fixture.Post(client, $"/actions/plans/{planId}/apply", csrf, [])).StatusCode);
        Assert.True(System.IO.File.Exists(operation.Candidate.FullPath));
        fixture.AssertTestPath(operation.Candidate.FullPath); fixture.AssertTestPath(operation.QuarantinePath);
        await fixture.Post(client, $"/actions/plans/{planId}/apply", csrf, new() { ["confirm"] = planId });
        Assert.Equal(OperationState.Completed, fixture.Store.GetOperation(operation.Id).State);
        Assert.False(System.IO.File.Exists(operation.Candidate.FullPath)); Assert.True(System.IO.File.Exists(operation.QuarantinePath));
        System.IO.File.WriteAllText(operation.Candidate.FullPath, "restore conflict");
        await fixture.Post(client, $"/actions/quarantine/{operation.Id}/restore", csrf, new() { ["confirm"] = operation.Id });
        Assert.Equal("restore conflict", System.IO.File.ReadAllText(operation.Candidate.FullPath));
        Assert.Equal(OperationState.Completed, fixture.Store.GetOperation(operation.Id).State);
        fixture.AssertTestPath(operation.Candidate.FullPath); System.IO.File.Delete(operation.Candidate.FullPath);
        await fixture.Post(client, $"/actions/quarantine/{operation.Id}/restore", csrf, new() { ["confirm"] = operation.Id });
        Assert.Equal(OperationState.Restored, fixture.Store.GetOperation(operation.Id).State);
        Assert.Equal("generated duplicate content", System.IO.File.ReadAllText(operation.Candidate.FullPath));
        var manifestResponse = await fixture.Post(client, "/actions/manifests/create", csrf, new() { ["root"] = "0" });
        Assert.Equal("application/json", manifestResponse.Content.Headers.ContentType?.MediaType);
        var before = await manifestResponse.Content.ReadAsStringAsync();
        var document = JsonSerializer.Deserialize<ManifestDocument>(before, JsonDefaults.Options)!; Assert.Equal(2, document.Files.Count);
        System.IO.File.WriteAllText(fixture.File("b.txt"), "changed content");
        using var verify = new MultipartFormDataContent();
        verify.Add(new StringContent(csrf), "__RequestVerificationToken"); verify.Add(new StringContent("0"), "root");
        verify.Add(new StringContent(before, Encoding.UTF8, "application/json"), "manifest", "manifest.json");
        using var verifyRequest = new HttpRequestMessage(HttpMethod.Post, "/actions/manifests/verify") { Content = verify }; verifyRequest.Headers.Add("Origin", "http://localhost");
        var verified = await client.SendAsync(verifyRequest); var resultId = WebFixture.Query(verified, "result");
        Assert.Contains(fixture.Workspace.Result(resultId)!.Differences, x => x.Kind == DifferenceKind.ContentChanged && x.Path == "b.txt");
        Assert.Contains("内容变化", WebUtility.HtmlDecode(await fixture.Html(client, "/?tab=manifests&result=" + resultId)));
        Assert.True(fixture.Store.ListHistory().Total > 0);
        Assert.Contains("安全检查", WebUtility.HtmlDecode(await fixture.Html(client, "/?tab=history")));
    }

    [Fact]
    public async Task PermanentPurgeRequiresSeparateSecondConfirmation()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new WebFixture(); using var client = await fixture.Login(); var csrf = await fixture.Csrf(client);
        var scan = await fixture.Services.GetRequiredService<Scanner>().ScanAsync(new ScanOptions { Roots = [fixture.Root] });
        var plan = fixture.Workspace.Cleanup.CreatePlan(scan.Id, new PlanOptions());
        await fixture.Workspace.Cleanup.ApplyAsync(plan.Id, true); var operation = Assert.Single(fixture.Store.GetPlan(plan.Id).Operations);
        fixture.AssertTestPath(operation.QuarantinePath);
        var one = await fixture.Post(client, $"/actions/quarantine/{operation.Id}/purge", csrf, new() { ["confirm"] = operation.Id });
        Assert.Equal(HttpStatusCode.BadRequest, one.StatusCode); Assert.True(System.IO.File.Exists(operation.QuarantinePath));
        await fixture.Post(client, $"/actions/quarantine/{operation.Id}/purge", csrf, new() { ["confirm"] = operation.Id, ["permanent"] = "PERMANENT" });
        Assert.Equal(OperationState.Purged, fixture.Store.GetOperation(operation.Id).State); Assert.False(System.IO.File.Exists(operation.QuarantinePath));
        Assert.True(System.IO.File.Exists(operation.Keeper.FullPath));
    }

    [Theory]
    [InlineData("http://0.0.0.0:5187")]
    [InlineData("http://example.com:5187")]
    [InlineData("http://localhost:5187;http://0.0.0.0:5187")]
    [InlineData("https://localhost:5187")]
    public void RemoteAndUnsupportedListenerConfigurationsFailClosed(string url) => Assert.Throws<GuardException>(() => WebStartup.Parse(["--urls", url]));

    [Fact]
    public async Task ManifestDiffAndStrictUploadUseTheSameCoreValidation()
    {
        using var fixture = new WebFixture(); using var client = await fixture.Login(); var csrf = await fixture.Csrf(client);
        var before = await (await fixture.Post(client, "/actions/manifests/create", csrf, new() { ["root"] = "0" })).Content.ReadAsStringAsync();
        System.IO.File.WriteAllText(fixture.File("a.txt"), "changed generated content");
        var after = await (await fixture.Post(client, "/actions/manifests/create", csrf, new() { ["root"] = "0" })).Content.ReadAsStringAsync();
        var response = await fixture.Upload(client, "/actions/manifests/diff", csrf, new() { ["before"] = before, ["after"] = after });
        var result = fixture.Workspace.Result(WebFixture.Query(response, "result"))!;
        Assert.Contains(result.Differences, x => x.Path == "a.txt" && x.Kind == DifferenceKind.ContentChanged);
        foreach (var invalid in new[] { "{}", before.Replace("\"schemaVersion\": 1", "\"schemaVersion\": 1, \"schemaVersion\": 2", StringComparison.Ordinal), before.Replace("a.txt", "../outside.txt", StringComparison.Ordinal) })
        {
            var count = fixture.Store.ListScans().Total;
            var rejected = await fixture.Upload(client, "/actions/manifests/verify", csrf, new() { ["manifest"] = invalid });
            Assert.Equal(HttpStatusCode.Redirect, rejected.StatusCode); Assert.Contains("notice=", rejected.Headers.Location!.OriginalString); Assert.Equal(count, fixture.Store.ListScans().Total);
        }
    }

    [Fact]
    public async Task ChangedAndExpiredPlansAreSafelySkippedThroughWeb()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new WebFixture(); using var client = await fixture.Login(); var csrf = await fixture.Csrf(client);
        var scan = await fixture.Services.GetRequiredService<Scanner>().ScanAsync(new ScanOptions { Roots = [fixture.Root] });
        var stale = fixture.Workspace.Cleanup.CreatePlan(scan.Id, new PlanOptions()); var candidate = Assert.Single(stale.Operations).Candidate.FullPath;
        fixture.AssertTestPath(candidate); System.IO.File.WriteAllText(candidate, "unique content changed after planning");
        await fixture.Post(client, $"/actions/plans/{stale.Id}/apply", csrf, new() { ["confirm"] = stale.Id });
        Assert.Equal(OperationState.Skipped, Assert.Single(fixture.Store.GetPlan(stale.Id).Operations).State); Assert.Equal("unique content changed after planning", System.IO.File.ReadAllText(candidate));
        System.IO.File.WriteAllText(candidate, "generated duplicate content");
        scan = await fixture.Services.GetRequiredService<Scanner>().ScanAsync(new ScanOptions { Roots = [fixture.Root] });
        var expired = fixture.Workspace.Cleanup.CreatePlan(scan.Id, new PlanOptions()) with { ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1) }; fixture.Store.SavePlan(expired);
        await fixture.Post(client, $"/actions/plans/{expired.Id}/apply", csrf, new() { ["confirm"] = expired.Id });
        var operation = Assert.Single(fixture.Store.GetPlan(expired.Id).Operations);
        Assert.Equal(OperationState.Skipped, operation.State); Assert.Contains("过期", operation.Detail); Assert.True(System.IO.File.Exists(operation.Candidate.FullPath));
    }

    [Fact]
    public async Task DisabledRootsBlockCleanupRestorePurgeAndRecoverNeedsExplicitConfirmation()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new WebFixture(); using var client = await fixture.Login(); var csrf = await fixture.Csrf(client);
        var scan = await fixture.Services.GetRequiredService<Scanner>().ScanAsync(new ScanOptions { Roots = [fixture.Root] });
        var plan = fixture.Workspace.Cleanup.CreatePlan(scan.Id, new PlanOptions()); var operation = Assert.Single(plan.Operations);
        await fixture.Post(client, "/actions/roots", csrf, []);
        await fixture.Post(client, $"/actions/plans/{plan.Id}/apply", csrf, new() { ["confirm"] = plan.Id });
        Assert.Equal(OperationState.Planned, fixture.Store.GetOperation(operation.Id).State); Assert.True(System.IO.File.Exists(operation.Candidate.FullPath));
        await fixture.Post(client, "/actions/roots", csrf, new() { ["roots"] = "0" });
        await fixture.Post(client, $"/actions/plans/{plan.Id}/apply", csrf, new() { ["confirm"] = plan.Id });
        Assert.Equal(OperationState.Completed, fixture.Store.GetOperation(operation.Id).State);
        await fixture.Post(client, "/actions/roots", csrf, []);
        await fixture.Post(client, $"/actions/quarantine/{operation.Id}/restore", csrf, new() { ["confirm"] = operation.Id });
        await fixture.Post(client, $"/actions/quarantine/{operation.Id}/purge", csrf, new() { ["confirm"] = operation.Id, ["permanent"] = "PERMANENT" });
        Assert.Equal(OperationState.Completed, fixture.Store.GetOperation(operation.Id).State); Assert.True(System.IO.File.Exists(operation.QuarantinePath));
        operation = fixture.Store.GetOperation(operation.Id); operation.State = OperationState.NeedsReview; fixture.Store.SaveOperation(operation);
        Assert.Equal(HttpStatusCode.BadRequest, (await fixture.Post(client, "/actions/recover", csrf, [])).StatusCode);
        await fixture.Post(client, "/actions/recover", csrf, new() { ["confirm"] = "RECOVER" }); Assert.Equal(OperationState.NeedsReview, fixture.Store.GetOperation(operation.Id).State);
        await fixture.Post(client, "/actions/roots", csrf, new() { ["roots"] = "0" });
        var preview = await fixture.Html(client, "/?tab=quarantine"); Assert.Contains("中断恢复预览", WebUtility.HtmlDecode(preview)); Assert.Contains(operation.Id, preview);
        await fixture.Post(client, "/actions/recover", csrf, new() { ["confirm"] = "RECOVER" }); Assert.Equal(OperationState.Completed, fixture.Store.GetOperation(operation.Id).State);
    }

    [Fact]
    public async Task WebCancellationPersistsAndErrorFilesOfferRetry()
    {
        using var fixture = new WebFixture(bytesPerSecond: 1); using var client = await fixture.Login(); var csrf = await fixture.Csrf(client);
        var queued = await fixture.Post(client, "/actions/scans", csrf, new() { ["roots"] = "0" }); var scanId = WebFixture.Query(queued, "scan");
        await fixture.Post(client, $"/actions/scans/{scanId}/cancel", csrf, []); Assert.Equal(ScanState.Cancelled, (await fixture.Finished(scanId)).State);
        var cancelledHtml = await fixture.Html(client, "/?tab=scans&scan=" + scanId); Assert.Contains("已取消", WebUtility.HtmlDecode(cancelledHtml));
        using var locked = new FileStream(fixture.File("a.txt"), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var failed = await fixture.Services.GetRequiredService<Scanner>().ScanAsync(new ScanOptions { Roots = [fixture.Root] });
        Assert.Equal(ScanState.PartialFailure, failed.State);
        var failures = await fixture.Html(client, "/?tab=scans&scan=" + failed.Id + "&state=Unreadable");
        Assert.Contains("a.txt", failures); Assert.Contains("修复权限后重新扫描", WebUtility.HtmlDecode(failures)); locked.Dispose();
        var retried = await fixture.Post(client, $"/actions/scans/{failed.Id}/retry", csrf, []); var retryId = WebFixture.Query(retried, "scan");
        Assert.NotEqual(failed.Id, retryId); Assert.Equal(ScanState.Completed, (await fixture.Finished(retryId)).State);
    }

    private sealed class WebFixture : WebApplicationFactory<Program>
    {
        public string Parent { get; } = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", ".test-data", "web-" + Guid.NewGuid().ToString("N")));
        public string Root => Path.Combine(Parent, "root");
        public string Data => Path.Combine(Parent, "state");
        public string TokenPath => Path.Combine(Data, "web-private", "startup-token.txt");
        public string StartupToken => System.IO.File.ReadAllText(TokenPath);
        public WebWorkspace Workspace => Services.GetRequiredService<WebWorkspace>();
        public FileGuardStore Store => Services.GetRequiredService<FileGuardStore>();
        private readonly long _bytesPerSecond;
        public WebFixture(long bytesPerSecond = 0) { _bytesPerSecond = bytesPerSecond; Directory.CreateDirectory(Root); System.IO.File.WriteAllText(File("a.txt"), "generated duplicate content"); System.IO.File.WriteAllText(File("b.txt"), "generated duplicate content"); }
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureServices(services => { services.RemoveAll<GuardSettings>(); services.AddSingleton(new GuardSettings { DataDirectory = Data, AllowedRoots = [Root], QuarantineDirectory = Path.Combine(Parent, "quarantine"), BytesPerSecond = _bytesPerSecond }); });
        }
        public HttpClient Client() => CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("http://localhost"), AllowAutoRedirect = false });
        public async Task<HttpClient> Login() { var client = Client(); var token = StartupToken; var result = await Post(client, "/auth/login", await Csrf(client, "/login"), new() { ["token"] = token }); Assert.Equal("/", result.Headers.Location?.OriginalString); return client; }
        public async Task<string> Html(HttpClient client, string path) { var response = await client.GetAsync(path); Assert.True(response.StatusCode == HttpStatusCode.OK, "Page status " + response.StatusCode + "; redirect " + response.Headers.Location); return await response.Content.ReadAsStringAsync(); }
        public async Task<string> Csrf(HttpClient client, string path = "/")
        {
            var html = await Html(client, path); var match = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\""); Assert.True(match.Success, "Rendered form must contain antiforgery token."); return WebUtility.HtmlDecode(match.Groups[1].Value);
        }
        public async Task<HttpResponseMessage> Post(HttpClient client, string path, string csrf, Dictionary<string, string> fields, string origin = "http://localhost")
        {
            fields["__RequestVerificationToken"] = csrf; using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new FormUrlEncodedContent(fields) }; request.Headers.Add("Origin", origin); return await client.SendAsync(request);
        }
        public async Task<ScanRecord> Finished(string id)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            while (true) { var scan = Store.GetScan(id); if (!Ui.Active(scan.State)) return scan; await Task.Delay(30, timeout.Token); }
        }
        public async Task<HttpResponseMessage> Upload(HttpClient client, string path, string csrf, Dictionary<string, string> files)
        {
            using var content = new MultipartFormDataContent(); content.Add(new StringContent(csrf), "__RequestVerificationToken"); content.Add(new StringContent("0"), "root");
            foreach (var file in files) content.Add(new StringContent(file.Value, Encoding.UTF8, "application/json"), file.Key, file.Key + ".json");
            using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content }; request.Headers.Add("Origin", "http://localhost"); return await client.SendAsync(request);
        }
        public static string Query(HttpResponseMessage response, string key)
        {
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode); var location = response.Headers.Location?.OriginalString ?? "";
            var match = Regex.Match(location, "[?&]" + key + "=([a-f0-9]{32})"); Assert.True(match.Success, "Expected task/result ID in redirect: " + location); return match.Groups[1].Value;
        }
        public string File(string name) => Path.Combine(Root, name);
        public void AssertTestPath(string path) => Assert.StartsWith(Parent + Path.DirectorySeparatorChar, Path.GetFullPath(path), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        protected override void Dispose(bool disposing) { base.Dispose(disposing); if (Directory.Exists(Parent)) { var absolute = Path.GetFullPath(Parent); Assert.Contains(Path.DirectorySeparatorChar + ".test-data" + Path.DirectorySeparatorChar, absolute); Directory.Delete(absolute, true); } }
    }
}
