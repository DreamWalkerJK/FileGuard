using System.Diagnostics;
using System.Text.Json;
using FileGuard.Cli;
using FileGuard.Core;
using Xunit;

namespace FileGuard.Tests;

public sealed class CliTests
{
    [Fact]
    public async Task HelpAndInvalidArgumentsReturnMachineReadableResults()
    {
        using var fixture = new CliFixture();
        var help = await fixture.Run("--help");
        Assert.Equal(0, help.ExitCode);
        Assert.Equal(1, help.Document.GetProperty("schemaVersion").GetInt32());
        Assert.Contains("cleanup apply", help.Data.GetProperty("help").GetString());
        var invalid = await fixture.Run("scan", "--unknown", "value");
        Assert.Equal(2, invalid.ExitCode);
        Assert.Equal("invalidArguments", invalid.Document.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task CliScanDuplicatesManifestAndDryRunUseSharedCore()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new CliFixture();
        var scan = await fixture.Run("scan", fixture.Root);
        Assert.Equal(0, scan.ExitCode);
        var scanId = scan.Data.GetProperty("id").GetString()!;
        Assert.Equal(2, scan.Data.GetProperty("fileCount").GetInt64());
        var duplicates = await fixture.Run("duplicates", scanId);
        Assert.Single(duplicates.Data.EnumerateArray());
        var plan = await fixture.Run("cleanup", "plan", scanId);
        Assert.Equal(0, plan.ExitCode);
        var planId = plan.Data.GetProperty("id").GetString()!;
        var preview = await fixture.Run("cleanup", "apply", planId);
        Assert.All(preview.Data.EnumerateArray(), x => Assert.True(x.GetProperty("dryRun").GetBoolean()));
        var manifest = fixture.Child("manifest.json");
        Assert.Equal(0, (await fixture.Run("manifest", "create", fixture.Root, "--output", manifest)).ExitCode);
        Assert.Equal(0, (await fixture.Run("manifest", "verify", fixture.Root, "--manifest", manifest)).ExitCode);
        await File.WriteAllTextAsync(fixture.File("a.txt"), "changed");
        Assert.Equal(1, (await fixture.Run("manifest", "verify", fixture.Root, "--manifest", manifest)).ExitCode);
    }

    [Fact]
    public async Task ActualProcessCompletesCleanupRecoveryAndRejectsChangedPlan()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new CliFixture();
        var scan = await fixture.Run("scan", fixture.Root);
        var plan = await fixture.Run("cleanup", "plan", scan.Data.GetProperty("id").GetString()!);
        var id = plan.Data.GetProperty("id").GetString()!;
        var operation = Assert.Single(plan.Data.GetProperty("operations").EnumerateArray());
        var operationId = operation.GetProperty("id").GetString()!;
        var original = operation.GetProperty("candidate").GetProperty("fullPath").GetString()!;
        var quarantine = operation.GetProperty("quarantinePath").GetString()!;
        Assert.True(PathSafety.IsWithin(original, fixture.Root));
        Assert.True(PathSafety.IsWithin(quarantine, fixture.DataDirectory));
        Assert.Equal(0, (await fixture.Run("cleanup", "show", id)).ExitCode);
        Assert.Equal(0, (await fixture.Run("cleanup", "apply", id, "--confirm")).ExitCode);
        Assert.False(System.IO.File.Exists(original));
        Assert.Equal("same generated content", await System.IO.File.ReadAllTextAsync(quarantine));
        Assert.True((await fixture.Run("history")).Data.GetProperty("total").GetInt32() > 0);
        Assert.Equal(0, (await fixture.Run("quarantine", "restore", operationId, "--confirm")).ExitCode);
        Assert.Equal("same generated content", await System.IO.File.ReadAllTextAsync(original));
        var before = fixture.Child("before.json"); var after = fixture.Child("after.json");
        Assert.Equal(0, (await fixture.Run("manifest", "create", fixture.Root, "--output", before)).ExitCode);
        scan = await fixture.Run("scan", fixture.Root);
        plan = await fixture.Run("cleanup", "plan", scan.Data.GetProperty("id").GetString()!);
        id = plan.Data.GetProperty("id").GetString()!;
        var changed = Assert.Single(plan.Data.GetProperty("operations").EnumerateArray()).GetProperty("candidate").GetProperty("fullPath").GetString()!;
        await System.IO.File.WriteAllTextAsync(changed, "unique edited bytes");
        Assert.Equal(3, (await fixture.Run("cleanup", "apply", id, "--confirm")).ExitCode);
        Assert.Equal("unique edited bytes", await System.IO.File.ReadAllTextAsync(changed));
        Assert.Equal(1, (await fixture.Run("manifest", "verify", fixture.Root, "--manifest", before)).ExitCode);
        Assert.Equal(0, (await fixture.Run("manifest", "create", fixture.Root, "--output", after)).ExitCode);
        Assert.Equal(1, (await fixture.Run("manifest", "diff", "--before", before, "--after", after)).ExitCode);
    }

    [Fact]
    public async Task TwoCliProcessesCannotApplySameCandidateTwice()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new CliFixture();
        var scan = await fixture.Run("scan", fixture.Root);
        var plan = await fixture.Run("cleanup", "plan", scan.Data.GetProperty("id").GetString()!);
        var id = plan.Data.GetProperty("id").GetString()!;
        var operation = Assert.Single(plan.Data.GetProperty("operations").EnumerateArray());
        var results = await Task.WhenAll(fixture.Run("cleanup", "apply", id, "--confirm"), fixture.Run("cleanup", "apply", id, "--confirm"));
        Assert.Contains(results, x => x.ExitCode == 0);
        Assert.All(results, x => Assert.Contains(x.ExitCode, new[] { 0, 3 }));
        var candidate = operation.GetProperty("candidate").GetProperty("fullPath").GetString()!;
        var keeper = operation.GetProperty("keeper").GetProperty("fullPath").GetString()!;
        var target = operation.GetProperty("quarantinePath").GetString()!;
        Assert.False(System.IO.File.Exists(candidate));
        Assert.Equal("same generated content", await System.IO.File.ReadAllTextAsync(keeper));
        Assert.Equal("same generated content", await System.IO.File.ReadAllTextAsync(target));
        Assert.Equal(1, new FileGuardStore(fixture.DataDirectory).ListOperations().Total);
    }

    [Fact]
    public async Task CancellationPersistsCancelledScanAndReleasesHandle()
    {
        using var fixture = new CliFixture();
        await using (var file = new FileStream(fixture.File("large.bin"), FileMode.CreateNew)) file.SetLength(8 * 1024 * 1024);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        using var output = new StringWriter();
        using var error = new StringWriter();
        var code = await CliApplication.RunAsync(["scan", fixture.Root, "--data", fixture.DataDirectory, "--hash-all", "--bytes-per-second", "32768", "--json"], output, error, cancellation.Token);
        Assert.Equal(130, code);
        var scan = Assert.Single(new FileGuardStore(fixture.DataDirectory).ListScans().Items);
        Assert.Equal(ScanState.Cancelled, scan.State);
        using var reopened = new FileStream(fixture.File("large.bin"), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    }

    private sealed class CliFixture : IDisposable
    {
        private readonly string sandbox;
        public readonly string Repository;
        public string Root { get; }
        public string DataDirectory => Child("state");
        public CliFixture()
        {
            var parent = new DirectoryInfo(AppContext.BaseDirectory);
            while (parent is not null && !Directory.Exists(Path.Combine(parent.FullName, "src", "FileGuard.Cli"))) parent = parent.Parent;
            Repository = parent?.FullName ?? throw new InvalidOperationException("Repository root not found.");
            sandbox = Path.Combine(Repository, ".test-data", "cli-" + Guid.NewGuid().ToString("N"));
            Root = Child("files"); Directory.CreateDirectory(Root);
            System.IO.File.WriteAllText(File("a.txt"), "same generated content");
            System.IO.File.WriteAllText(File("b.txt"), "same generated content");
        }
        public string Child(string name) => Path.Combine(sandbox, name);
        public string File(string name) => Path.Combine(Root, name);
        public async Task<Result> Run(params string[] args)
        {
            var start = new ProcessStartInfo("dotnet") { WorkingDirectory = Repository, UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            start.ArgumentList.Add(typeof(CliApplication).Assembly.Location);
            foreach (var arg in args) start.ArgumentList.Add(arg);
            start.ArgumentList.Add("--data"); start.ArgumentList.Add(DataDirectory); start.ArgumentList.Add("--allow-root"); start.ArgumentList.Add(Root); start.ArgumentList.Add("--json");
            using var process = Process.Start(start)!;
            var stdout = await process.StandardOutput.ReadToEndAsync(); var stderr = await process.StandardError.ReadToEndAsync(); await process.WaitForExitAsync();
            Assert.False(string.IsNullOrWhiteSpace(stdout), stderr);
            using var document = JsonDocument.Parse(stdout);
            return new(process.ExitCode, document.RootElement.Clone(), stderr);
        }
        public void Dispose()
        {
            var root = Path.GetFullPath(Path.Combine(Repository, ".test-data")); var path = Path.GetFullPath(sandbox);
            Assert.StartsWith(root + Path.DirectorySeparatorChar, path, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
            if (Directory.Exists(path)) Directory.Delete(path, true);
        }
    }
    private sealed record Result(int ExitCode, JsonElement Document, string Stderr)
    {
        public JsonElement Data => Document.GetProperty("data");
    }
}
