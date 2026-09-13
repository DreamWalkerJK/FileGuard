using System.Diagnostics;
using FileGuard.Core;
using Xunit;

namespace FileGuard.Tests;

public sealed class CleanupTests
{
    [Fact]
    public async Task HandlesPreventCandidateAndAncestorReplacementDuringApply()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new CleanupFixture();
        var operation = Assert.Single((await fixture.Plan()).Operations);
        var checkedHandles = false;
        fixture.Cleanup.Checkpoint = (stage, current) =>
        {
            if (stage != "started") return;
            Assert.Throws<IOException>(() => File.Move(current.Candidate.FullPath, fixture.Child("replacement")));
            Assert.Throws<IOException>(() => File.WriteAllText(current.Keeper.FullPath, "change"));
            Assert.Throws<IOException>(() => File.WriteAllText(current.Candidate.FullPath + ":concurrent", "unique stream"));
            Assert.Throws<IOException>(() => Directory.Move(fixture.Settings.AllowedRoots[0], fixture.Child("moved-directory")));
            checkedHandles = true;
        };
        Assert.Equal(OperationState.Completed, Assert.Single(await fixture.Cleanup.ApplyAsync(operation.PlanId, true)).State);
        Assert.True(checkedHandles);
    }

    [Fact]
    public async Task AlternateDataStreamAddedAfterScanIsPreservedAndRefused()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new CleanupFixture();
        var operation = Assert.Single((await fixture.Plan()).Operations);
        await File.WriteAllTextAsync(operation.Candidate.FullPath + ":unique", "unique secondary stream");
        Assert.Equal(OperationState.Skipped, Assert.Single(await fixture.Cleanup.ApplyAsync(operation.PlanId, true)).State);
        Assert.Equal("unique secondary stream", await File.ReadAllTextAsync(operation.Candidate.FullPath + ":unique"));
        Assert.True(File.Exists(operation.Candidate.FullPath));
        var scan = await fixture.Scanner.ScanAsync(new ScanOptions { Roots = fixture.Settings.AllowedRoots });
        Assert.Equal(ScanState.PartialFailure, scan.State);
        Assert.Contains(fixture.Store.EnumerateFiles(scan.Id), x => x.FullPath == operation.Candidate.FullPath && x.State == FileState.Unreadable);
        Assert.Empty(fixture.Scanner.GetDuplicates(scan.Id));
    }

    [CrossVolumeTheory]
    [InlineData("copy-created", OperationState.Planned)]
    [InlineData("copied", OperationState.Planned)]
    [InlineData("source-deleted", OperationState.Completed)]
    public async Task CrossVolumeInterruptionsRecoverWithoutLosingData(string checkpoint, OperationState expected)
    {
        using var fixture = new CleanupFixture(crossVolume: true);
        var operation = Assert.Single((await fixture.Plan()).Operations);
        fixture.Cleanup.Checkpoint = (stage, _) => { if (stage == checkpoint) throw new InjectedCrash(); };
        await Assert.ThrowsAsync<InjectedCrash>(() => fixture.Cleanup.ApplyAsync(operation.PlanId, true));
        fixture.Cleanup.Checkpoint = null;
        Assert.Equal(expected, Assert.Single(await fixture.Cleanup.RecoverAsync()).State);
        if (expected == OperationState.Planned) Assert.Equal(OperationState.Completed, Assert.Single(await fixture.Cleanup.ApplyAsync(operation.PlanId, true)).State);
        Assert.Equal("same content", await File.ReadAllTextAsync(operation.QuarantinePath));
        Assert.False(File.Exists(operation.Candidate.FullPath));
        Assert.Equal(OperationState.Restored, (await fixture.Cleanup.RestoreAsync(operation.Id, true)).State);
        Assert.Equal("same content", await File.ReadAllTextAsync(operation.Candidate.FullPath));
        Assert.Equal(operation.Candidate.ModifiedUtc.UtcDateTime, File.GetLastWriteTimeUtc(operation.Candidate.FullPath));
    }

    [CrossVolumeTheory]
    [InlineData("restore-copy-created")]
    [InlineData("restore-copied")]
    public async Task CrossVolumeRestoreInterruptionPreservesVerifiedQuarantine(string checkpoint)
    {
        using var fixture = new CleanupFixture(crossVolume: true);
        var operation = Assert.Single((await fixture.Plan()).Operations);
        Assert.Equal(OperationState.Completed, Assert.Single(await fixture.Cleanup.ApplyAsync(operation.PlanId, true)).State);
        fixture.Cleanup.Checkpoint = (stage, _) => { if (stage == checkpoint) throw new InjectedCrash(); };
        await Assert.ThrowsAsync<InjectedCrash>(() => fixture.Cleanup.RestoreAsync(operation.Id, true));
        fixture.Cleanup.Checkpoint = null;
        Assert.Equal(OperationState.Completed, Assert.Single(await fixture.Cleanup.RecoverAsync()).State);
        Assert.False(File.Exists(operation.Candidate.FullPath));
        Assert.Equal("same content", await File.ReadAllTextAsync(operation.QuarantinePath));
        Assert.Equal(OperationState.Restored, (await fixture.Cleanup.RestoreAsync(operation.Id, true)).State);
    }

    [CrossVolumeTheory]
    [InlineData(0)]
    public async Task InsufficientTargetCapacityLeavesOriginalIntact(long availableBytes)
    {
        using var fixture = new CleanupFixture(crossVolume: true);
        var operation = Assert.Single((await fixture.Plan()).Operations);
        fixture.Cleanup.AvailableSpace = _ => availableBytes;
        var result = Assert.Single(await fixture.Cleanup.ApplyAsync(operation.PlanId, true));
        Assert.Equal(OperationState.NeedsReview, result.State);
        Assert.Contains("容量不足", result.Detail);
        Assert.Equal("same content", await File.ReadAllTextAsync(operation.Candidate.FullPath));
        Assert.False(File.Exists(operation.QuarantinePath));
        Assert.Equal(OperationState.Planned, Assert.Single(await fixture.Cleanup.RecoverAsync()).State);
    }

    [CrossVolumeTheory]
    [InlineData("copy-created", false)]
    [InlineData("copied", false)]
    [InlineData("restore-copy-created", true)]
    [InlineData("restore-copied", true)]
    public async Task RecoveryNeverDeletesPostCrashEditsToSameFileIdentity(string checkpoint, bool restore)
    {
        using var fixture = new CleanupFixture(crossVolume: true);
        var operation = Assert.Single((await fixture.Plan()).Operations);
        if (restore) await fixture.Cleanup.ApplyAsync(operation.PlanId, true);
        fixture.Cleanup.Checkpoint = (stage, _) => { if (stage == checkpoint) throw new InjectedCrash(); };
        await Assert.ThrowsAsync<InjectedCrash>(async () =>
        {
            if (restore) await fixture.Cleanup.RestoreAsync(operation.Id, true);
            else await fixture.Cleanup.ApplyAsync(operation.PlanId, true);
        });
        var edited = restore ? operation.Candidate.FullPath : operation.QuarantinePath;
        var editRoot = restore ? operation.Candidate.Root : fixture.Settings.QuarantineDirectory!;
        string? before;
        using (var opened = SafeFile.OpenRead(edited, editRoot)) before = opened.Snapshot().Identity;
        await File.WriteAllTextAsync(edited, "unique new data");
        using (var opened = SafeFile.OpenRead(edited, editRoot)) Assert.Equal(before, opened.Snapshot().Identity);
        fixture.Cleanup.Checkpoint = null;
        Assert.Equal(OperationState.NeedsReview, Assert.Single(await fixture.Cleanup.RecoverAsync()).State);
        Assert.Equal("unique new data", await File.ReadAllTextAsync(edited));
        Assert.True(File.Exists(operation.Candidate.FullPath));
        Assert.True(File.Exists(operation.QuarantinePath));
    }

    [Theory]
    [InlineData("renamed", "apply")]
    [InlineData("restore-renamed", "restore")]
    [InlineData("purged", "purge")]
    public async Task ActualOperationCheckpointsRecoverAcrossServiceRestart(string checkpoint, string action)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new CleanupFixture();
        var operation = Assert.Single((await fixture.Plan()).Operations);
        if (action != "apply") await fixture.Cleanup.ApplyAsync(operation.PlanId, true);
        fixture.Cleanup.Checkpoint = (stage, _) => { if (stage == checkpoint) throw new InjectedCrash(); };
        await Assert.ThrowsAsync<InjectedCrash>(async () =>
        {
            if (action == "apply") await fixture.Cleanup.ApplyAsync(operation.PlanId, true);
            else if (action == "restore") await fixture.Cleanup.RestoreAsync(operation.Id, true);
            else await fixture.Cleanup.PurgeAsync(operation.Id, true, true);
        });
        var restarted = new FileGuardStore(fixture.Settings.DataDirectory);
        restarted.Initialize();
        var recovery = new CleanupService(restarted, fixture.Settings, new Scanner(restarted, fixture.Settings));
        var recovered = Assert.Single(await recovery.RecoverAsync());
        Assert.Equal(action switch { "apply" => OperationState.Completed, "restore" => OperationState.Restored, _ => OperationState.Purged }, recovered.State);
    }

    [Fact]
    public async Task RealQuarantineRestoreAndPurgeRequireExplicitConfirmation()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new CleanupFixture();
        var plan = await fixture.Plan();
        var operation = Assert.Single(plan.Operations);
        var dry = await fixture.Cleanup.ApplyAsync(plan.Id);
        Assert.True(Assert.Single(dry).DryRun);
        Assert.True(File.Exists(operation.Candidate.FullPath));
        var result = await fixture.Cleanup.ApplyAsync(plan.Id, true);
        Assert.Equal(OperationState.Completed, Assert.Single(result).State);
        Assert.False(File.Exists(operation.Candidate.FullPath));
        Assert.Equal("same content", await File.ReadAllTextAsync(operation.QuarantinePath));
        Assert.True(File.Exists(operation.Keeper.FullPath));
        Assert.Equal(OperationState.Completed, Assert.Single(await fixture.Cleanup.ApplyAsync(plan.Id, true)).State);
        Assert.True((await fixture.Cleanup.RestoreAsync(operation.Id)).DryRun);
        Assert.False(File.Exists(operation.Candidate.FullPath));
        Assert.Equal(OperationState.Restored, (await fixture.Cleanup.RestoreAsync(operation.Id, true)).State);
        Assert.Equal("same content", await File.ReadAllTextAsync(operation.Candidate.FullPath));
        plan = await fixture.Plan();
        operation = Assert.Single(plan.Operations);
        Assert.Equal(OperationState.Completed, Assert.Single(await fixture.Cleanup.ApplyAsync(plan.Id, true)).State);
        await Assert.ThrowsAsync<GuardException>(() => fixture.Cleanup.PurgeAsync(operation.Id, true));
        Assert.True(File.Exists(operation.QuarantinePath));
        Assert.Equal(OperationState.Purged, (await fixture.Cleanup.PurgeAsync(operation.Id, true, true)).State);
        Assert.False(File.Exists(operation.QuarantinePath));
        Assert.Contains(fixture.Store.ListHistory(0, 100).Items, x => x.SafetyCheck.Contains("byte-compare", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("changed")]
    [InlineData("identity")]
    [InlineData("keeper")]
    [InlineData("expired")]
    public async Task StalePlansPreserveFilesAndRecordSafetyRefusal(string reason)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new CleanupFixture();
        var plan = await fixture.Plan();
        var operation = Assert.Single(plan.Operations);
        if (reason == "changed") await File.WriteAllTextAsync(operation.Candidate.FullPath, "other bytes");
        if (reason == "identity")
        {
            File.Move(operation.Candidate.FullPath, fixture.Child("original-away"));
            await File.WriteAllTextAsync(operation.Candidate.FullPath, "same content");
            File.SetLastWriteTimeUtc(operation.Candidate.FullPath, operation.Candidate.ModifiedUtc.UtcDateTime);
        }
        if (reason == "keeper") File.Move(operation.Keeper.FullPath, fixture.Child("keeper-away"));
        if (reason == "expired") fixture.Store.SavePlan(plan with { ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1) });
        Assert.Equal(OperationState.Skipped, Assert.Single(await fixture.Cleanup.ApplyAsync(plan.Id, true)).State);
        Assert.True(File.Exists(operation.Candidate.FullPath));
        Assert.False(File.Exists(operation.QuarantinePath));
        Assert.NotEmpty(fixture.Store.GetOperation(operation.Id).Detail!);
    }

    [Fact]
    public async Task RestoreConflictAndQuarantineReplacementNeverOverwrite()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new CleanupFixture();
        var operation = Assert.Single((await fixture.Plan()).Operations);
        await fixture.Cleanup.ApplyAsync(operation.PlanId, true);
        await File.WriteAllTextAsync(operation.Candidate.FullPath, "new unique file");
        Assert.Equal(OperationState.Failed, (await fixture.Cleanup.RestoreAsync(operation.Id, true)).State);
        Assert.Equal("new unique file", await File.ReadAllTextAsync(operation.Candidate.FullPath));
        Assert.True(File.Exists(operation.QuarantinePath));
        File.Move(operation.QuarantinePath, fixture.Child("quarantine-original"));
        await File.WriteAllTextAsync(operation.QuarantinePath, "same content");
        Assert.Equal(OperationState.Failed, (await fixture.Cleanup.PurgeAsync(operation.Id, true, true)).State);
        Assert.True(File.Exists(operation.QuarantinePath));
    }

    [Fact]
    public async Task InterruptedRenameIsReconciledUsingIdentityAndDigest()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new CleanupFixture();
        var operation = Assert.Single((await fixture.Plan()).Operations);
        Directory.CreateDirectory(Path.GetDirectoryName(operation.QuarantinePath)!);
        operation.State = OperationState.Started;
        operation.QuarantineIdentity = operation.Candidate.Identity;
        fixture.Store.SaveOperation(operation);
        File.Move(operation.Candidate.FullPath, operation.QuarantinePath);
        var restarted = new FileGuardStore(fixture.Settings.DataDirectory);
        restarted.Initialize();
        var recovery = new CleanupService(restarted, fixture.Settings, new Scanner(restarted, fixture.Settings));
        Assert.Equal(OperationState.Completed, Assert.Single(await recovery.RecoverAsync()).State);
        Assert.Equal(OperationState.Restored, (await recovery.RestoreAsync(operation.Id, true)).State);
    }

    [Fact]
    public async Task InterruptedScanIsMarkedWithoutStealingLiveOwners()
    {
        using var fixture = new CleanupFixture();
        var dead = new ScanRecord { Owner = "2147483647:1", State = ScanState.Hashing };
        var live = new ScanRecord { Owner = FileGuardStore.CurrentOwner, State = ScanState.Hashing };
        fixture.Store.SaveScan(dead);
        fixture.Store.SaveScan(live);
        new FileGuardStore(fixture.Settings.DataDirectory).Initialize();
        Assert.Equal(ScanState.Interrupted, fixture.Store.GetScan(dead.Id).State);
        Assert.Equal(ScanState.Hashing, fixture.Store.GetScan(live.Id).State);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task MutationLockExcludesASeparateOperatingSystemProcess()
    {
        using var fixture = new CleanupFixture();
        using var held = fixture.Store.AcquireMutationLock();
        var start = new ProcessStartInfo("pwsh") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add("try { $f=[System.IO.FileStream]::new($env:FILEGUARD_LOCK_TEST,[System.IO.FileMode]::OpenOrCreate,[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None); $f.Dispose(); exit 9 } catch { exit 0 }");
        start.Environment["FILEGUARD_LOCK_TEST"] = Path.Combine(fixture.Settings.DataDirectory, "mutation.lock");
        using var child = Process.Start(start)!;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await child.WaitForExitAsync(timeout.Token);
        Assert.Equal(0, child.ExitCode);
    }

    [Fact]
    public void UnknownDatabaseVersionIsRejected()
    {
        using var fixture = new CleanupFixture();
        using (var connection = fixture.Store.OpenConnection())
        using (var command = connection.CreateCommand()) { command.CommandText = "PRAGMA user_version=99"; command.ExecuteNonQuery(); }
        Assert.Throws<GuardException>(() => new FileGuardStore(fixture.Settings.DataDirectory).Initialize());
    }

    private sealed class CleanupFixture : IDisposable
    {
        private readonly string root;
        private readonly string? externalRoot;
        public GuardSettings Settings { get; }
        public FileGuardStore Store { get; }
        public Scanner Scanner { get; }
        public CleanupService Cleanup { get; }
        public CleanupFixture(bool crossVolume = false)
        {
            var repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
            var testRoot = Path.Combine(repository, ".test-data", "cleanup");
            root = Path.Combine(testRoot, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path.Combine(root, "files"));
            Settings = new() { AllowedRoots = [Path.Combine(root, "files")], DataDirectory = Path.Combine(root, "state") };
            if (crossVolume)
            {
                externalRoot = Path.Combine(Path.GetTempPath(), "FileGuard.Tests", "cross-volume", Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(externalRoot);
                Settings = Settings with { QuarantineDirectory = Path.Combine(externalRoot, "quarantine") };
                Assert.False(string.Equals(Path.GetPathRoot(root), Path.GetPathRoot(externalRoot), StringComparison.OrdinalIgnoreCase));
            }
            Store = new(Settings.DataDirectory);
            Store.Initialize();
            Scanner = new(Store, Settings);
            Cleanup = new(Store, Settings, Scanner);
        }
        public string Child(string name) => Path.Combine(root, name);
        public async Task<CleanupPlan> Plan()
        {
            var files = Settings.AllowedRoots[0];
            await File.WriteAllTextAsync(Path.Combine(files, "keep.txt"), "same content");
            await File.WriteAllTextAsync(Path.Combine(files, "remove.txt"), "same content");
            var scan = await Scanner.ScanAsync(new() { Roots = [files] });
            Assert.Equal(ScanState.Completed, scan.State);
            return Cleanup.CreatePlan(scan.Id, new());
        }
        public void Dispose()
        {
            var expected = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.test-data/cleanup"));
            if (!PathSafety.IsWithin(Path.GetFullPath(root), expected) || Path.GetFileName(root).Length != 32) throw new InvalidOperationException("Unsafe test cleanup path.");
            Directory.Delete(root, recursive: true);
            if (externalRoot is not null)
            {
                var externalBoundary = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "FileGuard.Tests", "cross-volume"));
                if (!PathSafety.IsWithin(externalRoot, externalBoundary) || Path.GetFileName(externalRoot).Length != 32) throw new InvalidOperationException("Unsafe external test cleanup path.");
                Directory.Delete(externalRoot, recursive: true);
            }
        }
    }
    private sealed class InjectedCrash : Exception;
}

public sealed class CrossVolumeTheoryAttribute : TheoryAttribute
{
    public CrossVolumeTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows() || string.Equals(Path.GetPathRoot(AppContext.BaseDirectory), Path.GetPathRoot(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase))
            Skip = "需要 Windows，并且测试仓库与系统临时目录位于不同卷。";
    }
}
