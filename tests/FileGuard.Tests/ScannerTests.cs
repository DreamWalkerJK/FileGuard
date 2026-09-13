using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using FileGuard.Core;
using Microsoft.Win32.SafeHandles;
using Xunit;

namespace FileGuard.Tests;

public sealed class ScannerTests
{
    [Fact]
    public async Task HashesOnlyEqualSizeCandidatesAndDistinguishesSameNameContent()
    {
        using var fixture = new ScanFixture();
        fixture.Write("a.txt", "equal"); fixture.Write("nested/b.txt", "equal"); fixture.Write("other/a.txt", "DIFF!");
        fixture.Write("unique.bin", "a uniquely sized file");
        var scan = await fixture.Scanner.ScanAsync(new() { Roots = [fixture.Root], Concurrency = 3, ChannelCapacity = 1 });
        Assert.Equal(ScanState.Completed, scan.State);
        Assert.Equal(4, scan.FileCount); Assert.Equal(3, scan.HashCount);
        var group = Assert.Single(fixture.Scanner.GetDuplicates(scan.Id));
        Assert.Equal(2, group.Files.Count); Assert.Equal(5, group.Size);
        Assert.Null(fixture.Store.EnumerateFiles(scan.Id).Single(x => x.RelativePath == "unique.bin").Sha256);
    }

    [Fact]
    public async Task EmptyFilesHaveRealSha256AndZeroLogicalBytes()
    {
        using var fixture = new ScanFixture(); fixture.Write("empty-a", ""); fixture.Write("empty-b", "");
        var scan = await fixture.Scan();
        var group = Assert.Single(fixture.Scanner.GetDuplicates(scan.Id));
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", group.Sha256);
        Assert.Equal(0, group.LogicalDuplicateBytes);
    }

    [Fact]
    public async Task MultiRootScansAvoidOverlappingRootDuplicatesAndEnforceAllowlist()
    {
        using var fixture = new ScanFixture(); fixture.Write("one/a", "same"); fixture.Write("two/b", "same");
        var scan = await fixture.Scanner.ScanAsync(new() { Roots = [fixture.Root, Path.Combine(fixture.Root, "one")] });
        Assert.Equal(2, scan.FileCount);
        var split = await fixture.Scanner.ScanAsync(new() { Roots = [Path.Combine(fixture.Root, "one"), Path.Combine(fixture.Root, "two")] });
        Assert.Single(fixture.Scanner.GetDuplicates(split.Id));
        await Assert.ThrowsAsync<GuardException>(() => fixture.Scanner.ScanAsync(new() { Roots = [fixture.Base] }));
    }

    [Fact]
    public async Task GlobsExtensionSizeAndModificationFiltersActuallyExcludeFiles()
    {
        using var fixture = new ScanFixture();
        fixture.Write("root.txt", "valid"); fixture.Write("nested/good.txt", "valid"); fixture.Write("ignored/no.txt", "valid");
        fixture.Write("nested/short.txt", "x"); fixture.Write("nested/wrong.bin", "valid"); fixture.Write("old.txt", "valid");
        File.SetLastWriteTimeUtc(Path.Combine(fixture.Root, "old.txt"), DateTime.UtcNow.AddDays(-5));
        var scan = await fixture.Scanner.ScanAsync(new()
        {
            Roots = [fixture.Root], Include = ["**/*.txt"], Exclude = ["ignored/**"], Extensions = ["txt"],
            MinSize = 2, MaxSize = 6, ModifiedAfter = DateTimeOffset.UtcNow.AddDays(-1), HashAll = true
        });
        Assert.Equal(new[] { "nested/good.txt", "root.txt" }, fixture.Store.EnumerateFiles(scan.Id).Select(x => x.RelativePath).Order().ToArray());
        Assert.Equal(2, scan.HashCount);
    }

    [Fact]
    public async Task HandlesUnicodeSpecialCharactersDeepAndLongPaths()
    {
        using var fixture = new ScanFixture();
        var deep = string.Join('/', Enumerable.Repeat("深层目录" + new string('x', 35), 8));
        fixture.Write(deep + "/数据 & #[1].txt", "你好完整性"); fixture.Write("副本.txt", "你好完整性");
        var scan = await fixture.Scan();
        Assert.Equal(ScanState.Completed, scan.State);
        Assert.Single(fixture.Scanner.GetDuplicates(scan.Id));
    }

    [Fact]
    public async Task HardlinkAliasesAreNotIndependentDuplicates()
    {
        using var fixture = new ScanFixture(); var original = fixture.Write("a", "shared");
        ScanFixture.HardLink(Path.Combine(fixture.Root, "alias"), original);
        var scan = await fixture.Scan();
        if (OperatingSystem.IsWindows())
        {
            Assert.Empty(fixture.Scanner.GetDuplicates(scan.Id));
            Assert.Single(fixture.Store.EnumerateFiles(scan.Id).Select(x => x.Identity).Distinct());
            Assert.All(fixture.Store.EnumerateFiles(scan.Id), x => Assert.True(x.LinkCount >= 2));
        }
        fixture.Write("independent", "shared");
        scan = await fixture.Scan();
        var group = Assert.Single(fixture.Scanner.GetDuplicates(scan.Id));
        Assert.Equal(3, group.Files.Count); Assert.Null(group.EstimatedReclaimableBytes);
    }

    [Fact]
    public async Task JunctionsAndLinkLoopsAreRecordedWithoutFollowingTargets()
    {
        using var fixture = new ScanFixture(); fixture.Write("visible.txt", "same");
        var outside = Path.Combine(fixture.Base, "outside"); Directory.CreateDirectory(outside);
        File.WriteAllText(Path.Combine(outside, "private.txt"), "outside");
        ScanFixture.DirectoryLink(Path.Combine(fixture.Root, "escape"), outside);
        ScanFixture.DirectoryLink(Path.Combine(fixture.Root, "loop"), fixture.Root);
        var scan = await fixture.Scan();
        var records = fixture.Store.EnumerateFiles(scan.Id).ToArray();
        Assert.Equal(2, records.Count(x => x.State == FileState.SkippedLink));
        Assert.DoesNotContain(records, x => x.RelativePath.Contains("private", StringComparison.Ordinal));
        Assert.Equal(3, scan.FileCount);
        await Assert.ThrowsAsync<GuardException>(() => fixture.Scanner.ScanAsync(new() { Roots = [Path.Combine(fixture.Root, "escape")] }));
    }

    [NonWindowsSymbolicLinkFact]
    public async Task SymbolicFileLinkIsSkipped()
    {
        using var fixture = new ScanFixture(); var original = fixture.Write("original", "same");
        File.CreateSymbolicLink(Path.Combine(fixture.Root, "symlink"), original);
        var scan = await fixture.Scan();
        Assert.Contains(fixture.Store.EnumerateFiles(scan.Id), x => x.RelativePath == "symlink" && x.State == FileState.SkippedLink);
        Assert.Empty(fixture.Scanner.GetDuplicates(scan.Id));
    }

    [Fact]
    public async Task FileChangedOrRemovedBetweenIndexingAndHashingIsRecorded()
    {
        using var fixture = new ScanFixture(); fixture.Write("changed", "same"); fixture.Write("missing", "same"); fixture.Write("keeper", "same");
        var edited = false;
        var progress = new ImmediateProgress<ScanProgress>(p =>
        {
            if (p.State != ScanState.Hashing || edited) return;
            edited = true;
            File.WriteAllText(Path.Combine(fixture.Root, "changed"), "changed-size");
            File.Delete(Path.Combine(fixture.Root, "missing"));
        });
        var scan = await fixture.Scanner.ScanAsync(new() { Roots = [fixture.Root] }, progress);
        Assert.Equal(ScanState.PartialFailure, scan.State);
        var records = fixture.Store.EnumerateFiles(scan.Id).ToArray();
        Assert.Equal(FileState.Unstable, records.Single(x => x.RelativePath == "changed").State);
        Assert.Equal(FileState.Missing, records.Single(x => x.RelativePath == "missing").State);
        Assert.Equal(2, scan.ErrorCount); Assert.Empty(fixture.Scanner.GetDuplicates(scan.Id));
    }

    [Fact]
    public async Task ExclusiveFileOccupancyIsExplicitUnreadable()
    {
        if (!OperatingSystem.IsWindows()) return; // Windows sharing is mandatory; Unix advisory sharing differs.
        using var fixture = new ScanFixture(); var path = fixture.Write("locked", "same");
        using var occupied = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var scan = await fixture.Scan();
        Assert.Equal(ScanState.PartialFailure, scan.State);
        Assert.Equal(FileState.Unreadable, Assert.Single(fixture.Store.EnumerateFiles(scan.Id)).State);
    }

    [Fact]
    public async Task CancellationPersistsTerminalStateAndReleasesReadHandles()
    {
        using var fixture = new ScanFixture(); var path = fixture.Write("large", new string('a', 512 * 1024));
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var scan = await fixture.Scanner.ScanAsync(new() { Roots = [fixture.Root], HashAll = true, BytesPerSecond = 128 * 1024 }, cancellationToken: cancel.Token);
        Assert.Equal(ScanState.Cancelled, scan.State);
        Assert.Equal(ScanState.Cancelled, fixture.Store.GetScan(scan.Id).State);
        using var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.True(exclusive.CanWrite);
    }

    [Fact]
    public async Task AggregateReadRateAndProgressAreObservable()
    {
        using var fixture = new ScanFixture(); fixture.Write("first", new string('a', 128 * 1024)); fixture.Write("second", new string('a', 128 * 1024));
        var progress = new List<ScanProgress>();
        var clock = Stopwatch.StartNew();
        var scan = await fixture.Scanner.ScanAsync(new() { Roots = [fixture.Root], Concurrency = 2, BytesPerSecond = 256 * 1024 },
            new ImmediateProgress<ScanProgress>(progress.Add));
        Assert.True(clock.Elapsed >= TimeSpan.FromMilliseconds(850));
        Assert.Equal(256 * 1024, scan.BytesRead); Assert.Equal(2, scan.HashCount);
        Assert.Contains(progress, x => x.State == ScanState.Enumerating);
        Assert.Contains(progress, x => x.State == ScanState.Hashing);
        Assert.Equal(ScanState.Completed, progress[^1].State);
    }

    [Fact]
    public async Task InternalStoreAndQuarantineAreExcluded()
    {
        using var fixture = new ScanFixture();
        var settings = new GuardSettings { DataDirectory = Path.Combine(fixture.Root, "runtime"), AllowedRoots = [fixture.Root],
            QuarantineDirectory = Path.Combine(fixture.Root, "quarantine") };
        var store = new FileGuardStore(settings.DataDirectory); store.Initialize();
        fixture.Write("quarantine/hidden", "same"); fixture.Write("visible", "same");
        var scan = await new Scanner(store, settings).ScanAsync(new() { Roots = [fixture.Root], HashAll = true });
        Assert.Equal("visible", Assert.Single(store.EnumerateFiles(scan.Id)).RelativePath);
    }

    [Fact]
    public async Task WindowsCaseInsensitiveAndLinuxCaseSensitiveGlobsUseHostSemantics()
    {
        using var fixture = new ScanFixture(); fixture.Write("Mixed.TXT", "same");
        var scan = await fixture.Scanner.ScanAsync(new() { Roots = [fixture.Root], Include = ["*.txt"], HashAll = true });
        var expected = OperatingSystem.IsWindows() && !PathSafety.IsCaseSensitiveDirectory(fixture.Root) ? 1 : 0;
        Assert.Equal(expected, scan.FileCount);
    }

    [Fact]
    public async Task ExplicitExistingScanIdCannotOverwriteCompletedIndex()
    {
        using var fixture = new ScanFixture(); fixture.Write("a", "same"); var scan = await fixture.Scan();
        await Assert.ThrowsAsync<GuardException>(() => fixture.Scanner.ScanAsync(new() { Roots = [fixture.Root] }, scanId: scan.Id));
        Assert.Equal(scan.FileCount, fixture.Store.GetScan(scan.Id).FileCount);
    }

    [Fact]
    public async Task QueuedWebScanCanBeClaimedOnceAndRetainsSubmissionTime()
    {
        using var fixture = new ScanFixture(); fixture.Write("a", "same");
        var queued = new ScanRecord { State = ScanState.Queued, Owner = FileGuardStore.CurrentOwner, CreatedUtc = DateTimeOffset.UtcNow.AddSeconds(-10) };
        fixture.Store.SaveScan(queued);
        var completed = await fixture.Scanner.ScanAsync(new() { Roots = [fixture.Root] }, scanId: queued.Id);
        Assert.Equal(ScanState.Completed, completed.State); Assert.Equal(queued.CreatedUtc, completed.CreatedUtc);
        await Assert.ThrowsAsync<GuardException>(() => fixture.Scanner.ScanAsync(new() { Roots = [fixture.Root] }, scanId: queued.Id));
    }

    [Fact]
    public async Task SparseLargeFilesAreStreamedAndNeverClaimDefinitePhysicalCapacity()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new ScanFixture();
        const long size = 16 * 1024 * 1024;
        ScanFixture.Sparse(Path.Combine(fixture.Root, "sparse-a"), size);
        ScanFixture.Sparse(Path.Combine(fixture.Root, "sparse-b"), size);
        var scan = await fixture.Scan();
        Assert.Equal(size * 2, scan.BytesRead);
        var group = Assert.Single(fixture.Scanner.GetDuplicates(scan.Id));
        Assert.All(group.Files, x => Assert.True(x.SparseOrCompressed));
        Assert.Equal(size, group.LogicalDuplicateBytes); Assert.Null(group.EstimatedReclaimableBytes);
    }

    [Fact]
    public async Task IdentityReplacementWithUnchangedSizeAndTimestampIsUnstable()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new ScanFixture();
        var path = fixture.Write("replaced", "same"); fixture.Write("keeper", "same");
        var time = File.GetLastWriteTimeUtc(path);
        var changed = false;
        var scan = await fixture.Scanner.ScanAsync(new() { Roots = [fixture.Root] }, new ImmediateProgress<ScanProgress>(p =>
        {
            if (p.State != ScanState.Hashing || changed) return;
            changed = true;
            File.Move(path, Path.Combine(fixture.Base, "old-object"));
            File.WriteAllText(path, "same"); File.SetLastWriteTimeUtc(path, time);
        }));
        Assert.Equal(FileState.Unstable, fixture.Store.EnumerateFiles(scan.Id).Single(x => x.RelativePath == "replaced").State);
        Assert.Empty(fixture.Scanner.GetDuplicates(scan.Id));
    }
}

internal sealed class ImmediateProgress<T>(Action<T> report) : IProgress<T>
{
    public void Report(T value) => report(value);
}

internal sealed class ScanFixture : IDisposable
{
    public string Base { get; }
    public string Root { get; }
    public FileGuardStore Store { get; }
    public Scanner Scanner { get; }
    public ManifestService Manifests { get; }
    private readonly string _testParent;
    public ScanFixture()
    {
        var project = new DirectoryInfo(AppContext.BaseDirectory);
        while (project is not null && !File.Exists(Path.Combine(project.FullName, "FileGuard.slnx"))) project = project.Parent;
        _testParent = Path.GetFullPath(Path.Combine(project?.FullName ?? AppContext.BaseDirectory, ".test-artifacts", "scanner"));
        Base = Path.Combine(_testParent, Guid.NewGuid().ToString("N")); Root = Path.Combine(Base, "root"); Directory.CreateDirectory(Root);
        var settings = new GuardSettings { DataDirectory = Path.Combine(Base, "state"), AllowedRoots = [Root] };
        Store = new FileGuardStore(settings.DataDirectory); Store.Initialize(); Scanner = new(Store, settings); Manifests = new(Scanner, Store);
    }
    public string Write(string relative, string contents)
    {
        var path = Path.GetFullPath(Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar)));
        Assert.True(PathSafety.IsWithin(path, Root));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, contents, new UTF8Encoding(false)); return path;
    }
    public Task<ScanRecord> Scan() => Scanner.ScanAsync(new() { Roots = [Root] });
    public void Dispose()
    {
        var full = Path.GetFullPath(Base);
        Assert.StartsWith(_testParent + Path.DirectorySeparatorChar, full, StringComparison.Ordinal);
        if (!Directory.Exists(full)) return;
        foreach (var entry in Directory.EnumerateFileSystemEntries(Root))
        {
            Assert.True(PathSafety.IsWithin(entry, Root));
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) == 0) continue;
            if (OperatingSystem.IsWindows()) Assert.True(RemoveDirectoryW(entry), "Unable to remove test junction: " + Marshal.GetLastPInvokeError());
            else Directory.Delete(entry);
        }
        Directory.Delete(full, recursive: true);
    }
    public static void HardLink(string link, string existing)
    {
        if (OperatingSystem.IsWindows()) Assert.True(CreateHardLinkW(link, existing, IntPtr.Zero), "Hardlink failed: " + Marshal.GetLastPInvokeError());
        else Assert.Equal(0, Link(existing, link));
    }
    public static void DirectoryLink(string link, string target)
    {
        if (!OperatingSystem.IsWindows()) { Directory.CreateSymbolicLink(link, target); return; }
        var info = new ProcessStartInfo("cmd.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        info.ArgumentList.Add("/c"); info.ArgumentList.Add("mklink"); info.ArgumentList.Add("/J"); info.ArgumentList.Add(link); info.ArgumentList.Add(target);
        using var process = Process.Start(info)!;
        process.WaitForExit(); Assert.True(process.ExitCode == 0, process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd());
    }
    public static SafeFileHandle LockDirectory(string directory)
    {
        var handle = CreateFileW(directory, 0x40000000, 0, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        Assert.False(handle.IsInvalid); return handle;
    }
    public static void Sparse(string path, long size)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        Assert.True(DeviceIoControl(file.SafeFileHandle, 0x900c4, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero));
        file.SetLength(size); file.Position = size - 1; file.WriteByte(1);
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string fileName, string existingFileName, IntPtr securityAttributes);
    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int Link(string oldPath, string newPath);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveDirectoryW(string path);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
}

internal sealed class NonWindowsSymbolicLinkFactAttribute : FactAttribute
{
    public NonWindowsSymbolicLinkFactAttribute()
    {
        if (OperatingSystem.IsWindows()) Skip = "This Windows test account lacks SeCreateSymbolicLinkPrivilege; junction reparse boundaries are tested separately.";
    }
}
