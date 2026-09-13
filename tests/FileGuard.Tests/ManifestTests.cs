using System.Text;
using System.Text.Json;
using FileGuard.Core;
using Xunit;

namespace FileGuard.Tests;

public sealed class ManifestTests
{
    [Fact]
    public async Task CreateVerifyAndDiffDetectContentMissingAddedAndIgnoreTimestampOnlyChanges()
    {
        using var fixture = new ScanFixture();
        fixture.Write("unchanged", "stable"); fixture.Write("changed", "before"); fixture.Write("missing", "gone");
        var before = await fixture.Manifests.CreateAsync(fixture.Root);
        Assert.All(before.Files, x => Assert.Equal(FileState.Ready, x.State));
        Assert.False((await fixture.Manifests.VerifyAsync(fixture.Root, before)).HasDifferences);
        fixture.Write("changed", "after!"); fixture.Write("added", "new");
        File.Delete(Path.Combine(fixture.Root, "missing"));
        File.SetLastWriteTimeUtc(Path.Combine(fixture.Root, "unchanged"), DateTime.UtcNow.AddDays(-2));
        var differences = (await fixture.Manifests.VerifyAsync(fixture.Root, before)).Differences.ToDictionary(x => x.Path);
        Assert.Equal(DifferenceKind.Unchanged, differences["unchanged"].Kind);
        Assert.Equal(DifferenceKind.ContentChanged, differences["changed"].Kind);
        Assert.Equal(DifferenceKind.Added, differences["added"].Kind);
        Assert.Equal(DifferenceKind.Missing, differences["missing"].Kind);
        var after = await fixture.Manifests.CreateAsync(fixture.Root);
        Assert.Equal(differences.Values.OrderBy(x => x.Path).Select(x => x.Kind), fixture.Manifests.Diff(before, after).Differences.OrderBy(x => x.Path).Select(x => x.Kind));
    }

    [Fact]
    public async Task CanonicalWriteIsDeterministicUtf8WithoutBomLfAndOrdinalSorted()
    {
        using var fixture = new ScanFixture(); fixture.Write("z", "same"); fixture.Write("a", "same"); fixture.Write("中文", "same");
        var manifest = await fixture.Manifests.CreateAsync(fixture.Root);
        var first = Path.Combine(fixture.Base, "one.json"); var second = Path.Combine(fixture.Base, "two.json");
        await ManifestService.WriteAsync(first, manifest with { Files = manifest.Files.AsEnumerable().Reverse().ToList() });
        await ManifestService.WriteAsync(second, manifest);
        var bytes = await File.ReadAllBytesAsync(first);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(second));
        Assert.False(bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }));
        Assert.DoesNotContain((byte)'\r', bytes); Assert.Equal((byte)'\n', bytes[^1]);
        var read = await ManifestService.ReadAsync(first);
        Assert.Equal(new[] { "a", "z", "中文" }, read.Files.Select(x => x.Path));
        Assert.False((await fixture.Manifests.VerifyAsync(fixture.Root, read)).HasDifferences);
    }

    [Theory]
    [InlineData("../outside")]
    [InlineData("dir/../../outside")]
    [InlineData("/absolute")]
    [InlineData("C:/absolute")]
    [InlineData("\\\\server\\share\\file")]
    [InlineData("dir\\file")]
    [InlineData("dir//file")]
    [InlineData("./file")]
    [InlineData("file/")]
    [InlineData("file:stream")]
    [InlineData("dir./file")]
    [InlineData("dir /file")]
    [InlineData("CON.txt")]
    [InlineData("nul")]
    [InlineData("LPT1.log")]
    public async Task RejectsEscapingAndAmbiguousManifestPaths(string path)
    {
        using var fixture = new ScanFixture();
        var manifest = Make(path);
        Assert.Throws<GuardException>(() => ManifestService.Validate(manifest));
        await Assert.ThrowsAsync<GuardException>(() => fixture.Manifests.VerifyAsync(fixture.Root, manifest));
    }

    [Fact]
    public async Task RejectsManifestTraversalThroughExistingJunction()
    {
        using var fixture = new ScanFixture(); var outside = Path.Combine(fixture.Base, "outside"); Directory.CreateDirectory(outside);
        File.WriteAllText(Path.Combine(outside, "private"), "secret");
        ScanFixture.DirectoryLink(Path.Combine(fixture.Root, "escape"), outside);
        await Assert.ThrowsAsync<GuardException>(() => fixture.Manifests.VerifyAsync(fixture.Root, Make("escape/private")));
        var created = await fixture.Manifests.CreateAsync(fixture.Root);
        Assert.Empty(created.Files);
    }

    [Fact]
    public void RejectsSchemaAlgorithmDuplicatePathsInvalidHashAndUnfinishedState()
    {
        var valid = Make("a");
        Assert.Throws<GuardException>(() => ManifestService.Validate(valid with { SchemaVersion = 2 }));
        Assert.Throws<GuardException>(() => ManifestService.Validate(valid with { Algorithm = "MD5" }));
        Assert.Throws<GuardException>(() => ManifestService.Validate(valid with { Files = [valid.Files[0], valid.Files[0]] }));
        Assert.Throws<GuardException>(() => ManifestService.Validate(valid with { Files = [valid.Files[0] with { Sha256 = "123" }] }));
        Assert.Throws<GuardException>(() => ManifestService.Validate(valid with { Files = [valid.Files[0] with { State = FileState.Indexed }] }));
        Assert.Throws<GuardException>(() => ManifestService.Validate(valid with { Files = [valid.Files[0] with { Size = -1 }] }));
        Assert.Throws<GuardException>(() => ManifestService.Validate(valid with { Files = [valid.Files[0] with { State = FileState.Unstable }] }));
    }

    [Fact]
    public async Task ReadRejectsDuplicateUnknownMissingAndNumericStateFields()
    {
        using var fixture = new ScanFixture(); var path = Path.Combine(fixture.Base, "bad.json");
        var valid = JsonSerializer.Serialize(Make("a"), JsonDefaults.Options);
        var malformed = new[]
        {
            valid.Replace("\"schemaVersion\": 1", "\"schemaVersion\": 1, \"schemaVersion\": 2", StringComparison.Ordinal),
            valid.Replace("\"schemaVersion\": 1", "\"schemaVersion\": 1, \"unknown\": 2", StringComparison.Ordinal),
            valid.Replace("\"schemaVersion\": 1,", "", StringComparison.Ordinal),
            valid.Replace("\"Ready\"", "1", StringComparison.Ordinal),
            "{\"schemaVersion\":1,\"algorithm\":\"SHA-256\",\"createdUtc\":\"2026-01-01T00:00:00Z\",\"files\":null}",
            "{"
        };
        foreach (var json in malformed)
        {
            await File.WriteAllTextAsync(path, json, new UTF8Encoding(false));
            await Assert.ThrowsAsync<GuardException>(() => ManifestService.ReadAsync(path));
        }
        await File.WriteAllBytesAsync(path, [0xff, 0xfe, 0]);
        await Assert.ThrowsAsync<GuardException>(() => ManifestService.ReadAsync(path));
        await File.WriteAllTextAsync(path, valid, new UTF8Encoding(true));
        await Assert.ThrowsAsync<GuardException>(() => ManifestService.ReadAsync(path));
    }

    [Fact]
    public void DiffPreservesUnreadableUnstableAndMissingDistinctions()
    {
        using var fixture = new ScanFixture();
        var before = Make("a") with { Files = [Entry("a"), Entry("b"), Entry("c")] };
        var after = before with { Files = [Entry("a") with { State = FileState.Unreadable, Sha256 = null, Error = "permission" },
            Entry("b") with { State = FileState.Unstable, Sha256 = null }, Entry("c") with { State = FileState.Missing, Sha256 = null }] };
        Assert.Equal(new[] { DifferenceKind.Unreadable, DifferenceKind.Unstable, DifferenceKind.Missing }, fixture.Manifests.Diff(before, after).Differences.Select(x => x.Kind));
    }

    [Fact]
    public async Task VerifyUsesActualWindowsCaseSemantics()
    {
        using var fixture = new ScanFixture(); fixture.Write("CaseName", "same");
        var manifest = await fixture.Manifests.CreateAsync(fixture.Root);
        var differentCase = manifest with { Files = manifest.Files.Select(x => x with { Path = x.Path.ToLowerInvariant() }).ToList() };
        var result = await fixture.Manifests.VerifyAsync(fixture.Root, differentCase);
        if (OperatingSystem.IsWindows() && !PathSafety.IsCaseSensitiveDirectory(fixture.Root)) Assert.False(result.HasDifferences);
        else Assert.True(result.HasDifferences);
    }

    [Fact]
    public async Task CancelledManifestWritePreservesExistingDestinationAndRemovesTemporaryFile()
    {
        using var fixture = new ScanFixture(); var path = Path.Combine(fixture.Base, "manifest.json");
        await File.WriteAllTextAsync(path, "original"); using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ManifestService.WriteAsync(path, Make("a"), cancellation.Token));
        Assert.Equal("original", await File.ReadAllTextAsync(path));
        Assert.Empty(Directory.EnumerateFiles(fixture.Base, "*.tmp"));
    }

    [Fact]
    public async Task ExistingManifestOutputCannotBeOverwritten()
    {
        using var fixture = new ScanFixture();
        var path = Path.Combine(fixture.Base, "existing.json");
        await File.WriteAllTextAsync(path, "preserve");
        await Assert.ThrowsAsync<GuardException>(() => ManifestService.WriteAsync(path, Make("a")));
        Assert.Equal("preserve", await File.ReadAllTextAsync(path));
    }

    [Fact]
    public void UnreadableAncestorNeverBecomesFalseMissingDescendants()
    {
        using var fixture = new ScanFixture();
        var before = Make("private/a") with { Files = [Entry("private/a"), Entry("private/deep/b"), Entry("genuinely-missing")] };
        var after = new ManifestDocument { Files = [new("private", 0, null, default, FileState.Unreadable, "access denied", IsDirectory: true)] };
        var result = fixture.Manifests.Diff(before, after).Differences.ToDictionary(x => x.Path);
        Assert.Equal(DifferenceKind.Unreadable, result["private/a"].Kind);
        Assert.Equal(DifferenceKind.Unreadable, result["private/deep/b"].Kind);
        Assert.Equal(DifferenceKind.Missing, result["genuinely-missing"].Kind);
    }

    [Fact]
    public async Task ActualBlockedDirectoryProducesUnreadableDescendantsInVerification()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new ScanFixture(); fixture.Write("private/a", "same");
        var baseline = await fixture.Manifests.CreateAsync(fixture.Root);
        using var locked = ScanFixture.LockDirectory(Path.Combine(fixture.Root, "private"));
        var result = await fixture.Manifests.VerifyAsync(fixture.Root, baseline);
        Assert.Equal(DifferenceKind.Unreadable, result.Differences.Single(x => x.Path == "private/a").Kind);
        Assert.DoesNotContain(result.Differences, x => x.Kind == DifferenceKind.Missing);
    }

    private static ManifestDocument Make(string path) => new() { Files = [Entry(path)] };
    private static ManifestEntry Entry(string path) => new(path, 4, "0967115f2813a3541eaef77de9d9d577eafafb150c9e463febe5568d8ec7f2a1", DateTimeOffset.UtcNow, FileState.Ready);
}
