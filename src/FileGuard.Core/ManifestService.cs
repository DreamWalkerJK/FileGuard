using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FileGuard.Core;

/// <summary>Versioned SHA-256 content manifests. Manifests do not authenticate their publisher.</summary>
public sealed class ManifestService(Scanner scanner, FileGuardStore store)
{
    private static readonly JsonSerializerOptions Format = new(JsonDefaults.Options)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 16,
        Converters = { new JsonStringEnumConverter(allowIntegerValues: false) }
    };

    public async Task<ManifestDocument> CreateAsync(string root, CancellationToken cancellationToken = default)
    {
        var scan = await scanner.ScanAsync(new ScanOptions { Roots = [root], HashAll = true }, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (scan.State == ScanState.Cancelled) throw new OperationCanceledException(cancellationToken);
        if (scan.State == ScanState.Failed) throw new GuardException(scan.Error ?? "清单扫描失败。");
        var manifest = new ManifestDocument
        {
            Files = store.EnumerateFiles(scan.Id).Where(x => x.State != FileState.SkippedLink)
                .Select(x => new ManifestEntry(x.RelativePath.Replace(Path.DirectorySeparatorChar, '/'), x.Size, x.Sha256,
                    x.ModifiedUtc, x.State, x.Error, x.IsDirectory)).OrderBy(x => x.Path, StringComparer.Ordinal).ToList()
        };
        if (manifest.Files.Any(x => x.IsDirectory && x.Path == "."))
            throw new GuardException("无法遍历清单根目录；本次结果不完整，不能用于判定文件缺失。请检查权限和占用后重新扫描。");
        Validate(manifest);
        return manifest;
    }

    public async Task<ManifestResult> VerifyAsync(string root, ManifestDocument manifest, CancellationToken cancellationToken = default)
    {
        Validate(manifest);
        root = Path.GetFullPath(root);
        PathSafety.ValidateRoot(root);
        // Resolve every untrusted entry before starting I/O; even a dangling link must not become an escape.
        foreach (var entry in manifest.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            PathSafety.ResolveManifestPath(root, entry.Path);
        }
        var actual = await CreateAsync(root, cancellationToken).ConfigureAwait(false);
        // A Windows subtree may enable case sensitivity independently of its root. Match each expected path
        // against actual spelling by walking the real parent directory semantics, then use an ordinal diff.
        var actualPaths = actual.Files.ToDictionary(x => x.Path, StringComparer.Ordinal);
        var caseCandidates = actual.Files.ToLookup(x => x.Path, StringComparer.OrdinalIgnoreCase);
        var renamed = new List<ManifestEntry>(manifest.Files.Count);
        foreach (var entry in manifest.Files)
        {
            if (actualPaths.ContainsKey(entry.Path)) { renamed.Add(entry); continue; }
            var equivalent = caseCandidates[entry.Path].FirstOrDefault(x => PathsEquivalent(root, entry.Path, x.Path));
            renamed.Add(equivalent is null ? entry : entry with { Path = equivalent.Path });
        }
        if (renamed.Select(x => x.Path).Distinct(StringComparer.Ordinal).Count() != renamed.Count)
            throw new GuardException("清单中的多个路径解析到同一目标文件。");
        return Diff(manifest with { Files = renamed }, actual);
    }

    public ManifestResult Diff(ManifestDocument before, ManifestDocument after)
    {
        Validate(before);
        Validate(after);
        var left = before.Files.ToDictionary(x => x.Path, StringComparer.Ordinal);
        var right = after.Files.ToDictionary(x => x.Path, StringComparer.Ordinal);
        var unreadableDirectories = after.Files.Where(x => x.IsDirectory && x.State == FileState.Unreadable).ToArray();
        var differences = new List<ManifestDifference>();
        foreach (var path in left.Keys.Union(right.Keys, StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal))
        {
            left.TryGetValue(path, out var oldEntry);
            right.TryGetValue(path, out var newEntry);
            var blockedParent = unreadableDirectories.FirstOrDefault(x => path.StartsWith(x.Path + "/", StringComparison.Ordinal));
            if (newEntry is null && blockedParent is not null)
                differences.Add(new(path, DifferenceKind.Unreadable, "父目录无法遍历，不能判定该文件是否缺失。"));
            else if (newEntry is null && oldEntry is { IsDirectory: true } && right.Keys.Any(x => x.StartsWith(path + "/", StringComparison.Ordinal)))
                differences.Add(new(path, DifferenceKind.ContentChanged, "原基准中的不可读取目录现在可读取；请审查其中新增索引。"));
            else if (newEntry is null || newEntry.State == FileState.Missing)
                differences.Add(new(path, DifferenceKind.Missing, "基准中的文件已不存在。"));
            else if (newEntry.State == FileState.Unstable)
                differences.Add(new(path, DifferenceKind.Unstable, newEntry.Error ?? "文件在读取期间变化。"));
            else if (newEntry.State is FileState.Unreadable or FileState.SkippedLink)
                differences.Add(new(path, DifferenceKind.Unreadable, newEntry.Error ?? "文件无法安全读取。"));
            else if (oldEntry is null)
                differences.Add(new(path, DifferenceKind.Added));
            else if (oldEntry.State != FileState.Ready || oldEntry.Size != newEntry.Size
                     || !string.Equals(oldEntry.Sha256, newEntry.Sha256, StringComparison.OrdinalIgnoreCase))
                differences.Add(new(path, DifferenceKind.ContentChanged, oldEntry.State == FileState.Ready ? null : "基准文件没有可用的完整摘要。"));
            else differences.Add(new(path, DifferenceKind.Unchanged));
        }
        return new(differences);
    }

    public static ManifestDocument Read(string path) => ReadAsync(path).GetAwaiter().GetResult();

    public static async Task<ManifestDocument> ReadAsync(string path, CancellationToken cancellationToken = default)
    {
        var bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        return Parse(bytes);
    }

    public static ManifestDocument Parse(byte[] bytes)
    {
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) throw new GuardException("清单必须使用无 BOM 的 UTF-8 编码。");
        try
        {
            var text = new UTF8Encoding(false, true).GetString(bytes);
            using var parsed = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 16 });
            CheckJson(parsed.RootElement);
            RequireProperties(parsed.RootElement, "schemaVersion", "algorithm", "createdUtc", "files");
            if (parsed.RootElement.GetProperty("files").ValueKind != JsonValueKind.Array) throw new GuardException("清单 files 必须为数组。");
            foreach (var entry in parsed.RootElement.GetProperty("files").EnumerateArray())
            {
                RequireProperties(entry, "path", "size", "sha256", "modifiedUtc", "state");
                if (entry.GetProperty("state").ValueKind != JsonValueKind.String) throw new GuardException("清单 state 必须为字符串枚举。");
            }
            var result = JsonSerializer.Deserialize<ManifestDocument>(text, Format) ?? throw new GuardException("清单内容为空。");
            Validate(result);
            return result;
        }
        catch (JsonException) { throw new GuardException("清单 JSON 或字段类型无效，或含不支持的字段。"); }
        catch (DecoderFallbackException) { throw new GuardException("清单包含无效的 UTF-8 字节。"); }
    }

    public static async Task WriteAsync(string path, ManifestDocument manifest, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Validate(manifest);
        var normalized = manifest with
        {
            Files = manifest.Files.OrderBy(x => x.Path, StringComparer.Ordinal)
                .Select(x => x with { Sha256 = x.Sha256?.ToLowerInvariant() }).ToList()
        };
        var text = JsonSerializer.Serialize(normalized, Format).Replace("\r\n", "\n", StringComparison.Ordinal) + "\n";
        path = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(path)!;
        PathSafety.Validate(path, parent);
        using var directoryGuards = OperatingSystem.IsWindows() ? new DirectoryGuards(parent, mutation: true) : null;
        if (File.Exists(path) || Directory.Exists(path)) throw new GuardException("清单目标已存在；请选择新的输出路径，不会覆盖现有文件。");
        // Write beside the destination and then rename, so cancellation cannot truncate an existing manifest.
        var temporary = Path.Combine(parent, ".fileguard-manifest-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.Asynchronous))
            {
                await stream.WriteAsync(Encoding.UTF8.GetBytes(text), cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            PathSafety.Validate(path, parent);
            File.Move(temporary, path, overwrite: false);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public static void Validate(ManifestDocument manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (manifest.SchemaVersion != 1 || manifest.Algorithm != "SHA-256") throw new GuardException("仅支持 schemaVersion 1 和 SHA-256 清单。");
        if (manifest.Files is null || manifest.CreatedUtc == default) throw new GuardException("清单缺少 files 或 createdUtc。");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in manifest.Files)
        {
            if (entry is null) throw new GuardException("清单不能包含空文件项。");
            ValidateRelativePath(entry.Path);
            if (!seen.Add(entry.Path)) throw new GuardException("清单包含重复路径。");
            if (entry.Size < 0 || entry.Error?.Length > 4096) throw new GuardException("清单大小或错误信息无效。");
            if (entry.State is not (FileState.Ready or FileState.Unreadable or FileState.Missing or FileState.Unstable or FileState.SkippedLink))
                throw new GuardException("清单包含无效或尚未完成的文件状态。");
            if (entry.Sha256 is not null && (entry.Sha256.Length != 64 || !entry.Sha256.All(Uri.IsHexDigit)))
                throw new GuardException("SHA-256 摘要必须为 64 个十六进制字符。");
            if (entry.State == FileState.Ready && (entry.Sha256 is null || entry.ModifiedUtc == default))
                throw new GuardException("可读文件必须包含完整摘要和修改时间。");
            if (entry.State != FileState.Ready && entry.Sha256 is not null)
                throw new GuardException("不可读取或不稳定的文件不能声明可信摘要。");
            if (entry.IsDirectory && (entry.State != FileState.Unreadable || entry.Size != 0 || entry.Sha256 is not null))
                throw new GuardException("目录项只用于记录无法遍历的目录，不能声明内容摘要或文件大小。");
        }
    }

    private static void ValidateRelativePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 32767 || path[0] == '/' || path.Contains('\\') || path.Contains(':')
            || path.Any(char.IsControl) || Path.IsPathRooted(path)) throw new GuardException("清单只允许使用 / 分隔的安全相对路径。");
        foreach (var segment in path.Split('/'))
        {
            if (segment is "" or "." or ".." || segment.EndsWith('.') || segment.EndsWith(' '))
                throw new GuardException("清单路径包含空段、遍历段或含歧义的名称。");
            var stem = segment.Split('.')[0].ToUpperInvariant();
            if (stem is "CON" or "PRN" or "AUX" or "NUL" || stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal)
                || stem.StartsWith("LPT", StringComparison.Ordinal)) && stem[3] is >= '1' and <= '9')
                throw new GuardException("清单路径包含 Windows 保留设备名称。");
        }
    }

    private static void CheckJson(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in node.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new GuardException("清单 JSON 包含重复属性。");
                CheckJson(property.Value);
            }
        }
        else if (node.ValueKind == JsonValueKind.Array) foreach (var item in node.EnumerateArray()) CheckJson(item);
    }

    private static void RequireProperties(JsonElement node, params string[] names)
    {
        if (node.ValueKind != JsonValueKind.Object || names.Any(name => !node.TryGetProperty(name, out _)))
            throw new GuardException("清单缺少必需字段。");
    }

    private static bool PathsEquivalent(string root, string left, string right)
    {
        if (!OperatingSystem.IsWindows()) return string.Equals(left, right, StringComparison.Ordinal);
        var a = left.Split('/');
        var b = right.Split('/');
        if (a.Length != b.Length) return false;
        var parent = root;
        for (var i = 0; i < a.Length; i++)
        {
            var comparison = Directory.Exists(parent) && PathSafety.IsCaseSensitiveDirectory(parent)
                ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
            if (!string.Equals(a[i], b[i], comparison)) return false;
            parent = Path.Combine(parent, b[i]);
        }
        return true;
    }
}
