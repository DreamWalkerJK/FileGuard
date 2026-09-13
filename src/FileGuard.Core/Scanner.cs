using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Threading.Channels;

namespace FileGuard.Core;

/// <summary>Two bounded pipelines: directory enumeration → index; size candidates → hash workers → index.</summary>
public sealed class Scanner(FileGuardStore store, GuardSettings settings)
{
    public async Task<ScanRecord> ScanAsync(ScanOptions options, IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default, string? scanId = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ValidateOptions(options);
        var roots = options.Roots.Select(Path.GetFullPath).Select(Path.TrimEndingDirectorySeparator)
            .Distinct(StringComparer.Ordinal).ToArray();
        if (roots.Length == 0) throw new GuardException("请指定至少一个扫描根目录。");
        var allowed = settings.AllowedRoots.Select(Path.GetFullPath).ToArray();
        foreach (var root in roots)
        {
            if (!allowed.Any(x => PathSafety.IsWithin(root, x))) throw new GuardException("扫描根目录不在允许列表中。");
            PathSafety.ValidateRoot(root);
        }
        // Nested roots would otherwise enumerate the same files twice.
        roots = roots.Where(root => !roots.Any(other => other != root && PathSafety.IsWithin(root, other))).ToArray();
        var scan = new ScanRecord
        {
            Id = scanId ?? Guid.NewGuid().ToString("N"), Options = options with { Roots = roots },
            Owner = FileGuardStore.CurrentOwner, State = ScanState.Enumerating
        };
        using (var connection = store.OpenConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT json FROM records WHERE kind='scan' AND id=$id";
            command.Parameters.AddWithValue("$id", scan.Id);
            if (command.ExecuteScalar() is string previous)
            {
                var queued = JsonSerializer.Deserialize<ScanRecord>(previous, JsonDefaults.Options)!;
                if (queued.State != ScanState.Queued || queued.Owner != FileGuardStore.CurrentOwner)
                    throw new GuardException("扫描 ID 已存在或由其他进程拥有；请使用新的 ID 重新扫描。");
                scan = scan with { CreatedUtc = queued.CreatedUtc };
            }
            command.CommandText = """
                INSERT INTO records(kind,id,json,updated) VALUES('scan',$id,$json,$utc)
                ON CONFLICT(kind,id) DO UPDATE SET json=excluded.json,updated=excluded.updated
                WHERE json_extract(records.json,'$.state')='Queued' AND json_extract(records.json,'$.owner')=$owner
                """;
            command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(scan, JsonDefaults.Options));
            command.Parameters.AddWithValue("$utc", DateTimeOffset.UtcNow.ToString("O"));
            command.Parameters.AddWithValue("$owner", FileGuardStore.CurrentOwner);
            if (command.ExecuteNonQuery() != 1) throw new GuardException("扫描任务已被另一个工作单元领取；请勿重复启动。");
        }
        var matcher = new ScanMatcher(options);
        var timer = Stopwatch.StartNew();
        var progressGate = new object();
        long bytesRead = 0;
        var lastSave = TimeSpan.Zero;
        void Report(bool force = false)
        {
            lock (progressGate)
            {
                scan.BytesRead = Interlocked.Read(ref bytesRead);
                if (!force && timer.Elapsed - lastSave < TimeSpan.FromMilliseconds(250)) return;
                lastSave = timer.Elapsed;
                store.SaveScan(scan);
                progress?.Report(new(scan.Id, scan.State, scan.FileCount, scan.BytesRead, scan.ErrorCount));
            }
        }
        try
        {
            Report(true);
            using (var stage = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                var indexed = Channel.CreateBounded<FileRecord>(new BoundedChannelOptions(options.ChannelCapacity)
                    { SingleWriter = true, SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
                var producer = Task.Run(async () =>
                {
                    try
                    {
                        foreach (var root in roots)
                            await EnumerateRootAsync(scan.Id, root, matcher, indexed.Writer, stage.Token).ConfigureAwait(false);
                        indexed.Writer.TryComplete();
                    }
                    catch (Exception ex) { indexed.Writer.TryComplete(ex); stage.Cancel(); throw; }
                }, CancellationToken.None);
                var writer = Task.Run(async () =>
                {
                    try
                    {
                        await foreach (var record in indexed.Reader.ReadAllAsync(stage.Token).ConfigureAwait(false))
                        {
                            store.SaveFile(record);
                            lock (progressGate)
                            {
                                scan.FileCount++;
                                scan.TotalBytes += record.Size;
                                if (IsError(record.State)) scan.ErrorCount++;
                            }
                            Report();
                        }
                    }
                    catch { stage.Cancel(); throw; }
                }, CancellationToken.None);
                await Task.WhenAll(producer, writer).ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();
            scan.State = ScanState.Hashing;
            Report(true);
            using (var stage = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                var candidates = Channel.CreateBounded<FileRecord>(new BoundedChannelOptions(options.ChannelCapacity)
                    { SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
                var hashed = Channel.CreateBounded<FileRecord>(new BoundedChannelOptions(options.ChannelCapacity)
                    { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
                var limiter = new ReadLimiter(options.BytesPerSecond);
                var producer = Task.Run(async () =>
                {
                    try
                    {
                        foreach (var record in store.EnumerateHashCandidates(scan.Id, options.HashAll))
                        {
                            stage.Token.ThrowIfCancellationRequested();
                            await candidates.Writer.WriteAsync(record, stage.Token).ConfigureAwait(false);
                        }
                        candidates.Writer.TryComplete();
                    }
                    catch (Exception ex) { candidates.Writer.TryComplete(ex); stage.Cancel(); throw; }
                }, CancellationToken.None);
                var workers = Enumerable.Range(0, options.Concurrency).Select(_ => Task.Run(async () =>
                {
                    try
                    {
                        await foreach (var record in candidates.Reader.ReadAllAsync(stage.Token).ConfigureAwait(false))
                        {
                            var result = await HashRecordAsync(record, limiter,
                                count => { Interlocked.Add(ref bytesRead, count); Report(); }, stage.Token).ConfigureAwait(false);
                            await hashed.Writer.WriteAsync(result, stage.Token).ConfigureAwait(false);
                        }
                    }
                    catch { stage.Cancel(); throw; }
                }, CancellationToken.None)).ToArray();
                var completion = Task.Run(async () =>
                {
                    try { await Task.WhenAll(workers).ConfigureAwait(false); hashed.Writer.TryComplete(); }
                    catch (Exception ex) { hashed.Writer.TryComplete(ex); throw; }
                }, CancellationToken.None);
                var writer = Task.Run(async () =>
                {
                    try
                    {
                        await foreach (var record in hashed.Reader.ReadAllAsync(stage.Token).ConfigureAwait(false))
                        {
                            store.SaveFile(record);
                            lock (progressGate)
                            {
                                scan.CandidateCount++;
                                if (record.Sha256 is not null) scan.HashCount++;
                                if (IsError(record.State)) scan.ErrorCount++;
                            }
                            Report();
                        }
                    }
                    catch { stage.Cancel(); throw; }
                }, CancellationToken.None);
                await Task.WhenAll(producer, completion, writer).ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();
            scan.State = scan.ErrorCount == 0 ? ScanState.Completed : ScanState.PartialFailure;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            scan.State = ScanState.Cancelled;
            scan.Error = "扫描已取消；已完成的索引已保存。请使用原选项启动新扫描，不能将部分索引当作完整结果。";
        }
        catch (Exception ex)
        {
            scan.State = ScanState.Failed;
            scan.Error = DescribeError(ex);
        }
        finally
        {
            scan.FinishedUtc = DateTimeOffset.UtcNow;
            Report(true);
        }
        return scan;
    }

    public IReadOnlyList<DuplicateGroup> GetDuplicates(string scanId)
    {
        var scan = store.GetScan(scanId);
        if (scan.State is ScanState.Queued or ScanState.Enumerating or ScanState.Hashing)
            throw new GuardException("扫描仍在运行，请在任务结束后查看重复组。");
        var result = new List<DuplicateGroup>();
        foreach (var group in EnumerateDuplicateCandidates(scanId))
        {
            var files = group.ToArray();
            var size = files[0].Size;
            var hash = files[0].Sha256!;
            var distinctPhysical = files.Select(x => x.Identity is { Length: > 0 } ? "id:" + x.Identity : "path:" + x.FullPath)
                .Distinct(StringComparer.Ordinal).Count();
            if (distinctPhysical < 2) continue;
            var uncertain = files.Any(x => x.Identity is null || x.LinkCount is null or > 1 || x.SparseOrCompressed);
            result.Add(new(size.ToString("x") + "-" + hash, size, hash, files,
                checked((files.Length - 1L) * size), uncertain ? null : checked((distinctPhysical - 1L) * size),
                uncertain ? "硬链接、稀疏/压缩文件或未知身份导致物理回收量无法确定；逻辑大小不等于物理占用。隔离不释放空间。"
                    : "物理回收量是估计值，可能受块分配、快照或写时复制影响。隔离不释放空间，永久清除后才可能释放。"));
        }
        return result.OrderByDescending(x => x.LogicalDuplicateBytes).ThenBy(x => x.Id, StringComparer.Ordinal).ToArray();
    }

    private IEnumerable<List<FileRecord>> EnumerateDuplicateCandidates(string scanId)
    {
        using var connection = store.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.json FROM files f JOIN (
                SELECT size,sha256 FROM files WHERE scanId=$id AND state='Ready' AND sha256 IS NOT NULL
                GROUP BY size,sha256 HAVING COUNT(*)>1
            ) d ON f.size=d.size AND f.sha256=d.sha256
            WHERE f.scanId=$id AND f.state='Ready' ORDER BY f.size,f.sha256,f.path
            """;
        command.Parameters.AddWithValue("$id", scanId);
        using var reader = command.ExecuteReader();
        var group = new List<FileRecord>();
        while (reader.Read())
        {
            var item = JsonSerializer.Deserialize<FileRecord>(reader.GetString(0), JsonDefaults.Options)!;
            if (group.Count > 0 && (group[0].Size != item.Size || group[0].Sha256 != item.Sha256))
            {
                yield return group;
                group = [];
            }
            group.Add(item);
        }
        if (group.Count > 0) yield return group;
    }

    public async IAsyncEnumerable<FileRecord> ReadFilesAsync(string scanId,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (var record in store.EnumerateFiles(scanId))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return record;
            await Task.CompletedTask.ConfigureAwait(false);
        }
    }

    private async Task EnumerateRootAsync(string scanId, string root, ScanMatcher matcher, ChannelWriter<FileRecord> writer, CancellationToken ct)
    {
        var frames = new Stack<(string Path, IEnumerator<string> Entries, bool Sensitive)>();
        async Task AddDirectory(string directory)
        {
            try
            {
                PathSafety.Validate(directory, root);
                var sensitive = !OperatingSystem.IsWindows() || PathSafety.IsCaseSensitiveDirectory(directory);
                frames.Push((directory, Directory.EnumerateFileSystemEntries(directory).GetEnumerator(), sensitive));
            }
            catch (Exception ex) when (IsFileException(ex))
            {
                await writer.WriteAsync(ErrorFile(scanId, root, directory, FileState.Unreadable, DescribeError(ex)) with { IsDirectory = true }, ct).ConfigureAwait(false);
            }
        }
        await AddDirectory(root).ConfigureAwait(false);
        try
        {
            while (frames.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                var frame = frames.Peek();
                string? entry = null;
                Exception? traversalError = null;
                try
                {
                    PathSafety.Validate(frame.Path, root);
                    if (frame.Entries.MoveNext()) entry = frame.Entries.Current;
                }
                catch (Exception ex) when (IsFileException(ex)) { traversalError = ex; }
                if (entry is null)
                {
                    frames.Pop().Entries.Dispose();
                    if (traversalError is not null)
                        await writer.WriteAsync(ErrorFile(scanId, root, frame.Path, FileState.Unreadable, DescribeError(traversalError)) with { IsDirectory = true }, ct).ConfigureAwait(false);
                    continue;
                }
                if (IsInternalPath(entry)) continue;
                var relative = Relative(root, entry);
                FileAttributes attributes;
                try { attributes = File.GetAttributes(entry); }
                catch (Exception ex) when (IsFileException(ex))
                {
                    await writer.WriteAsync(ErrorFile(scanId, root, entry, StateFor(ex), DescribeError(ex)), ct).ConfigureAwait(false);
                    continue;
                }
                var isDirectory = (attributes & FileAttributes.Directory) != 0;
                var caseSensitive = frame.Sensitive;
                if (matcher.Excluded(relative, isDirectory, caseSensitive)) continue;
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    await writer.WriteAsync(ErrorFile(scanId, root, entry, FileState.SkippedLink,
                        "已跳过符号链接、junction 或其他 reparse point；不跟随链接。"), ct).ConfigureAwait(false);
                    continue;
                }
                if (isDirectory) { await AddDirectory(entry).ConfigureAwait(false); continue; }
                if (!matcher.Included(relative, caseSensitive)) continue;
                FileRecord? record;
                try
                {
                    using var safe = SafeFile.OpenRead(entry, root);
                    var snapshot = safe.Snapshot();
                    record = matcher.Metadata(snapshot.Size, snapshot.ModifiedUtc) ? new FileRecord
                    {
                        ScanId = scanId, Root = root, RelativePath = relative, FullPath = entry,
                        Size = snapshot.Size, ModifiedUtc = snapshot.ModifiedUtc, Identity = snapshot.Identity,
                        LinkCount = snapshot.LinkCount, SparseOrCompressed = snapshot.SparseOrCompressed, State = FileState.Indexed
                    } : null;
                }
                catch (Exception ex) when (IsFileException(ex)) { record = ErrorFile(scanId, root, entry, StateFor(ex), DescribeError(ex)); }
                if (record is not null) await writer.WriteAsync(record, ct).ConfigureAwait(false);
            }
        }
        finally { while (frames.Count > 0) frames.Pop().Entries.Dispose(); }
    }

    private bool IsInternalPath(string path) => PathSafety.IsWithin(path, store.DataDirectory)
        || (settings.QuarantineDirectory is { Length: > 0 } quarantine && PathSafety.IsWithin(path, quarantine));

    private static async Task<FileRecord> HashRecordAsync(FileRecord record, ReadLimiter limiter, Action<int> onRead, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var safe = SafeFile.OpenRead(record.FullPath, record.Root);
                var before = safe.Snapshot();
                if (before.Size != record.Size || before.ModifiedUtc != record.ModifiedUtc || before.Identity != record.Identity)
                    return record with { State = FileState.Unstable, Error = "文件身份、大小或修改时间在索引后发生变化，请重新扫描。", Sha256 = null };
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[128 * 1024];
                long total = 0;
                int read;
                while ((read = await safe.Stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                {
                    await limiter.ConsumeAsync(read, ct).ConfigureAwait(false);
                    onRead(read);
                    total += read;
                    hash.AppendData(buffer, 0, read);
                }
                var after = safe.Snapshot();
                PathSafety.Validate(record.FullPath, record.Root);
                if (before != after || total != before.Size)
                {
                    if (attempt == 0) continue;
                    return record with { State = FileState.Unstable, Error = "文件在读取期间变化，两次尝试均未得到稳定内容。", Sha256 = null };
                }
                return record with { State = FileState.Ready, Sha256 = Convert.ToHexStringLower(hash.GetHashAndReset()), Error = null };
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (IsFileException(ex))
            {
                if (ex is IOException && ex is not (FileNotFoundException or DirectoryNotFoundException) && attempt == 0) continue;
                return record with { State = StateFor(ex), Error = DescribeError(ex), Sha256 = null };
            }
        }
        return record with { State = FileState.Unstable, Error = "无法取得稳定内容。", Sha256 = null };
    }

    private static FileRecord ErrorFile(string scanId, string root, string path, FileState state, string error) => new()
    {
        ScanId = scanId, Root = root, RelativePath = Relative(root, path), FullPath = path, State = state, Error = error
    };
    private static string Relative(string root, string path) => Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');
    private static bool IsError(FileState state) => state is FileState.Unreadable or FileState.Missing or FileState.Unstable;
    private static bool IsFileException(Exception ex) => ex is IOException or UnauthorizedAccessException or GuardException or System.Security.SecurityException;
    private static FileState StateFor(Exception ex) => ex is FileNotFoundException or DirectoryNotFoundException ? FileState.Missing : FileState.Unreadable;
    private static string DescribeError(Exception ex) => ex switch
    {
        FileNotFoundException or DirectoryNotFoundException => "文件或目录在扫描期间消失。",
        UnauthorizedAccessException or System.Security.SecurityException => "权限不足，无法读取文件或目录。请检查访问权限后重试。",
        GuardException => "路径安全检查拒绝访问（链接、身份变化或不受支持的路径）；请检查文件状态后重试。",
        IOException => "文件被占用或发生 I/O 错误，请关闭占用程序并检查存储后重试。",
        _ => $"扫描失败（{ex.GetType().Name}）；请检查存储和参数后重新扫描。"
    };

    private static void ValidateOptions(ScanOptions options)
    {
        if (options.Roots is null || options.Include is null || options.Exclude is null || options.Extensions is null)
            throw new GuardException("扫描列表参数不能为 null。");
        if (options.Concurrency is < 1 or > 64 || options.ChannelCapacity is < 1 or > 4096 || options.BytesPerSecond < 0)
            throw new GuardException("并发度必须为 1–64，Channel 容量为 1–4096，I/O 字节上限不能为负数。");
        if (options.MinSize < 0 || options.MaxSize < 0 || options.MinSize > options.MaxSize || options.ModifiedAfter > options.ModifiedBefore)
            throw new GuardException("文件大小或修改时间范围无效。");
        if (options.Include.Concat(options.Exclude).Concat(options.Extensions).Any(x => string.IsNullOrWhiteSpace(x) || x.Length > 4096))
            throw new GuardException("过滤规则不能为空或超过 4096 字符。");
    }

    private sealed class ReadLimiter(long bytesPerSecond)
    {
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private readonly object _gate = new();
        private double _scheduledSeconds;
        public async Task ConsumeAsync(int count, CancellationToken ct)
        {
            if (bytesPerSecond == 0) return;
            double delay;
            lock (_gate)
            {
                _scheduledSeconds = Math.Max(_scheduledSeconds, _clock.Elapsed.TotalSeconds) + (double)count / bytesPerSecond;
                delay = _scheduledSeconds - _clock.Elapsed.TotalSeconds;
            }
            while (delay > 0)
            {
                var duration = Math.Min(delay, 30);
                await Task.Delay(TimeSpan.FromSeconds(duration), ct).ConfigureAwait(false);
                delay -= duration;
            }
        }
    }

    private sealed class ScanMatcher(ScanOptions options)
    {
        private readonly Dictionary<(string Pattern, bool Sensitive), Regex> _expressions = new();
        public bool Excluded(string path, bool directory, bool sensitive) => options.Exclude.Any(p => Match(p, path, sensitive)
            || (directory && Match(p, path + "/", sensitive)));
        public bool Included(string path, bool sensitive) => (options.Include.Length == 0 || options.Include.Any(p => Match(p, path, sensitive)))
            && (options.Extensions.Length == 0 || options.Extensions.Any(e => string.Equals(Path.GetExtension(path), e.StartsWith('.') ? e : "." + e,
                sensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase)));
        public bool Metadata(long size, DateTimeOffset modified) => (options.MinSize is null || size >= options.MinSize)
            && (options.MaxSize is null || size <= options.MaxSize) && (options.ModifiedAfter is null || modified >= options.ModifiedAfter)
            && (options.ModifiedBefore is null || modified <= options.ModifiedBefore);
        private bool Match(string pattern, string path, bool sensitive)
        {
            if (!_expressions.TryGetValue((pattern, sensitive), out var expression))
            {
                var glob = pattern.Replace('\\', '/');
                var regex = new StringBuilder("^");
                if (!glob.Contains('/')) regex.Append("(?:.*/)?");
                for (var i = 0; i < glob.Length; i++)
                {
                    if (glob[i] == '*' && i + 1 < glob.Length && glob[i + 1] == '*')
                    {
                        i++;
                        if (i + 1 < glob.Length && glob[i + 1] == '/') { i++; regex.Append("(?:.*/)?"); }
                        else regex.Append(".*");
                    }
                    else if (glob[i] == '*') regex.Append("[^/]*");
                    else if (glob[i] == '?') regex.Append("[^/]");
                    else regex.Append(Regex.Escape(glob[i].ToString()));
                }
                regex.Append('$');
                expression = new Regex(regex.ToString(), RegexOptions.CultureInvariant | RegexOptions.NonBacktracking
                    | (sensitive ? RegexOptions.None : RegexOptions.IgnoreCase), TimeSpan.FromMilliseconds(250));
                _expressions.Add((pattern, sensitive), expression);
            }
            return expression.IsMatch(path);
        }
    }
}
