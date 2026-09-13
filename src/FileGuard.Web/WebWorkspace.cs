using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Threading.Channels;
using FileGuard.Core;

namespace FileGuard.Web;

public sealed class WebWorkspace : BackgroundService
{
    private readonly Channel<(string Id, ScanOptions Options)> _queue = Channel.CreateBounded<(string, ScanOptions)>(8);
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _cancellations = new();
    private readonly ConcurrentDictionary<string, ScanProgress> _progress = new();
    private readonly ConcurrentDictionary<string, ManifestResult> _results = new();
    private readonly Scanner _scanner;
    private HashSet<int> _enabled;
    public FileGuardStore Store { get; }
    public GuardSettings Settings { get; }
    public CleanupService Cleanup { get; }
    public ManifestService Manifests { get; }
    public WebWorkspace(FileGuardStore store, GuardSettings settings, Scanner scanner, CleanupService cleanup, ManifestService manifests)
    {
        Store = store; Settings = settings; _scanner = scanner; Cleanup = cleanup; Manifests = manifests;
        _enabled = Enumerable.Range(0, settings.AllowedRoots.Length).ToHashSet();
        if (Store.GetSetting<string[]>("web-enabled-roots") is { } saved)
        {
            _enabled = Enumerable.Range(0, settings.AllowedRoots.Length).Where(i => saved.Contains(settings.AllowedRoots[i], PathComparer)).ToHashSet();
        }
    }
    private static StringComparer PathComparer => StringComparer.Ordinal;
    public bool Enabled(int index) => Volatile.Read(ref _enabled).Contains(index);
    public void DemandEnabledRoots(IEnumerable<string> roots)
    {
        if (roots.Any(root => !Enumerable.Range(0, Settings.AllowedRoots.Length).Any(index => Enabled(index) && PathComparer.Equals(Path.GetFullPath(root), Path.GetFullPath(Settings.AllowedRoots[index])))))
            throw new GuardException("操作涉及已停用或未被服务器允许的根目录。请先在根目录设置中启用。");
    }
    public void DemandOperationsEnabled(IEnumerable<CleanupOperation> operations) => DemandEnabledRoots(operations.SelectMany(operation => new[] { operation.Candidate.Root, operation.Keeper.Root }));
    public IEnumerable<CleanupOperation> RecoveryCandidates() => Store.EnumerateOperations().Where(operation => operation.State is OperationState.Started or OperationState.Copied or OperationState.Restoring or OperationState.Purging or OperationState.NeedsReview);
    public string Root(int index) => index >= 0 && index < Settings.AllowedRoots.Length && Enabled(index) ? Settings.AllowedRoots[index] : throw new GuardException("目录不在启用的服务器允许列表中。");
    public void SetRoots(int[] indexes)
    {
        if (indexes.Any(x => x < 0 || x >= Settings.AllowedRoots.Length)) throw new GuardException("根目录超出服务器启动允许列表。");
        var enabled = indexes.ToHashSet();
        Store.SaveSetting("web-enabled-roots", enabled.Select(x => Settings.AllowedRoots[x]).ToArray());
        Store.Audit("web.roots", "allowed-roots", "允许目录设置已更新", "只接受启动允许列表中的目录索引");
        Volatile.Write(ref _enabled, enabled);
    }
    public string Queue(ScanOptions options)
    {
        if (options.Roots.Length == 0 || options.Roots.Any(root => !Enumerable.Range(0, Settings.AllowedRoots.Length).Any(i => Enabled(i) && PathComparer.Equals(root, Settings.AllowedRoots[i]))))
            throw new GuardException("必须选择一个已启用的允许根目录。");
        var scan = new ScanRecord { Options = options, State = ScanState.Queued, Owner = FileGuardStore.CurrentOwner }; Store.SaveScan(scan);
        var cancellation = new CancellationTokenSource(); _cancellations[scan.Id] = cancellation;
        if (!_queue.Writer.TryWrite((scan.Id, options)))
        {
            _cancellations.TryRemove(scan.Id, out _); cancellation.Dispose();
            scan.State = ScanState.Failed; scan.Error = "Web 扫描队列已满（最多 8 个等待任务）。"; scan.FinishedUtc = DateTimeOffset.UtcNow; Store.SaveScan(scan);
            throw new GuardException("扫描队列已满。");
        }
        return scan.Id;
    }
    public string Retry(string id) => Queue((Store.GetScan(id) ?? throw new GuardException("找不到扫描任务。")).Options);
    public void Cancel(string id) { if (_cancellations.TryGetValue(id, out var cancellation)) cancellation.Cancel(); }
    public ScanProgress? ProgressFor(string id) => _progress.TryGetValue(id, out var progress) ? progress : null;
    public IReadOnlyList<DuplicateGroup> Duplicates(string scanId) => _scanner.GetDuplicates(scanId);
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var work in _queue.Reader.ReadAllAsync(stoppingToken))
            {
                if (!_cancellations.TryGetValue(work.Id, out var cancellation)) continue;
                using (cancellation)
                using (var linked = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, cancellation.Token))
                {
                    try
                    {
                        if (work.Options.Roots.Any(root => !Enumerable.Range(0, Settings.AllowedRoots.Length).Any(i => Enabled(i) && PathComparer.Equals(root, Settings.AllowedRoots[i])))) throw new GuardException("排队期间根目录已被禁用。");
                        await _scanner.ScanAsync(work.Options, new InlineProgress(value => _progress[value.ScanId] = value), linked.Token, work.Id);
                    }
                    catch (Exception exception)
                    {
                        var scan = Store.GetScan(work.Id);
                        if (scan is not null)
                        {
                            scan.State = exception is OperationCanceledException ? ScanState.Cancelled : ScanState.Failed;
                            scan.Error = exception is GuardException ? exception.Message : "扫描未完成。请检查权限、可用磁盘空间并重试。";
                            scan.FinishedUtc = DateTimeOffset.UtcNow; Store.SaveScan(scan);
                        }
                    }
                    finally { _cancellations.TryRemove(work.Id, out _); _progress.TryRemove(work.Id, out _); }
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            while (_queue.Reader.TryRead(out var pending))
            {
                var scan = Store.GetScan(pending.Id);
                if (scan is not null) { scan.State = ScanState.Interrupted; scan.FinishedUtc = DateTimeOffset.UtcNow; Store.SaveScan(scan); }
                if (_cancellations.TryRemove(pending.Id, out var cancellation)) cancellation.Dispose();
            }
        }
    }
    private sealed class InlineProgress(Action<ScanProgress> report) : IProgress<ScanProgress> { public void Report(ScanProgress value) => report(value); }
    public static string[] Split(string? value) => (value ?? "").Split([';', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    public static long? OptionalLong(string? value) => string.IsNullOrWhiteSpace(value) ? null : long.Parse(value, CultureInfo.InvariantCulture);
    public static DateTimeOffset? OptionalDate(string? value) => string.IsNullOrWhiteSpace(value) ? null : DateTimeOffset.Parse(value, CultureInfo.InvariantCulture);
    public static async Task<ManifestDocument> ReadManifest(IFormFile? file, CancellationToken cancellationToken)
    {
        if (file is null || file.Length == 0 || file.Length > 8 * 1024 * 1024) throw new GuardException("请选择不超过 8 MB 的 JSON 清单。");
        await using var stream = file.OpenReadStream();
        using var bytes = new MemoryStream();
        await stream.CopyToAsync(bytes, cancellationToken);
        return ManifestService.Parse(bytes.ToArray());
    }
    public string SaveResult(ManifestResult result)
    {
        if (_results.Count >= 16) _results.TryRemove(_results.Keys.First(), out _);
        var id = Guid.NewGuid().ToString("N"); _results[id] = result; return id;
    }
    public ManifestResult? Result(string id) => _results.GetValueOrDefault(id);
}
