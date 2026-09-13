using System.Security.Cryptography;

namespace FileGuard.Core;

public sealed class CleanupService(FileGuardStore store, GuardSettings settings, Scanner scanner)
{
    internal Action<string, CleanupOperation>? Checkpoint { get; set; }
    internal Func<string, long> AvailableSpace { get; set; } = directory => new DriveInfo(Path.GetPathRoot(directory)!).AvailableFreeSpace;
    private string QuarantineRoot => Path.GetFullPath(settings.QuarantineDirectory ?? Path.Combine(store.DataDirectory, "quarantine"));

    public CleanupPlan CreatePlan(string scanId, PlanOptions options)
    {
        if (options.ValidForHours is < 1 or > 168) throw new GuardException("计划有效期必须为 1 到 168 小时。");
        var scan = store.GetScan(scanId);
        if (scan.State is not (ScanState.Completed or ScanState.PartialFailure)) throw new GuardException("只能从已经结束的扫描生成计划。");
        if (options.Rule == KeepRule.PreferredDirectory && string.IsNullOrWhiteSpace(options.PreferredDirectory)) throw new GuardException("首选目录规则需要目录。");
        if (options.Rule == KeepRule.Explicit && options.KeepPaths.Length == 0) throw new GuardException("显式保留规则需要指定保留文件。");
        var groups = scanner.GetDuplicates(scanId);
        var operations = new List<CleanupOperation>();
        var estimateKnown = true;
        long estimate = 0;
        foreach (var group in groups)
        {
            var ordered = group.Files.OrderBy(x => x.FullPath, StringComparer.Ordinal).ToArray();
            FileRecord keeper = options.Rule switch
            {
                KeepRule.Oldest => ordered.MinBy(x => x.ModifiedUtc)!,
                KeepRule.Newest => ordered.MaxBy(x => x.ModifiedUtc)!,
                KeepRule.PreferredDirectory => ordered.FirstOrDefault(x => PathSafety.IsWithin(x.FullPath, options.PreferredDirectory!)) ?? ordered[0],
                KeepRule.Explicit => ordered.FirstOrDefault(x => options.KeepPaths.Contains(x.FullPath, PathSafety.Comparer))
                    ?? throw new GuardException("每个重复组必须显式指定至少一个保留项。"),
                _ => ordered[0]
            };
            foreach (var candidate in ordered)
            {
                // Preserve all hardlink aliases and all explicitly selected keepers. Unknown identities are read-only.
                if (PathSafety.Comparer.Equals(candidate.FullPath, keeper.FullPath) || candidate.Identity is null || candidate.LinkCount != 1 ||
                    candidate.Identity == keeper.Identity || options.KeepPaths.Contains(candidate.FullPath, PathSafety.Comparer)) continue;
                operations.Add(new CleanupOperation { Candidate = candidate, Keeper = keeper });
                estimate += candidate.Size;
                if (candidate.SparseOrCompressed || group.EstimatedReclaimableBytes is null) estimateKnown = false;
            }
        }
        var plan = new CleanupPlan
        {
            ScanId = scanId, Options = options, ExpiresUtc = DateTimeOffset.UtcNow.AddHours(options.ValidForHours),
            Operations = operations, EstimatedReclaimableBytes = estimateKnown ? estimate : null
        };
        foreach (var operation in operations)
        {
            operation.PlanId = plan.Id;
            operation.QuarantinePath = Path.Combine(QuarantineRoot, operation.Id + ".bin");
        }
        store.SavePlan(plan);
        foreach (var operation in operations) store.SaveOperation(operation);
        store.Audit("plan", plan.Id, "planned", "完整 SHA-256 分组；执行前仍需重新验证身份和逐字节内容。");
        return plan;
    }

    public async Task<IReadOnlyList<OperationResult>> ApplyAsync(string planId, bool confirm = false, CancellationToken cancellationToken = default)
    {
        using var coordinator = store.AcquireMutationLock();
        var plan = store.GetPlan(planId);
        if (plan.SchemaVersion != 1) throw new GuardException("不支持的清理计划版本。");
        var results = new List<OperationResult>();
        foreach (var operation in plan.Operations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (operation.State != OperationState.Planned)
            {
                results.Add(new(operation.Id, operation.State, "此操作已处理；不会重复执行。中断操作请使用 quarantine recover。", !confirm));
                continue;
            }
            if (!confirm)
            {
                results.Add(new(operation.Id, operation.State, plan.ExpiresUtc < DateTimeOffset.UtcNow ? "预览：计划已过期，执行时将跳过。" : "预览：候选将移入隔离区；执行时重新验证。", true));
                continue;
            }
            try
            {
                if (plan.ExpiresUtc < DateTimeOffset.UtcNow) throw new GuardException("计划已过期，请重新扫描并生成计划。");
                ValidateOperationPaths(operation);
                EnsureQuarantine();
                using var candidate = SafeFile.OpenMutable(operation.Candidate.FullPath, operation.Candidate.Root);
                using var keeper = SafeFile.OpenRead(operation.Keeper.FullPath, operation.Keeper.Root);
                ValidateSnapshot(candidate.Snapshot(), operation.Candidate);
                ValidateSnapshot(keeper.Snapshot(), operation.Keeper);
                if (candidate.Snapshot().LinkCount != 1 || candidate.Snapshot().Identity == keeper.Snapshot().Identity) throw new GuardException("候选具有硬链接或与保留项为同一物理文件。");
                await ValidateContent(candidate, operation.Candidate.Sha256!, cancellationToken);
                await ValidateContent(keeper, operation.Keeper.Sha256!, cancellationToken);
                if (!await EqualBytes(candidate.Stream, keeper.Stream, cancellationToken)) throw new GuardException("候选与保留项的字节内容不相同。");
                using var targetGuards = new DirectoryGuards(QuarantineRoot, mutation: true);
                RejectConflict(operation.QuarantinePath);
                operation.SafetyCheck = "allowlist; no-reparse; final-handle-path; identity; size; timestamp; SHA-256; byte-compare; keeper-readable; exclusive-process-lock; no-overwrite";
                SetState(operation, OperationState.Started, "身份、摘要、逐字节和保留副本验证通过。", "apply");
                Checkpoint?.Invoke("started", operation);
                if (SameVolume(operation.Candidate.FullPath, operation.QuarantinePath))
                {
                    operation.QuarantineIdentity = candidate.Snapshot().Identity;
                    store.SaveOperation(operation);
                    candidate.RenameTo(operation.QuarantinePath);
                    Checkpoint?.Invoke("renamed", operation);
                }
                else
                {
                    EnsureCapacity(QuarantineRoot, operation.Candidate.Size);
                    using var copy = await CopyVerified(candidate, operation.QuarantinePath, operation.Candidate.Sha256!, identity =>
                    { operation.QuarantineIdentity = identity; store.SaveOperation(operation); Checkpoint?.Invoke("copy-created", operation); }, cancellationToken);
                    operation.QuarantineIdentity = NativeFiles.Snapshot(copy.SafeFileHandle).Identity;
                    SetState(operation, OperationState.Copied, "跨卷副本已完整校验并持久化，即将删除原文件句柄。", "copy");
                    Checkpoint?.Invoke("copied", operation);
                    cancellationToken.ThrowIfCancellationRequested();
                    candidate.Delete();
                    Checkpoint?.Invoke("source-deleted", operation);
                }
                SetState(operation, OperationState.Completed, "文件已移入可恢复隔离区；同卷移动未释放磁盘空间。", "apply");
                results.Add(new(operation.Id, operation.State, operation.Detail!, false));
            }
            catch (OperationCanceledException)
            {
                store.Audit("cancel", operation.Id, operation.State.ToString(), operation.SafetyCheck ?? "尚未执行文件修改。");
                throw;
            }
            catch (Exception error) when (Expected(error))
            {
                var state = operation.State == OperationState.Planned ? OperationState.Skipped : OperationState.NeedsReview;
                SetState(operation, state, SafeError(error), "apply");
                results.Add(new(operation.Id, operation.State, operation.Detail!, false));
            }
        }
        return results;
    }

    public async Task<OperationResult> RestoreAsync(string operationId, bool confirm = false, CancellationToken cancellationToken = default)
    {
        using var coordinator = store.AcquireMutationLock();
        var operation = store.GetOperation(operationId);
        if (!confirm) return new(operation.Id, operation.State, "预览恢复到原路径；存在同名文件时拒绝覆盖。", true);
        if (operation.State == OperationState.Restored) return new(operation.Id, operation.State, "已恢复，不会重复操作。", false);
        if (operation.State != OperationState.Completed) throw new GuardException("只有已完成隔离的文件可恢复；中断操作请先 recover。");
        try
        {
            ValidateOperationPaths(operation);
            RejectConflict(operation.Candidate.FullPath);
            // Do not silently recreate missing ancestor trees: their identity and permissions may have changed.
            using var destination = new DirectoryGuards(Path.GetDirectoryName(operation.Candidate.FullPath)!, mutation: true);
            using var source = SafeFile.OpenMutable(operation.QuarantinePath, QuarantineRoot);
            ValidateQuarantineIdentity(source, operation);
            await ValidateContent(source, operation.Candidate.Sha256!, cancellationToken);
            operation.SafetyCheck = "restore; allowlist; no-reparse; final-handle-path; quarantine-identity; SHA-256; no-overwrite; exclusive-process-lock";
            operation.Intent = "restore";
            SetState(operation, OperationState.Restoring, "隔离内容验证通过，开始恢复。", "restore");
            if (SameVolume(operation.QuarantinePath, operation.Candidate.FullPath))
            {
                operation.RestoredIdentity = source.Snapshot().Identity;
                store.SaveOperation(operation);
                source.RenameTo(operation.Candidate.FullPath);
                Checkpoint?.Invoke("restore-renamed", operation);
            }
            else
            {
                EnsureCapacity(Path.GetDirectoryName(operation.Candidate.FullPath)!, operation.Candidate.Size);
                using var copy = await CopyVerified(source, operation.Candidate.FullPath, operation.Candidate.Sha256!, identity =>
                { operation.RestoredIdentity = identity; store.SaveOperation(operation); Checkpoint?.Invoke("restore-copy-created", operation); }, cancellationToken);
                operation.RestoredIdentity = NativeFiles.Snapshot(copy.SafeFileHandle).Identity;
                store.SaveOperation(operation);
                Checkpoint?.Invoke("restore-copied", operation);
                cancellationToken.ThrowIfCancellationRequested();
                source.Delete();
            }
            SetState(operation, OperationState.Restored, "已恢复至原路径。", "restore");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception error) when (Expected(error))
        {
            // Before any change a conflict is retryable; after starting require reconciliation.
            SetState(operation, operation.State == OperationState.Completed ? OperationState.Completed : OperationState.NeedsReview, SafeError(error), "restore-failed");
            return new(operation.Id, OperationState.Failed, operation.Detail!, false);
        }
        return new(operation.Id, operation.State, operation.Detail!, false);
    }

    public async Task<OperationResult> PurgeAsync(string operationId, bool confirm = false, bool permanent = false, CancellationToken cancellationToken = default)
    {
        using var coordinator = store.AcquireMutationLock();
        var operation = store.GetOperation(operationId);
        if (!confirm) return new(operation.Id, operation.State, "预览永久清除隔离文件；执行还需 permanent 二次确认。", true);
        if (!permanent) throw new GuardException("永久清除需要再次显式确认 permanent。");
        if (operation.State == OperationState.Purged) return new(operation.Id, operation.State, "已永久清除。", false);
        if (operation.State != OperationState.Completed) throw new GuardException("只能永久清除已经完成隔离的文件。");
        try
        {
            ValidateOperationPaths(operation);
            using var source = SafeFile.OpenMutable(operation.QuarantinePath, QuarantineRoot);
            ValidateQuarantineIdentity(source, operation);
            await ValidateContent(source, operation.Candidate.Sha256!, cancellationToken);
            operation.SafetyCheck = "purge; second-confirmation; quarantine-boundary; no-reparse; identity; SHA-256; exclusive-process-lock";
            operation.Intent = "purge";
            SetState(operation, OperationState.Purging, "开始永久清除已验证的隔离文件。", "purge");
            source.Delete();
            Checkpoint?.Invoke("purged", operation);
            operation.ActualReclaimedBytes = null;
            SetState(operation, OperationState.Purged, "已永久清除；物理回收字节无法在快照/压缩等文件系统上准确测量。", "purge");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception error) when (Expected(error))
        {
            SetState(operation, operation.State == OperationState.Completed ? OperationState.Completed : OperationState.NeedsReview, SafeError(error), "purge-failed");
            return new(operation.Id, OperationState.Failed, operation.Detail!, false);
        }
        return new(operation.Id, operation.State, operation.Detail!, false);
    }

    public async Task<IReadOnlyList<OperationResult>> RecoverAsync(CancellationToken cancellationToken = default)
    {
        using var coordinator = store.AcquireMutationLock();
        var results = new List<OperationResult>();
        foreach (var operation in store.EnumerateOperations())
        {
            if (operation.State is not (OperationState.Started or OperationState.Copied or OperationState.Restoring or OperationState.Purging or OperationState.NeedsReview)) continue;
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                ValidateOperationPaths(operation);
                var sourceExists = File.Exists(operation.Candidate.FullPath);
                var targetExists = File.Exists(operation.QuarantinePath);
                if (operation.Intent == "purge" && !targetExists)
                    SetState(operation, OperationState.Purged, "已确认永久清除后的隔离文件不存在。", "recover");
                else if (!sourceExists && targetExists && operation.Intent == "apply")
                {
                    using var target = SafeFile.OpenRead(operation.QuarantinePath, QuarantineRoot);
                    ValidateQuarantineIdentity(target, operation);
                    await ValidateContent(target, operation.Candidate.Sha256!, cancellationToken);
                    SetState(operation, OperationState.Completed, "中断后确认隔离文件身份和完整内容，原路径不存在。", "recover");
                }
                else if (sourceExists && !targetExists && operation.Intent == "restore")
                {
                    using var source = SafeFile.OpenRead(operation.Candidate.FullPath, operation.Candidate.Root);
                    if (operation.RestoredIdentity is null || source.Snapshot().Identity != operation.RestoredIdentity) throw new GuardException("恢复后的文件身份无法确认。");
                    await ValidateContent(source, operation.Candidate.Sha256!, cancellationToken);
                    SetState(operation, OperationState.Restored, "中断后确认恢复文件身份和完整内容。", "recover");
                }
                else if (sourceExists && !targetExists && operation.Intent == "apply")
                {
                    using var source = SafeFile.OpenRead(operation.Candidate.FullPath, operation.Candidate.Root);
                    ValidateSnapshot(source.Snapshot(), operation.Candidate);
                    await ValidateContent(source, operation.Candidate.Sha256!, cancellationToken);
                    SetState(operation, OperationState.Planned, "原文件完整且尚未隔离；可重新预览并执行原计划。", "recover");
                }
                else if (sourceExists && targetExists && operation.Intent == "apply")
                {
                    using var source = SafeFile.OpenRead(operation.Candidate.FullPath, operation.Candidate.Root);
                    ValidateSnapshot(source.Snapshot(), operation.Candidate);
                    await ValidateContent(source, operation.Candidate.Sha256!, cancellationToken);
                    using var target = SafeFile.OpenMutable(operation.QuarantinePath, QuarantineRoot);
                    ValidateQuarantineIdentity(target, operation);
                    if (!await IsExactPrefix(target.Stream, source.Stream, cancellationToken)) throw new GuardException("中断的隔离副本包含不同内容，可能已被修改；保留所有副本。");
                    operation.SafetyCheck = "recover-copy-rollback; original-identity-and-full-SHA256; quarantine-identity-and-byte-prefix; no-reparse; handle-delete";
                    store.Audit("recover-copy-rollback", operation.Id, "started", operation.SafetyCheck);
                    target.Delete();
                    SetState(operation, OperationState.Planned, "原文件完整；已撤销中断复制的隔离副本，可重新执行计划。", "recover");
                }
                else if (sourceExists && targetExists && operation.Intent == "restore")
                {
                    using var quarantine = SafeFile.OpenRead(operation.QuarantinePath, QuarantineRoot);
                    ValidateQuarantineIdentity(quarantine, operation);
                    await ValidateContent(quarantine, operation.Candidate.Sha256!, cancellationToken);
                    using var restored = SafeFile.OpenMutable(operation.Candidate.FullPath, operation.Candidate.Root);
                    if (operation.RestoredIdentity is null || restored.Snapshot().Identity != operation.RestoredIdentity || restored.Snapshot().LinkCount != 1)
                        throw new GuardException("恢复目标身份无法确认，保留所有副本。");
                    if (!await IsExactPrefix(restored.Stream, quarantine.Stream, cancellationToken)) throw new GuardException("中断的恢复目标包含不同内容，可能已被修改；保留所有副本。");
                    operation.SafetyCheck = "recover-restore-rollback; quarantine-identity-and-full-SHA256; restored-identity-and-byte-prefix; no-reparse; handle-delete";
                    store.Audit("recover-restore-rollback", operation.Id, "started", operation.SafetyCheck);
                    restored.Delete();
                    operation.Intent = "apply";
                    SetState(operation, OperationState.Completed, "完整隔离副本仍在；已撤销中断的恢复副本，可以重新恢复。", "recover");
                }
                else SetState(operation, OperationState.NeedsReview, "源/目标存在状态有歧义，保留所有副本。请按恢复手册人工核对；不自动删除。", "recover");
            }
            catch (Exception error) when (Expected(error)) { SetState(operation, OperationState.NeedsReview, SafeError(error), "recover"); }
            results.Add(new(operation.Id, operation.State, operation.Detail!, false));
        }
        return results;
    }

    private void ValidateOperationPaths(CleanupOperation operation)
    {
        if (!OperatingSystem.IsWindows()) throw new GuardException("首版仅 Windows 提供经过保护的隔离/恢复后端；此平台保持只读。");
        foreach (var file in new[] { operation.Candidate, operation.Keeper })
        {
            if (!settings.AllowedRoots.Any(root => PathSafety.IsWithin(file.FullPath, root))) throw new GuardException("计划文件不在当前允许根目录内。");
            PathSafety.Validate(file.FullPath, file.Root);
            if (PathSafety.IsWithin(file.FullPath, QuarantineRoot) || PathSafety.IsWithin(file.FullPath, store.DataDirectory)) throw new GuardException("禁止把应用状态或隔离目录作为清理源。");
        }
        if (operation.Id.Length != 32 || operation.Id.Any(c => !char.IsAsciiHexDigit(c)) ||
            !PathSafety.Comparer.Equals(operation.QuarantinePath, Path.Combine(QuarantineRoot, operation.Id + ".bin"))) throw new GuardException("隔离目标与操作 ID 不匹配。");
        PathSafety.Validate(operation.QuarantinePath, QuarantineRoot);
    }
    private void EnsureQuarantine()
    {
        PathSafety.Validate(QuarantineRoot, QuarantineRoot);
        Directory.CreateDirectory(QuarantineRoot);
        PathSafety.ValidateRoot(QuarantineRoot);
    }
    private static void ValidateSnapshot(FileSnapshot current, FileRecord expected)
    {
        if (current.Identity is null || expected.Identity is null || current.Identity != expected.Identity || current.Size != expected.Size || current.ModifiedUtc != expected.ModifiedUtc)
            throw new GuardException("文件身份、大小或修改时间自扫描后已变化。");
    }
    private static void ValidateQuarantineIdentity(SafeFile file, CleanupOperation operation)
    {
        if (operation.QuarantineIdentity is null || file.Snapshot().Identity != operation.QuarantineIdentity || file.Snapshot().LinkCount != 1)
            throw new GuardException("隔离文件身份或链接数已变化。");
    }
    private static async Task ValidateContent(SafeFile file, string expected, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(expected)) throw new GuardException("缺少完整 SHA-256，拒绝操作。");
        file.Stream.Position = 0;
        var digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(file.Stream, token));
        if (!string.Equals(digest, expected, StringComparison.OrdinalIgnoreCase)) throw new GuardException("文件内容自扫描后已变化。");
    }
    internal static async Task<bool> EqualBytes(Stream left, Stream right, CancellationToken token)
    {
        left.Position = right.Position = 0;
        if (left.Length != right.Length) return false;
        var a = new byte[131072];
        var b = new byte[131072];
        while (true)
        {
            var count = await left.ReadAtLeastAsync(a, a.Length, false, token);
            var other = await right.ReadAtLeastAsync(b, b.Length, false, token);
            if (count != other || !a.AsSpan(0, count).SequenceEqual(b.AsSpan(0, other))) return false;
            if (count == 0) return true;
        }
    }
    private static async Task<FileStream> CopyVerified(SafeFile source, string destination, string expected, Action<string?> created, CancellationToken token)
    {
        source.Stream.Position = 0;
        var target = new FileStream(destination, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 131072, FileOptions.WriteThrough);
        try
        {
            var identity = NativeFiles.Snapshot(target.SafeFileHandle).Identity
                ?? throw new GuardException("目标文件系统缺少可靠文件身份，拒绝跨卷复制提交；原文件已保留。");
            created(identity);
            await source.Stream.CopyToAsync(target, 131072, token);
            await target.FlushAsync(token);
            target.Flush(flushToDisk: true);
            target.Position = 0;
            var digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(target, token));
            if (!string.Equals(digest, expected, StringComparison.OrdinalIgnoreCase) || !await EqualBytes(source.Stream, target, token))
                throw new GuardException("跨卷副本校验失败，保留原文件。");
            File.SetLastWriteTimeUtc(target.SafeFileHandle, source.Snapshot().ModifiedUtc.UtcDateTime);
            target.Flush(flushToDisk: true);
            return target; // Caller holds destination against writers/deletion until source deletion is committed.
        }
        catch { target.Dispose(); throw; }
    }
    private static async Task<bool> IsExactPrefix(Stream partial, Stream complete, CancellationToken token)
    {
        if (partial.Length > complete.Length) return false;
        partial.Position = complete.Position = 0;
        var left = new byte[131072];
        var right = new byte[131072];
        while (true)
        {
            var count = await partial.ReadAtLeastAsync(left, left.Length, false, token);
            if (count == 0) return true;
            await complete.ReadExactlyAsync(right.AsMemory(0, count), token);
            if (!left.AsSpan(0, count).SequenceEqual(right.AsSpan(0, count))) return false;
        }
    }
    private static bool SameVolume(string left, string right) => PathSafety.Comparer.Equals(Path.GetPathRoot(left), Path.GetPathRoot(right));
    private void EnsureCapacity(string directory, long bytes)
    {
        if (AvailableSpace(directory) < bytes + 1048576L) throw new GuardException("隔离或恢复目标容量不足；原文件已保留。");
    }
    private static void RejectConflict(string path)
    {
        if (File.Exists(path) || Directory.Exists(path)) throw new GuardException("目标路径已经存在，禁止覆盖；请处理冲突后重试。");
    }
    private void SetState(CleanupOperation operation, OperationState state, string detail, string action)
    {
        operation.State = state;
        operation.Detail = detail;
        store.SaveOperation(operation);
        store.Audit(action, operation.Id, state + ": " + detail, operation.SafetyCheck ?? "安全检查未通过；未授权进一步修改。");
    }
    private static bool Expected(Exception error) => error is GuardException or IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception;
    private static string SafeError(Exception error) => error is GuardException ? error.Message : error switch
    {
        FileNotFoundException or DirectoryNotFoundException => "文件或父目录不存在；请重新扫描或检查恢复目标。",
        UnauthorizedAccessException => "权限不足，未覆盖或删除任何未验证文件。",
        _ => "文件操作失败（可能被占用、容量不足或目标冲突）；保留日志，使用 recover 核对。"
    };
}
