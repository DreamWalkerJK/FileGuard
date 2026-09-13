using System.Text.Json;
using System.Text.Json.Serialization;

namespace FileGuard.Core;

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
}

public sealed record GuardSettings
{
    public int SchemaVersion { get; init; } = 1;
    public string DataDirectory { get; init; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FileGuard");
    public string[] AllowedRoots { get; init; } = [];
    public string? QuarantineDirectory { get; init; }
    public int Concurrency { get; init; } = 2;
    public int ChannelCapacity { get; init; } = 64;
    public long BytesPerSecond { get; init; }
    public bool DiagnosticPaths { get; init; }
}

public sealed record ScanOptions
{
    public string[] Roots { get; init; } = [];
    public string[] Include { get; init; } = [];
    public string[] Exclude { get; init; } = [];
    public string[] Extensions { get; init; } = [];
    public long? MinSize { get; init; }
    public long? MaxSize { get; init; }
    public DateTimeOffset? ModifiedAfter { get; init; }
    public DateTimeOffset? ModifiedBefore { get; init; }
    public int Concurrency { get; init; } = 2;
    public int ChannelCapacity { get; init; } = 64;
    public long BytesPerSecond { get; init; }
    public bool HashAll { get; init; }
}

public enum ScanState { Queued, Enumerating, Hashing, Completed, PartialFailure, Cancelled, Interrupted, Failed }
public enum FileState { Indexed, Ready, Unreadable, Missing, Unstable, SkippedLink }

public sealed record ScanRecord
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public ScanOptions Options { get; init; } = new();
    public ScanState State { get; set; } = ScanState.Queued;
    public DateTimeOffset CreatedUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? FinishedUtc { get; set; }
    public long FileCount { get; set; }
    public long TotalBytes { get; set; }
    public long BytesRead { get; set; }
    public long ErrorCount { get; set; }
    public long HashCount { get; set; }
    public long CandidateCount { get; set; }
    public string? Error { get; set; }
    public string Owner { get; set; } = "";
    public string SnapshotWarning { get; init; } = "扫描不是整个文件系统的原子快照。";
}

public sealed record FileRecord
{
    public string ScanId { get; init; } = "";
    public string Root { get; init; } = "";
    public string RelativePath { get; init; } = "";
    public string FullPath { get; init; } = "";
    public long Size { get; init; }
    public DateTimeOffset ModifiedUtc { get; init; }
    public string? Identity { get; init; }
    public uint? LinkCount { get; init; }
    public bool SparseOrCompressed { get; init; }
    public string? Sha256 { get; init; }
    public FileState State { get; init; }
    public string? Error { get; init; }
    public bool IsDirectory { get; init; }
}

public sealed record ScanProgress(string ScanId, ScanState State, long Files, long BytesRead, long Errors);
public sealed record DuplicateGroup(string Id, long Size, string Sha256, IReadOnlyList<FileRecord> Files,
    long LogicalDuplicateBytes, long? EstimatedReclaimableBytes, string CapacityNote);
public sealed record Page<T>(IReadOnlyList<T> Items, long Total, int Offset, int Limit);

public sealed record ManifestDocument
{
    public int SchemaVersion { get; init; } = 1;
    public string Algorithm { get; init; } = "SHA-256";
    public DateTimeOffset CreatedUtc { get; init; } = DateTimeOffset.UtcNow;
    public List<ManifestEntry> Files { get; init; } = [];
}
public sealed record ManifestEntry(string Path, long Size, string? Sha256, DateTimeOffset ModifiedUtc, FileState State, string? Error = null, bool IsDirectory = false);
public enum DifferenceKind { Added, Missing, ContentChanged, Unreadable, Unstable, Unchanged }
public sealed record ManifestDifference(string Path, DifferenceKind Kind, string? Detail = null);
public sealed record ManifestResult(IReadOnlyList<ManifestDifference> Differences)
{
    public bool HasDifferences => Differences.Any(x => x.Kind != DifferenceKind.Unchanged);
}

public enum KeepRule { FirstPath, Oldest, Newest, PreferredDirectory, Explicit }
public sealed record PlanOptions
{
    public KeepRule Rule { get; init; } = KeepRule.FirstPath;
    public string? PreferredDirectory { get; init; }
    public string[] KeepPaths { get; init; } = [];
    public int ValidForHours { get; init; } = 24;
}
public enum OperationState { Planned, Started, Copied, Completed, Skipped, Failed, Restoring, Restored, Purging, Purged, NeedsReview }
public sealed record CleanupPlan
{
    public int SchemaVersion { get; init; } = 1;
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string ScanId { get; init; } = "";
    public DateTimeOffset CreatedUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresUtc { get; init; }
    public PlanOptions Options { get; init; } = new();
    public List<CleanupOperation> Operations { get; init; } = [];
    public long LogicalBytes => Operations.Sum(x => x.Candidate.Size);
    public long? EstimatedReclaimableBytes { get; init; }
    public string CapacityNote { get; init; } = "隔离不等于释放磁盘空间；永久清除后才可能释放。";
}
public sealed record CleanupOperation
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string PlanId { get; set; } = "";
    public FileRecord Candidate { get; init; } = new();
    public FileRecord Keeper { get; init; } = new();
    public string QuarantinePath { get; set; } = "";
    public string? QuarantineIdentity { get; set; }
    public string? RestoredIdentity { get; set; }
    public string Intent { get; set; } = "apply";
    public OperationState State { get; set; } = OperationState.Planned;
    public string? Detail { get; set; }
    public string? SafetyCheck { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public long? ActualReclaimedBytes { get; set; } = 0;
}
public sealed record OperationResult(string Id, OperationState State, string Detail, bool DryRun);
public sealed record AuditEvent(string Id, DateTimeOffset Utc, string Action, string SubjectId, string Result, string SafetyCheck);
public sealed class GuardException(string message) : Exception(message);
