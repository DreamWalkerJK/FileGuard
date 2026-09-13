using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace FileGuard.Core;

/// <summary>Connections are short lived; every cross-process mutation uses a separate OS-backed store lock.</summary>
public sealed class FileGuardStore
{
    public string DataDirectory { get; }
    public string DatabasePath => Path.Combine(DataDirectory, "fileguard.db");
    public static string CurrentOwner => $"{Environment.ProcessId}:{Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks}";

    public FileGuardStore(string dataDirectory) => DataDirectory = Path.GetFullPath(dataDirectory);

    public void Initialize()
    {
        Directory.CreateDirectory(DataDirectory);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version";
        var version = Convert.ToInt32(command.ExecuteScalar());
        if (version > 1) throw new GuardException("数据库版本高于当前程序支持版本，请升级程序。数据库未修改。");
        command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;";
        command.ExecuteNonQuery();
        using var transaction = connection.BeginTransaction();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA user_version";
        version = Convert.ToInt32(command.ExecuteScalar());
        if (version > 1) throw new GuardException("数据库版本高于当前程序支持版本，请升级程序。数据库未修改。");
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS records(kind TEXT NOT NULL,id TEXT NOT NULL,json TEXT NOT NULL,updated TEXT NOT NULL,PRIMARY KEY(kind,id));
            CREATE TABLE IF NOT EXISTS files(scanId TEXT NOT NULL,path TEXT NOT NULL,size INTEGER NOT NULL,sha256 TEXT,state TEXT NOT NULL,json TEXT NOT NULL,PRIMARY KEY(scanId,path));
            CREATE INDEX IF NOT EXISTS files_size ON files(scanId,size);
            CREATE INDEX IF NOT EXISTS files_hash ON files(scanId,sha256,size);
            CREATE TABLE IF NOT EXISTS history(id TEXT PRIMARY KEY,utc TEXT NOT NULL,json TEXT NOT NULL);
            PRAGMA user_version=1;
            """;
        command.ExecuteNonQuery();
        transaction.Commit();
        MarkInterruptedScans();
    }

    public SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath, Mode = SqliteOpenMode.ReadWriteCreate, DefaultTimeout = 30,
            Pooling = false
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA busy_timeout=30000; PRAGMA synchronous=FULL;";
        command.ExecuteNonQuery();
        return connection;
    }

    public void SaveScan(ScanRecord scan) => Save("scan", scan.Id, scan);
    public void SaveSetting<T>(string key, T value) => Save("setting", key, value);
    public T? GetSetting<T>(string key) where T : class => TryGet<T>("setting", key);
    public ScanRecord GetScan(string id) => Get<ScanRecord>("scan", id);
    public Page<ScanRecord> ListScans(int offset = 0, int limit = 50) => List<ScanRecord>("scan", offset, limit);
    public void SavePlan(CleanupPlan plan) => Save("plan", plan.Id, plan);
    public CleanupPlan GetPlan(string id)
    {
        var plan = Get<CleanupPlan>("plan", id);
        return plan with { Operations = plan.Operations.Select(x => TryGet<CleanupOperation>("operation", x.Id) ?? x).ToList() };
    }
    public Page<CleanupPlan> ListPlans(int offset = 0, int limit = 50) => List<CleanupPlan>("plan", offset, limit);
    public void SaveOperation(CleanupOperation operation)
    {
        operation.UpdatedUtc = DateTimeOffset.UtcNow;
        Save("operation", operation.Id, operation);
    }
    public CleanupOperation GetOperation(string id) => Get<CleanupOperation>("operation", id);
    public Page<CleanupOperation> ListOperations(int offset = 0, int limit = 50) => List<CleanupOperation>("operation", offset, limit);
    public IEnumerable<CleanupOperation> EnumerateOperations() => Enumerate<CleanupOperation>("operation");
    public void SaveFile(FileRecord file)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO files(scanId,path,size,sha256,state,json) VALUES($scan,$path,$size,$hash,$state,$json) ON CONFLICT(scanId,path) DO UPDATE SET size=$size,sha256=$hash,state=$state,json=$json";
        command.Parameters.AddWithValue("$scan", file.ScanId);
        command.Parameters.AddWithValue("$path", file.FullPath);
        command.Parameters.AddWithValue("$size", file.Size);
        command.Parameters.AddWithValue("$hash", (object?)file.Sha256 ?? DBNull.Value);
        command.Parameters.AddWithValue("$state", file.State.ToString());
        command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(file, JsonDefaults.Options));
        command.ExecuteNonQuery();
    }

    public Page<FileRecord> GetFiles(string scanId, int offset = 0, int limit = 100, FileState? state = null)
    {
        ValidatePage(offset, limit);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        var filter = state is null ? "" : " AND state=$state";
        command.Parameters.AddWithValue("$scan", scanId);
        if (state is not null) command.Parameters.AddWithValue("$state", state.ToString()!);
        command.CommandText = "SELECT COUNT(*) FROM files WHERE scanId=$scan" + filter;
        var total = (long)command.ExecuteScalar()!;
        command.CommandText = "SELECT json FROM files WHERE scanId=$scan" + filter + " ORDER BY path LIMIT $limit OFFSET $offset";
        command.Parameters.AddWithValue("$limit", limit);
        command.Parameters.AddWithValue("$offset", offset);
        using var reader = command.ExecuteReader();
        var items = new List<FileRecord>();
        while (reader.Read()) items.Add(JsonSerializer.Deserialize<FileRecord>(reader.GetString(0), JsonDefaults.Options)!);
        return new(items, total, offset, limit);
    }

    public IEnumerable<FileRecord> EnumerateFiles(string scanId)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT json FROM files WHERE scanId=$id ORDER BY path";
        command.Parameters.AddWithValue("$id", scanId);
        using var reader = command.ExecuteReader();
        while (reader.Read()) yield return JsonSerializer.Deserialize<FileRecord>(reader.GetString(0), JsonDefaults.Options)!;
    }

    public IEnumerable<FileRecord> EnumerateHashCandidates(string scanId, bool hashAll)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = hashAll
            ? "SELECT json FROM files WHERE scanId=$id AND state='Indexed' ORDER BY size,path"
            : "SELECT json FROM files WHERE scanId=$id AND state='Indexed' AND size IN (SELECT size FROM files WHERE scanId=$id AND state='Indexed' GROUP BY size HAVING COUNT(*) > 1) ORDER BY size,path";
        command.Parameters.AddWithValue("$id", scanId);
        using var reader = command.ExecuteReader();
        while (reader.Read()) yield return JsonSerializer.Deserialize<FileRecord>(reader.GetString(0), JsonDefaults.Options)!;
    }

    public void Audit(string action, string subjectId, string result, string safetyCheck)
    {
        var entry = new AuditEvent(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, action, subjectId, result, safetyCheck);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO history(id,utc,json) VALUES($id,$utc,$json)";
        command.Parameters.AddWithValue("$id", entry.Id);
        command.Parameters.AddWithValue("$utc", entry.Utc.ToString("O"));
        command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(entry, JsonDefaults.Options));
        command.ExecuteNonQuery();
    }

    public Page<AuditEvent> ListHistory(int offset = 0, int limit = 50)
    {
        ValidatePage(offset, limit);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM history";
        var total = (long)command.ExecuteScalar()!;
        command.CommandText = "SELECT json FROM history ORDER BY utc DESC,id LIMIT $limit OFFSET $offset";
        command.Parameters.AddWithValue("$limit", limit);
        command.Parameters.AddWithValue("$offset", offset);
        using var reader = command.ExecuteReader();
        var items = new List<AuditEvent>();
        while (reader.Read()) items.Add(JsonSerializer.Deserialize<AuditEvent>(reader.GetString(0), JsonDefaults.Options)!);
        return new(items, total, offset, limit);
    }

    public IDisposable AcquireMutationLock()
    {
        try
        {
            // Windows share denial and Unix flock used by FileStream(FileShare.None) are released on process exit.
            // Unlike a lease timeout this cannot expire while a slow file operation is still executing.
            return new FileStream(Path.Combine(DataDirectory, "mutation.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException) { throw new GuardException("另一个进程正在执行清理或恢复；请稍后重试。"); }
    }

    private void Save<T>(string kind, string id, T value)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO records(kind,id,json,updated) VALUES($kind,$id,$json,$utc) ON CONFLICT(kind,id) DO UPDATE SET json=$json,updated=$utc";
        command.Parameters.AddWithValue("$kind", kind);
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(value, JsonDefaults.Options));
        command.Parameters.AddWithValue("$utc", DateTimeOffset.UtcNow.ToString("O"));
        command.ExecuteNonQuery();
    }
    private T Get<T>(string kind, string id) where T : class => TryGet<T>(kind, id) ?? throw new GuardException("未找到指定记录。");
    private T? TryGet<T>(string kind, string id) where T : class
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT json FROM records WHERE kind=$kind AND id=$id";
        command.Parameters.AddWithValue("$kind", kind);
        command.Parameters.AddWithValue("$id", id);
        return command.ExecuteScalar() is string json ? JsonSerializer.Deserialize<T>(json, JsonDefaults.Options) : null;
    }
    private Page<T> List<T>(string kind, int offset, int limit)
    {
        ValidatePage(offset, limit);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM records WHERE kind=$kind";
        command.Parameters.AddWithValue("$kind", kind);
        var total = (long)command.ExecuteScalar()!;
        command.CommandText = "SELECT json FROM records WHERE kind=$kind ORDER BY updated DESC,id LIMIT $limit OFFSET $offset";
        command.Parameters.AddWithValue("$limit", limit);
        command.Parameters.AddWithValue("$offset", offset);
        using var reader = command.ExecuteReader();
        var items = new List<T>();
        while (reader.Read()) items.Add(JsonSerializer.Deserialize<T>(reader.GetString(0), JsonDefaults.Options)!);
        return new(items, total, offset, limit);
    }
    private IEnumerable<T> Enumerate<T>(string kind)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT json FROM records WHERE kind=$kind ORDER BY id";
        command.Parameters.AddWithValue("$kind", kind);
        using var reader = command.ExecuteReader();
        while (reader.Read()) yield return JsonSerializer.Deserialize<T>(reader.GetString(0), JsonDefaults.Options)!;
    }
    private void MarkInterruptedScans()
    {
        foreach (var scan in Enumerate<ScanRecord>("scan"))
        {
            if (scan.State is not (ScanState.Queued or ScanState.Enumerating or ScanState.Hashing) || IsOwnerAlive(scan.Owner)) continue;
            scan.State = ScanState.Interrupted;
            scan.Error = "原进程已退出；本次扫描不可原地恢复，请使用相同选项重新扫描。";
            scan.FinishedUtc = DateTimeOffset.UtcNow;
            SaveScan(scan);
        }
    }
    public static bool IsOwnerAlive(string owner)
    {
        var parts = owner.Split(':');
        if (parts.Length != 2 || !int.TryParse(parts[0], out var pid) || !long.TryParse(parts[1], out var ticks)) return false;
        try { using var process = Process.GetProcessById(pid); return process.StartTime.ToUniversalTime().Ticks == ticks && !process.HasExited; }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (System.ComponentModel.Win32Exception) { return true; } // Unknown ownership must not steal live work.
    }
    private static void ValidatePage(int offset, int limit)
    {
        if (offset < 0 || limit is < 1 or > 10000) throw new GuardException("分页参数必须满足 offset >= 0，limit 为 1 到 10000。");
    }
}
