using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using FileGuard.Core;

namespace FileGuard.Cli;

public static class CliApplication
{
    private const string GlobalOptions = "config data allow-root quarantine concurrency capacity bytes-per-second diagnostic-paths json help";

    public static async Task<int> RunAsync(string[] arguments, TextWriter stdout, TextWriter stderr, CancellationToken cancellationToken = default)
    {
        var json = arguments.Any(x => x is "--json" or "--json=true");
        var command = "fileguard";
        var diagnosticPaths = false;
        try
        {
            var args = Arguments.Parse(arguments);
            json = args.Flag("json");
            command = args.Positionals.FirstOrDefault() ?? "help";
            if (command is "manifest" or "cleanup" or "quarantine" or "scans")
                command += " " + (args.Positionals.ElementAtOrDefault(1) ?? "");
            if (args.Flag("help") || command == "help")
            {
                await WriteAsync(stdout, json, command, new { help = Help }, Help);
                return 0;
            }

            ValidateCommand(args, command);
            var settings = LoadSettings(args);
            diagnosticPaths = settings.DiagnosticPaths;
            if (command == "serve") return await ServeAsync(args, settings, stdout, stderr, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            var store = new FileGuardStore(settings.DataDirectory);
            store.Initialize();
            // An explicit local root authorizes reading only when no allowlist has been configured.
            var explicitRoots = command == "scan" ? args.Operands(1).Concat(args.Many("root")).ToArray()
                : command is "manifest create" or "manifest verify" ? [args.RequiredOperand(2, "root")] : Array.Empty<string>();
            if (settings.AllowedRoots.Length == 0 && explicitRoots.Length > 0)
                settings = settings with { AllowedRoots = explicitRoots.Select(Path.GetFullPath).ToArray() };
            var scanner = new Scanner(store, settings);
            var manifests = new ManifestService(scanner, store);
            var cleanup = new CleanupService(store, settings, scanner);
            object data;
            var code = 0;

            switch (command)
            {
                case "scan":
                {
                    if (explicitRoots.Length == 0) explicitRoots = settings.AllowedRoots;
                    if (explicitRoots.Length == 0) throw new UsageException("Specify a scan root or configure allowedRoots.");
                    var options = new ScanOptions
                    {
                        Roots = explicitRoots, Include = args.Many("include"), Exclude = args.Many("exclude"),
                        Extensions = args.Many("extension"), MinSize = args.OptionalLong("min-size", 0),
                        MaxSize = args.OptionalLong("max-size", 0), ModifiedAfter = args.Date("modified-after"),
                        ModifiedBefore = args.Date("modified-before"), Concurrency = settings.Concurrency,
                        ChannelCapacity = settings.ChannelCapacity, BytesPerSecond = settings.BytesPerSecond,
                        HashAll = args.Flag("hash-all")
                    };
                    if (options.MinSize > options.MaxSize) throw new UsageException("min-size cannot exceed max-size.");
                    if (options.ModifiedAfter > options.ModifiedBefore) throw new UsageException("modified-after cannot exceed modified-before.");
                    var scan = await scanner.ScanAsync(options, new ProgressSink(stderr), cancellationToken);
                    data = scan;
                    code = scan.State switch { ScanState.Cancelled => 130, ScanState.Completed => 0, _ => 3 };
                    break;
                }
                case "duplicates": data = scanner.GetDuplicates(args.RequiredOperand(1, "scan-id")); break;
                case "scans list": data = store.ListScans(args.Offset, args.Limit); break;
                case "scans show": data = store.GetScan(args.RequiredOperand(2, "scan-id")); break;
                case "scans files":
                    data = store.GetFiles(args.RequiredOperand(2, "scan-id"), args.Offset, args.Limit,
                        args.Value("state") is { } state ? args.EnumValue<FileState>(state, "state") : null);
                    break;
                case "manifest create":
                {
                    var manifest = await manifests.CreateAsync(args.RequiredOperand(2, "root"), cancellationToken);
                    var output = args.RequiredValue("output");
                    if (!args.Flag("dry-run")) await ManifestService.WriteAsync(output, manifest, cancellationToken);
                    data = new { dryRun = args.Flag("dry-run"), output = Path.GetFullPath(output), manifest };
                    code = manifest.Files.Any(x => x.State is FileState.Unreadable or FileState.Missing or FileState.Unstable) ? 3 : 0;
                    break;
                }
                case "manifest verify":
                {
                    var document = await ManifestService.ReadAsync(args.RequiredValue("manifest"), cancellationToken);
                    var result = await manifests.VerifyAsync(args.RequiredOperand(2, "root"), document, cancellationToken);
                    data = result; code = DifferenceCode(result); break;
                }
                case "manifest diff":
                {
                    var before = await ManifestService.ReadAsync(args.RequiredValue("before"), cancellationToken);
                    var after = await ManifestService.ReadAsync(args.RequiredValue("after"), cancellationToken);
                    var result = manifests.Diff(before, after);
                    data = result; code = DifferenceCode(result); break;
                }
                case "cleanup plan":
                {
                    var rule = (args.Value("rule") ?? "first").ToLowerInvariant() switch
                    {
                        "first" => KeepRule.FirstPath, "oldest" => KeepRule.Oldest, "newest" => KeepRule.Newest,
                        "preferred" => KeepRule.PreferredDirectory, "explicit" => KeepRule.Explicit,
                        _ => throw new UsageException("rule must be first, oldest, newest, preferred, or explicit.")
                    };
                    if (rule == KeepRule.PreferredDirectory && args.Value("preferred-directory") is null)
                        throw new UsageException("The preferred rule requires --preferred-directory.");
                    if (rule == KeepRule.Explicit && args.Many("keep-path").Length == 0)
                        throw new UsageException("The explicit rule requires at least one --keep-path.");
                    data = cleanup.CreatePlan(args.RequiredOperand(2, "scan-id"), new PlanOptions
                    {
                        Rule = rule, PreferredDirectory = args.Value("preferred-directory") is { } preferred ? Path.GetFullPath(preferred) : null,
                        KeepPaths = args.Many("keep-path").Select(Path.GetFullPath).ToArray(),
                        ValidForHours = args.Int("valid-hours", 24, 1, 168)
                    });
                    break;
                }
                case "cleanup list": data = store.ListPlans(args.Offset, args.Limit); break;
                case "cleanup show": data = store.GetPlan(args.RequiredOperand(2, "plan-id")); break;
                case "cleanup apply":
                {
                    var results = await cleanup.ApplyAsync(args.RequiredOperand(2, "plan-id"), args.Confirmed, cancellationToken);
                    data = results; code = OperationCode(results); break;
                }
                case "quarantine list": data = store.ListOperations(args.Offset, args.Limit); break;
                case "quarantine show": data = store.GetOperation(args.RequiredOperand(2, "operation-id")); break;
                case "quarantine restore":
                {
                    var result = await cleanup.RestoreAsync(args.RequiredOperand(2, "operation-id"), args.Confirmed, cancellationToken);
                    data = result; code = OperationCode([result]); break;
                }
                case "quarantine purge":
                {
                    if (args.Confirmed && !args.Flag("permanent"))
                        throw new UsageException("Permanent purge requires both --confirm and --permanent. Use --dry-run to preview.");
                    var result = await cleanup.PurgeAsync(args.RequiredOperand(2, "operation-id"), args.Confirmed,
                        args.Flag("permanent"), cancellationToken);
                    data = result; code = OperationCode([result]); break;
                }
                case "quarantine recover":
                {
                    if (!args.Confirmed)
                        data = new { dryRun = true, operations = store.EnumerateOperations().Where(x => x.State is OperationState.Started or OperationState.Copied or OperationState.Restoring or OperationState.Purging or OperationState.NeedsReview).ToArray() };
                    else
                    {
                        var results = await cleanup.RecoverAsync(cancellationToken);
                        data = results; code = OperationCode(results);
                    }
                    break;
                }
                case "history": data = store.ListHistory(args.Offset, args.Limit); break;
                default: throw new UsageException("Unknown command. Run fileguard --help.");
            }
            await WriteAsync(stdout, json, command, data);
            return code;
        }
        catch (OperationCanceledException)
        {
            await stderr.WriteLineAsync("Cancelled; completed work and operation state have been persisted.");
            await WriteErrorAsync(stdout, json, command, "cancelled", "Operation cancelled.");
            return 130;
        }
        catch (Exception exception) when (exception is UsageException or JsonException or FormatException or ArgumentException)
        {
            var message = exception is UsageException ? exception.Message : "Invalid arguments or configuration. Run fileguard --help.";
            await stderr.WriteLineAsync(message);
            await WriteErrorAsync(stdout, json, command, "invalidArguments", message);
            return 2;
        }
        catch (Exception exception) when (exception is GuardException or IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or Microsoft.Data.Sqlite.SqliteException)
        {
            var message = exception is GuardException ? exception.Message : $"File operation failed ({exception.GetType().Name}). Check access and operation history.";
            await stderr.WriteLineAsync(diagnosticPaths ? exception.ToString() : message);
            await WriteErrorAsync(stdout, json, command, "operationFailed", message);
            return 3;
        }
        catch (Exception exception)
        {
            const string message = "Unexpected operation failure. No success is assumed; review persisted state and use local diagnostics if needed.";
            await stderr.WriteLineAsync(diagnosticPaths ? exception.ToString() : $"{message} ({exception.GetType().Name})");
            await WriteErrorAsync(stdout, json, command, "internalError", message);
            return 3;
        }
    }

    private static int DifferenceCode(ManifestResult result) =>
        result.Differences.Any(x => x.Kind is DifferenceKind.Unreadable or DifferenceKind.Unstable) ? 3 : result.HasDifferences ? 1 : 0;
    private static int OperationCode(IEnumerable<OperationResult> results) =>
        results.Any(x => x.State is OperationState.Failed or OperationState.Skipped or OperationState.NeedsReview) ? 3 : 0;

    private static GuardSettings LoadSettings(Arguments args)
    {
        GuardSettings settings = new();
        if (args.Value("config") is { } config)
        {
            try { settings = JsonSerializer.Deserialize<GuardSettings>(File.ReadAllText(config), JsonDefaults.Options) ?? throw new UsageException("Configuration must be a JSON object."); }
            catch (IOException) { throw new UsageException("Cannot read the specified configuration file."); }
            catch (UnauthorizedAccessException) { throw new UsageException("Cannot access the specified configuration file."); }
        }
        if (settings.SchemaVersion != 1 || settings.AllowedRoots is null || string.IsNullOrWhiteSpace(settings.DataDirectory))
            throw new UsageException("Invalid configuration; schemaVersion 1, dataDirectory, and allowedRoots are required.");
        settings = settings with
        {
            DataDirectory = Path.GetFullPath(args.Value("data") ?? settings.DataDirectory),
            AllowedRoots = args.Many("allow-root").Length > 0 ? args.Many("allow-root").Select(Path.GetFullPath).ToArray() : settings.AllowedRoots.Select(Path.GetFullPath).ToArray(),
            QuarantineDirectory = args.Value("quarantine") ?? settings.QuarantineDirectory,
            Concurrency = args.Int("concurrency", settings.Concurrency, 1, 64),
            ChannelCapacity = args.Int("capacity", settings.ChannelCapacity, 1, 4096),
            BytesPerSecond = args.OptionalLong("bytes-per-second", 0) ?? settings.BytesPerSecond,
            DiagnosticPaths = args.Value("diagnostic-paths") is null ? settings.DiagnosticPaths : args.Flag("diagnostic-paths")
        };
        if (settings.Concurrency is < 1 or > 64 || settings.ChannelCapacity is < 1 or > 4096 || settings.BytesPerSecond < 0)
            throw new UsageException("Invalid configured concurrency, capacity, or bytesPerSecond.");
        return settings;
    }

    private static void ValidateCommand(Arguments args, string command)
    {
        var (options, min, max) = command switch
        {
            "scan" => ("root include exclude extension min-size max-size modified-after modified-before hash-all", 1, int.MaxValue),
            "duplicates" => ("", 2, 2),
            "scans list" or "cleanup list" or "quarantine list" => ("offset limit", 2, 2),
            "scans show" or "cleanup show" or "quarantine show" => ("", 3, 3),
            "scans files" => ("offset limit state", 3, 3),
            "manifest create" => ("output dry-run", 3, 3),
            "manifest verify" => ("manifest", 3, 3),
            "manifest diff" => ("before after", 2, 2),
            "cleanup plan" => ("rule preferred-directory keep-path valid-hours", 3, 3),
            "cleanup apply" or "quarantine restore" => ("confirm dry-run", 3, 3),
            "quarantine purge" => ("confirm permanent dry-run", 3, 3),
            "quarantine recover" => ("confirm dry-run", 2, 2),
            "history" => ("offset limit", 1, 1),
            "serve" => ("urls web-path", 1, 1),
            _ => throw new UsageException("Unknown command. Run fileguard --help.")
        };
        args.Validate(GlobalOptions + " " + options, min, max);
        if (command == "manifest create") _ = args.RequiredValue("output");
        if (command == "manifest verify") _ = args.RequiredValue("manifest");
        if (command == "manifest diff") { _ = args.RequiredValue("before"); _ = args.RequiredValue("after"); }
    }

    private static async Task WriteAsync(TextWriter stdout, bool json, string command, object data, string? human = null)
    {
        if (json) await stdout.WriteLineAsync(JsonSerializer.Serialize(new { schemaVersion = 1, command, data }, JsonDefaults.Options));
        else if (human is not null) await stdout.WriteLineAsync(human);
        else
        {
            await stdout.WriteLineAsync($"FileGuard · {command}");
            await stdout.WriteLineAsync(JsonSerializer.Serialize(data, JsonDefaults.Options));
        }
    }
    private static Task WriteErrorAsync(TextWriter stdout, bool json, string command, string code, string message) =>
        json ? stdout.WriteLineAsync(JsonSerializer.Serialize(new { schemaVersion = 1, command, error = new { code, message } }, JsonDefaults.Options)) : Task.CompletedTask;

    private static async Task<int> ServeAsync(Arguments args, GuardSettings settings, TextWriter stdout, TextWriter stderr, CancellationToken cancellationToken)
    {
        if (args.Flag("json")) throw new UsageException("serve is a long-running server command; JSON applies to finite CLI commands.");
        var urls = args.Value("urls") ?? "http://localhost:5187";
        if (!Uri.TryCreate(urls, UriKind.Absolute, out var uri) || !uri.IsLoopback || uri.Scheme != "http")
            throw new UsageException("v1 serve requires one loopback HTTP URL (for example http://localhost:5187). Remote listeners are disabled.");
        var webPath = FindWebBinary(args.Value("web-path"));
        var isDll = Path.GetExtension(webPath).Equals(".dll", StringComparison.OrdinalIgnoreCase);
        var start = new ProcessStartInfo(isDll ? "dotnet" : Path.GetFullPath(webPath))
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(webPath))!
        };
        if (isDll) start.ArgumentList.Add(Path.GetFullPath(webPath));
        if (args.Value("config") is { } config) { start.ArgumentList.Add("--config"); start.ArgumentList.Add(Path.GetFullPath(config)); }
        start.ArgumentList.Add("--data"); start.ArgumentList.Add(settings.DataDirectory);
        foreach (var root in settings.AllowedRoots) { start.ArgumentList.Add("--allow-root"); start.ArgumentList.Add(root); }
        if (settings.QuarantineDirectory is { } quarantine) { start.ArgumentList.Add("--quarantine"); start.ArgumentList.Add(Path.GetFullPath(quarantine)); }
        start.ArgumentList.Add("--concurrency"); start.ArgumentList.Add(settings.Concurrency.ToString(CultureInfo.InvariantCulture));
        start.ArgumentList.Add("--capacity"); start.ArgumentList.Add(settings.ChannelCapacity.ToString(CultureInfo.InvariantCulture));
        start.ArgumentList.Add("--bytes-per-second"); start.ArgumentList.Add(settings.BytesPerSecond.ToString(CultureInfo.InvariantCulture));
        start.ArgumentList.Add("--diagnostic-paths"); start.ArgumentList.Add(settings.DiagnosticPaths ? "true" : "false");
        start.ArgumentList.Add("--urls"); start.ArgumentList.Add(urls);
        using var process = Process.Start(start) ?? throw new GuardException("Could not start the Web server.");
        var outputPump = PumpAsync(process.StandardOutput, stdout);
        var errorPump = PumpAsync(process.StandardError, stderr);
        try { await process.WaitForExitAsync(cancellationToken); }
        catch (OperationCanceledException)
        {
            // Console Ctrl+C also reaches the server; allow ASP.NET to finish shutdown before enforcing exit.
            using var grace = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await process.WaitForExitAsync(grace.Token); }
            catch (OperationCanceledException) { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            await process.WaitForExitAsync(CancellationToken.None);
            await Task.WhenAll(outputPump, errorPump);
            throw;
        }
        await Task.WhenAll(outputPump, errorPump);
        return process.ExitCode;
    }

    private static string FindWebBinary(string? explicitPath)
    {
        if (explicitPath is not null)
            return File.Exists(explicitPath) ? Path.GetFullPath(explicitPath) : throw new UsageException("The --web-path file does not exist.");
        var directory = AppContext.BaseDirectory;
        var candidates = new List<string>
        {
            Path.Combine(directory, "FileGuard.Web.exe"), Path.Combine(directory, "FileGuard.Web.dll"),
            Path.GetFullPath(Path.Combine(directory, "..", "web", "FileGuard.Web.exe")),
            Path.GetFullPath(Path.Combine(directory, "..", "web", "FileGuard.Web.dll"))
        };
        for (var parent = new DirectoryInfo(directory); parent is not null; parent = parent.Parent)
        {
            candidates.Add(Path.Combine(parent.FullName, "src", "FileGuard.Web", "bin", "Debug", "net10.0", "FileGuard.Web.dll"));
            candidates.Add(Path.Combine(parent.FullName, "src", "FileGuard.Web", "bin", "Release", "net10.0", "FileGuard.Web.dll"));
        }
        return candidates.FirstOrDefault(File.Exists) ?? throw new UsageException("Web binary not found. Build the solution or supply --web-path <FileGuard.Web.dll>.");
    }
    private static async Task PumpAsync(StreamReader source, TextWriter target)
    {
        var buffer = new char[4096];
        int count;
        while ((count = await source.ReadAsync(buffer)) > 0) await target.WriteAsync(buffer.AsMemory(0, count));
    }
    private sealed class ProgressSink(TextWriter writer) : IProgress<ScanProgress>
    {
        private long last = Environment.TickCount64 - 1000;
        public void Report(ScanProgress value)
        {
            var now = Environment.TickCount64;
            if (now - Interlocked.Read(ref last) < 1000 && value.State is ScanState.Enumerating or ScanState.Hashing) return;
            Interlocked.Exchange(ref last, now);
            lock (writer) writer.WriteLine($"{value.State}: files={value.Files}, bytesRead={value.BytesRead}, errors={value.Errors}");
        }
    }
    private sealed class UsageException(string message) : Exception(message);

    private sealed class Arguments
    {
        private static readonly HashSet<string> Flags = ["json", "help", "hash-all", "confirm", "dry-run", "permanent", "diagnostic-paths"];
        private static readonly HashSet<string> Repeated = ["allow-root", "root", "include", "exclude", "extension", "keep-path"];
        private readonly Dictionary<string, List<string>> values = new(StringComparer.Ordinal);
        public List<string> Positionals { get; } = [];
        public bool Confirmed => Flag("confirm") && !Flag("dry-run");
        public int Offset => Int("offset", 0, 0, int.MaxValue);
        public int Limit => Int("limit", 50, 1, 10000);

        public static Arguments Parse(string[] tokens)
        {
            var result = new Arguments();
            var positionalOnly = false;
            for (var index = 0; index < tokens.Length; index++)
            {
                var token = tokens[index];
                if (positionalOnly) { result.Positionals.Add(token); continue; }
                if (token == "--") { positionalOnly = true; continue; }
                if (token is "-h" or "-?") token = "--help";
                if (!token.StartsWith("--", StringComparison.Ordinal))
                {
                    if (token.StartsWith('-')) throw new UsageException("Use long options such as --help.");
                    result.Positionals.Add(token); continue;
                }
                var split = token.IndexOf('=');
                var name = split < 0 ? token[2..] : token[2..split];
                if (name.Length == 0) throw new UsageException("Invalid empty option.");
                var value = split < 0 ? null : token[(split + 1)..];
                if (Flags.Contains(name))
                {
                    value ??= "true";
                    if (value is not ("true" or "false")) throw new UsageException($"--{name} requires true or false.");
                }
                else if (value is null)
                {
                    if (++index >= tokens.Length || tokens[index].StartsWith("--", StringComparison.Ordinal))
                        throw new UsageException($"--{name} requires a value.");
                    value = tokens[index];
                }
                if (string.IsNullOrWhiteSpace(value)) throw new UsageException($"--{name} requires a nonempty value.");
                if (!result.values.TryGetValue(name, out var list)) result.values[name] = list = [];
                if (list.Count > 0 && !Repeated.Contains(name)) throw new UsageException($"--{name} may only appear once.");
                list.Add(value);
            }
            return result;
        }
        public void Validate(string allowed, int min, int max)
        {
            var allowedSet = allowed.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
            foreach (var key in values.Keys) if (!allowedSet.Contains(key)) throw new UsageException($"Unknown option --{key} for this command.");
            if (Positionals.Count < min || Positionals.Count > max) throw new UsageException("Missing or extra command arguments. Run fileguard --help.");
        }
        public bool Flag(string name) => Value(name) == "true";
        public string? Value(string name) => values.TryGetValue(name, out var list) ? list.Last() : null;
        public string[] Many(string name) => values.TryGetValue(name, out var list) ? list.ToArray() : [];
        public string RequiredValue(string name) => Value(name) ?? throw new UsageException($"--{name} is required.");
        public string RequiredOperand(int index, string description) => Positionals.ElementAtOrDefault(index) ?? throw new UsageException($"{description} is required.");
        public IEnumerable<string> Operands(int skip) => Positionals.Skip(skip);
        public int Int(string name, int fallback, int min, int max)
        {
            if (Value(name) is not { } raw) return fallback;
            if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value < min || value > max)
                throw new UsageException($"--{name} must be an integer from {min} to {max}.");
            return value;
        }
        public long? OptionalLong(string name, long min)
        {
            if (Value(name) is not { } raw) return null;
            if (!long.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value < min)
                throw new UsageException($"--{name} must be an integer of at least {min}.");
            return value;
        }
        public DateTimeOffset? Date(string name)
        {
            if (Value(name) is not { } raw) return null;
            if (!DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var value))
                throw new UsageException($"--{name} must be an ISO-8601 date/time.");
            return value;
        }
        public T EnumValue<T>(string raw, string name) where T : struct, Enum =>
            Enum.TryParse<T>(raw, true, out var value) && Enum.IsDefined(value) ? value : throw new UsageException($"Invalid --{name} value.");
    }

    public const string Help = """
        FileGuard — 文件完整性、重复检测与可恢复隔离 (.NET 10)

        Usage: fileguard <command> [options]
        scan [root ...]                  Scan explicitly allowed roots; links are skipped
          --root PATH                    Additional root (repeatable)
          --include GLOB --exclude GLOB   Root-relative glob rules (repeatable)
          --extension .ext               Extension filter (repeatable)
          --min-size BYTES --max-size BYTES
          --modified-after ISO8601 --modified-before ISO8601
          --hash-all                     Hash every file (default: duplicate size candidates)
        duplicates <scan-id>             View complete SHA-256 duplicate groups
        scans list|show <scan-id>|files <scan-id> [--state Unreadable]
        manifest create <root> --output FILE [--dry-run]
        manifest verify <root> --manifest FILE
        manifest diff --before FILE --after FILE
        cleanup plan <scan-id> [--rule first|oldest|newest|preferred|explicit]
          --preferred-directory PATH --keep-path PATH (repeatable) --valid-hours 24
        cleanup list|show <plan-id>      Preview persisted plans
        cleanup apply <plan-id> [--confirm] [--dry-run]
        quarantine list|show <operation-id>
        quarantine restore <operation-id> [--confirm] [--dry-run]
        quarantine purge <operation-id> [--confirm --permanent] [--dry-run]
        quarantine recover [--confirm] [--dry-run]
        history [--offset 0 --limit 50]  Persistent operation and safety history
        serve [--urls http://localhost:5187] [--web-path FileGuard.Web.dll]

        Global: --config FILE --data DIRECTORY --allow-root PATH (repeatable)
          --quarantine DIRECTORY --concurrency 2 --capacity 64 --bytes-per-second 0
          --diagnostic-paths --json --help
        Precedence: built-in defaults < config JSON < CLI options.
        Explicit scan roots are allowed automatically only when no allowlist is configured.
        File mutations default to dry-run. --dry-run always overrides --confirm.
        Purge is permanent and requires BOTH --confirm and --permanent.
        No command waits for interactive input. Ctrl+C cancels and persists state.
        JSON stdout: one {schemaVersion:1, command, data|error} document; progress uses stderr.
        Exit: 0 success; 1 manifest differences; 2 arguments/config; 3 partial/failure; 130 cancelled.
        Web manages server files, not the browser's local disk. v1 Web is loopback only.
        File mutations require supported Windows identity/handle guarantees.

        Examples (use generated test data first):
          fileguard scan ./sample-data --data ./.fileguard --json
          fileguard duplicates SCAN_ID --data ./.fileguard --json
          fileguard cleanup plan SCAN_ID --data ./.fileguard --allow-root ./sample-data
          fileguard cleanup show PLAN_ID --data ./.fileguard
          fileguard cleanup apply PLAN_ID --confirm --data ./.fileguard --allow-root ./sample-data
          fileguard quarantine restore OPERATION_ID --confirm --data ./.fileguard --allow-root ./sample-data
          fileguard manifest create ./sample-data --output ./sample-manifest.json
          fileguard manifest verify ./sample-data --manifest ./sample-manifest.json --json
        """;
}
