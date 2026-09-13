using System.Diagnostics;
using System.Text.Json;
using FileGuard.Core;

var scenario = args.FirstOrDefault() ?? "small";
if (scenario is not ("small" or "large")) throw new ArgumentException("Scenario must be small or large.");
var repository = Directory.GetCurrentDirectory();
if (!File.Exists(Path.Combine(repository, "FileGuard.slnx"))) throw new InvalidOperationException("Run from the repository root.");
var count = scenario == "small" ? 10000 : 8;
var size = scenario == "small" ? 1024L : 64L * 1024 * 1024;
var concurrency = args.Length > 1 ? int.Parse(args[1]) : 2;
var root = Path.Combine(repository, ".test-data", "benchmarks", scenario + "-" + Guid.NewGuid().ToString("N"));
var files = Path.Combine(root, "files");
Directory.CreateDirectory(files);
var buffer = new byte[65536];
for (var index = 0; index < count; index++)
{
    new Random(index % (scenario == "small" ? 100 : 4)).NextBytes(buffer);
    await using var stream = new FileStream(Path.Combine(files, $"file-{index:D6}.bin"), FileMode.CreateNew, FileAccess.Write, FileShare.None, buffer.Length);
    for (long written = 0; written < size; written += buffer.Length)
        await stream.WriteAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, size - written)));
}
var settings = new GuardSettings { DataDirectory = Path.Combine(root, "state"), AllowedRoots = [files], Concurrency = concurrency };
var store = new FileGuardStore(settings.DataDirectory);
store.Initialize();
var scanner = new Scanner(store, settings);
using var process = Process.GetCurrentProcess();
var cpuStart = process.TotalProcessorTime;
var clock = Stopwatch.StartNew();
var scan = await scanner.ScanAsync(new ScanOptions { Roots = [files], Concurrency = concurrency, ChannelCapacity = 64 });
var groups = scanner.GetDuplicates(scan.Id);
clock.Stop();
process.Refresh();
var cpu = (process.TotalProcessorTime - cpuStart).TotalSeconds;
var report = new
{
    schemaVersion = 1,
    scenario,
    fileCount = count,
    totalBytes = count * size,
    storageMedium = Environment.GetEnvironmentVariable("FILEGUARD_BENCH_STORAGE") ?? "Not supplied; record physical storage separately",
    concurrency,
    channelCapacity = 64,
    elapsedSeconds = Math.Round(clock.Elapsed.TotalSeconds, 3),
    peakWorkingSetBytes = process.PeakWorkingSet64,
    cpuSeconds = Math.Round(cpu, 3),
    cpuPercentOfOneCore = Math.Round(cpu / clock.Elapsed.TotalSeconds * 100, 2),
    logicalProcessorCount = Environment.ProcessorCount,
    scan.ErrorCount,
    scan.CandidateCount,
    scan.HashCount,
    duplicateGroups = groups.Count,
    state = scan.State.ToString(),
    runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
    operatingSystem = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
    notes = "Generated data; recently written cache; baseline streaming buffers, no ArrayPool; peak is process lifetime, includes generator. Elapsed includes size filtering, full SHA-256, SQLite indexing and duplicate grouping. Physical reclaim is an estimate."
};
var json = JsonSerializer.Serialize(report, JsonDefaults.Options);
var reports = Path.Combine(repository, "artifacts", "benchmarks");
Directory.CreateDirectory(reports);
await File.WriteAllTextAsync(Path.Combine(reports, scenario + ".json"), json + "\n");
Console.WriteLine(json);
return scan.State == ScanState.Completed ? 0 : 3;
