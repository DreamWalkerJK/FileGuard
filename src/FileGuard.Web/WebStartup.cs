using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using FileGuard.Core;

namespace FileGuard.Web;

public sealed record WebStartup(string Urls, Dictionary<string, string?> Configuration)
{
    public static WebStartup Parse(string[] args)
    {
        string? config = Environment.GetEnvironmentVariable("FILEGUARD_CONFIG"), data = null, quarantine = null;
        int? concurrency = null, capacity = null;
        long? bytesPerSecond = null;
        bool? diagnosticPaths = null;
        var roots = new List<string>();
        var urls = "http://localhost:5187";
        for (var index = 0; index < args.Length; index++)
        {
            var pair = args[index].Split('=', 2);
            var key = pair[0];
            if (pair.Length == 1 && ++index >= args.Length) throw new GuardException("启动参数缺少值。");
            var value = pair.Length == 2 ? pair[1] : args[index];
            switch (key)
            {
                case "--config": config = value; break;
                case "--data": data = value; break;
                case "--quarantine": quarantine = value; break;
                case "--allow-root": roots.Add(value); break;
                case "--urls": urls = value; break;
                case "--concurrency": concurrency = int.Parse(value); break;
                case "--capacity": capacity = int.Parse(value); break;
                case "--bytes-per-second": bytesPerSecond = long.Parse(value); break;
                case "--diagnostic-paths": diagnosticPaths = bool.Parse(value); break;
                case "--applicationName": case "--contentRoot": case "--environment": break; // ASP.NET host bootstrap options, applied by its host builder.
                default: throw new GuardException("无法识别的 Web 启动参数。");
            }
        }
        if (!Uri.TryCreate(urls, UriKind.Absolute, out var uri) || uri.Scheme != "http" || !WebBoundary.IsLoopbackHost(uri.Host) || uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.UserInfo))
            throw new GuardException("首版 Web 仅支持单个 http://localhost、127.0.0.1 或 [::1] 地址。远程访问未启用。");
        var settings = config is null ? new GuardSettings() : JsonSerializer.Deserialize<GuardSettings>(File.ReadAllText(config), JsonDefaults.Options) ?? throw new GuardException("配置格式无效。");
        settings = settings with { DataDirectory = data ?? settings.DataDirectory, QuarantineDirectory = quarantine ?? settings.QuarantineDirectory, AllowedRoots = roots.Count > 0 ? roots.ToArray() : settings.AllowedRoots,
            Concurrency = concurrency ?? settings.Concurrency, ChannelCapacity = capacity ?? settings.ChannelCapacity, BytesPerSecond = bytesPerSecond ?? settings.BytesPerSecond, DiagnosticPaths = diagnosticPaths ?? settings.DiagnosticPaths };
        return new(urls, new() { ["FileGuardSettings"] = JsonSerializer.Serialize(settings, JsonDefaults.Options) });
    }
    public static GuardSettings LoadSettings(IConfiguration configuration) =>
        JsonSerializer.Deserialize<GuardSettings>(configuration["FileGuardSettings"]!, JsonDefaults.Options) ?? throw new GuardException("配置无效。");
}

public static class WebBoundary
{
    public static bool IsLoopbackHost(string host) => host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host is "127.0.0.1" or "[::1]" or "::1";
    public static bool IsLocalRequest(HttpContext context) =>
        IsLoopbackHost(context.Request.Host.Host) && (context.Connection.RemoteIpAddress is null || IPAddress.IsLoopback(context.Connection.RemoteIpAddress));
    public static bool IsSameOrigin(HttpContext context)
    {
        var origin = context.Request.Headers.Origin.ToString();
        return Uri.TryCreate(origin, UriKind.Absolute, out var uri) &&
            string.Equals(uri.GetLeftPart(UriPartial.Authority), $"{context.Request.Scheme}://{context.Request.Host}", StringComparison.OrdinalIgnoreCase) &&
            uri.AbsolutePath == "/" && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment);
    }
}

public sealed class StartupCredential
{
    private readonly byte[] _digest;
    private readonly string _path;
    private int _consumed;
    public string InstanceId { get; } = Guid.NewGuid().ToString("N");
    public StartupCredential(GuardSettings settings)
    {
        var directory = Path.Combine(Path.GetFullPath(settings.DataDirectory), "web-private");
        Directory.CreateDirectory(directory);
        if (OperatingSystem.IsWindows())
        {
            var identity = WindowsIdentity.GetCurrent().User ?? throw new GuardException("无法识别当前 Windows 用户。");
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(directory).SetAccessControl(security);
        }
        else File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        _path = Path.Combine(directory, "startup-token.txt");
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        _digest = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        File.WriteAllText(_path, token, new UTF8Encoding(false));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(_path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    public bool Consume(string token)
    {
        if (token.Length != 64 || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(token)), _digest)) return false;
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0) return false;
        File.Delete(_path); return true;
    }
}
