using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileGuard.Core;

public static class PathSafety
{
    public static StringComparer Comparer => OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
    public static bool IsWithin(string path, string root)
    {
        path = Path.GetFullPath(path);
        root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        // Exact spelling also preserves Windows case-sensitive directory boundaries. Accepting an
        // alternate root spelling would require resolving each component under its actual parent.
        var comparison = StringComparison.Ordinal;
        return path.Equals(root, comparison) || path.StartsWith(Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar, comparison);
    }

    public static void ValidateRoot(string root)
    {
        if (!Directory.Exists(root)) throw new GuardException("根目录不存在或不可访问。");
        Validate(root, root);
    }

    public static void Validate(string path, string root)
    {
        if (!IsWithin(path, root)) throw new GuardException("路径越出允许根目录。");
        var full = Path.GetFullPath(path);
        if (OperatingSystem.IsWindows())
        {
            if (full.StartsWith("\\\\", StringComparison.Ordinal)) throw new GuardException("首版不支持 UNC 或设备路径；请使用本地卷路径。");
            foreach (var segment in full[Path.GetPathRoot(full)!.Length..].Split(Path.DirectorySeparatorChar))
                if (segment.Contains(':') || segment.EndsWith('.') || segment.EndsWith(' ')) throw new GuardException("拒绝备用数据流或含歧义的 Windows 路径。");
        }
        for (var current = full; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
        {
            FileAttributes attributes;
            try { attributes = File.GetAttributes(current); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            if ((attributes & FileAttributes.ReparsePoint) != 0) throw new GuardException("路径含符号链接、junction 或其他 reparse point。");
        }
    }

    public static string ResolveManifestPath(string root, string relative)
    {
        if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative) || relative.Contains('\\') || relative.Contains(':') || relative.Contains('\0'))
            throw new GuardException("清单只允许使用 / 分隔的相对文件路径。");
        if (relative.Split('/').Any(x => x is "" or "." or "..")) throw new GuardException("清单路径包含空段、. 或 ..。");
        var path = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        Validate(path, root);
        return path;
    }

    public static bool IsCaseSensitiveDirectory(string directory)
    {
        if (!OperatingSystem.IsWindows()) return true;
        using var handle = NativeFiles.OpenDirectory(directory);
        return NativeFiles.IsCaseSensitive(handle);
    }
}

internal sealed class DirectoryGuards : IDisposable
{
    private readonly List<SafeFileHandle> handles = [];
    public DirectoryGuards(string directory, bool mutation)
    {
        try
        {
            var ancestors = new Stack<string>();
            for (var current = Path.GetFullPath(directory); !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current)) ancestors.Push(current);
            while (ancestors.TryPop(out var path))
            {
                var handle = NativeFiles.OpenDirectory(path);
                handles.Add(handle);
                NativeFiles.ValidateHandle(handle, path, directory: true);
                if (mutation && NativeFiles.IsCaseSensitive(handle)) throw new GuardException("首版在 Windows 大小写敏感目录中仅支持读取，拒绝清理。");
            }
        }
        catch { Dispose(); throw; }
    }
    public void Dispose() { for (var i = handles.Count - 1; i >= 0; --i) handles[i].Dispose(); handles.Clear(); }
}

public sealed record FileSnapshot(long Size, DateTimeOffset ModifiedUtc, string? Identity, uint? LinkCount, bool SparseOrCompressed);

/// <summary>Windows: keeps ancestors and leaf open with write/delete sharing denied through the final operation.</summary>
public sealed class SafeFile : IDisposable
{
    private readonly DirectoryGuards? guards;
    private readonly string path;
    private readonly bool mutation;
    public FileStream Stream { get; }
    public static SafeFile OpenRead(string path, string root) => new(path, root, false);
    internal static SafeFile OpenMutable(string path, string root) => new(path, root, true);
    private SafeFile(string path, string root, bool mutation)
    {
        PathSafety.Validate(path, root);
        this.path = Path.GetFullPath(path);
        this.mutation = mutation;
        if (mutation && !OperatingSystem.IsWindows()) throw new GuardException("当前平台没有经过验证的句柄修改后端；仅支持扫描和清单读取。");
        try
        {
            if (OperatingSystem.IsWindows())
            {
                guards = new DirectoryGuards(Path.GetDirectoryName(this.path)!, mutation);
                var handle = NativeFiles.OpenFile(this.path, mutation);
                try
                {
                    NativeFiles.ValidateHandle(handle, this.path, directory: false);
                    Stream = new FileStream(handle, FileAccess.Read, 131072, isAsync: false);
                }
                catch { handle.Dispose(); throw; }
            }
            else if (OperatingSystem.IsLinux())
            {
                var fd = NativeFiles.OpenLinux(this.path, 0x20000 | 0x80000); // O_NOFOLLOW | O_CLOEXEC
                if (fd < 0) throw new IOException("无法安全打开文件。", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
                var handle = new SafeFileHandle(fd, ownsHandle: true);
                try
                {
                    var target = File.ResolveLinkTarget($"/proc/self/fd/{fd}", true)?.FullName;
                    if (target is null || !PathSafety.IsWithin(target, root)) throw new GuardException("最终文件目标越界或不能验证。");
                    Stream = new FileStream(handle, FileAccess.Read, 131072, isAsync: false);
                }
                catch { handle.Dispose(); throw; }
            }
            else throw new GuardException("当前平台缺少安全读取后端。");
        }
        catch { guards?.Dispose(); throw; }
    }
    public FileSnapshot Snapshot()
    {
        if (OperatingSystem.IsWindows()) return NativeFiles.Snapshot(Stream.SafeFileHandle);
        var info = new FileInfo(path);
        info.Refresh();
        return new(Stream.Length, info.LastWriteTimeUtc, null, null, true);
    }
    internal void RenameTo(string destination)
    {
        if (!mutation) throw new InvalidOperationException("A mutable file handle is required.");
        NativeFiles.Rename(Stream.SafeFileHandle, destination);
        NativeFiles.ValidateHandle(Stream.SafeFileHandle, destination, directory: false);
    }
    internal void Delete()
    {
        if (!mutation) throw new InvalidOperationException("A mutable file handle is required.");
        NativeFiles.Delete(Stream.SafeFileHandle);
    }
    public void Dispose() { Stream.Dispose(); guards?.Dispose(); }
}
