using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace FileGuard.Core;

internal static class NativeFiles
{
    private const uint Read = 0x80000000, DeleteAccess = 0x10000, ReadAttributes = 0x80;
    private const uint OpenExisting = 3, OpenReparse = 0x00200000, BackupSemantics = 0x02000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInformation { public ulong Volume, Low, High; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation info);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, out uint info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, out FileIdInformation info, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint size, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, IntPtr buffer, uint size);
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    internal static extern int OpenLinux([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

    private static string Extended(string path) => "\\\\?\\" + Path.GetFullPath(path);
    public static SafeFileHandle OpenDirectory(string path) => Open(path, ReadAttributes, OpenReparse | BackupSemantics);
    public static SafeFileHandle OpenFile(string path, bool mutable) => Open(path, Read | (mutable ? DeleteAccess : 0), OpenReparse);
    private static SafeFileHandle Open(string path, uint access, uint flags)
    {
        var handle = CreateFileW(Extended(path), access, 1, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        var error = Marshal.GetLastPInvokeError();
        handle.Dispose();
        if (error is 2 or 3) throw new FileNotFoundException("文件或路径已不存在。");
        if (error == 5) throw new UnauthorizedAccessException("没有安全打开文件或目录所需的权限。");
        throw new IOException($"无法锁定文件或目录（OS {error}）。", new Win32Exception(error));
    }

    public static bool IsCaseSensitive(SafeFileHandle handle)
    {
        if (GetFileInformationByHandleEx(handle, 23, out uint flags, sizeof(uint))) return (flags & 1) != 0;
        // No reliable case semantics: mutation must fail closed.
        return true;
    }
    public static void ValidateHandle(SafeFileHandle handle, string expectedPath, bool directory)
    {
        if (!GetFileInformationByHandle(handle, out var info)) throw new IOException("不能核验文件身份。", new Win32Exception(Marshal.GetLastPInvokeError()));
        if ((info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 || ((info.Attributes & (uint)FileAttributes.Directory) != 0) != directory)
            throw new GuardException("文件类型或链接状态不符合安全要求。");
        var text = new StringBuilder(32768);
        var size = GetFinalPathNameByHandleW(handle, text, (uint)text.Capacity, 0);
        if (size == 0 || size >= text.Capacity) throw new GuardException("不能验证句柄最终路径。");
        var final = text.ToString();
        if (final.StartsWith("\\\\?\\", StringComparison.Ordinal)) final = final[4..];
        if (!string.Equals(Path.TrimEndingDirectorySeparator(final), Path.TrimEndingDirectorySeparator(Path.GetFullPath(expectedPath)), StringComparison.OrdinalIgnoreCase))
            throw new GuardException("文件句柄最终路径已变化。");
    }
    public static FileSnapshot Snapshot(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var info)) throw new IOException("不能读取文件身份。", new Win32Exception(Marshal.GetLastPInvokeError()));
        if (!GetFileInformationByHandleEx(handle, 18, out FileIdInformation id, 24)) throw new GuardException("文件系统不提供可靠的 128 位文件身份，拒绝依赖不完整身份。");
        var length = checked((long)(((ulong)info.SizeHigh << 32) | info.SizeLow));
        var ticks = ((long)info.Write.dwHighDateTime << 32) | (uint)info.Write.dwLowDateTime;
        return new(length, DateTime.FromFileTimeUtc(ticks), $"{id.Volume:x16}:{id.High:x16}{id.Low:x16}", info.Links,
            (info.Attributes & ((uint)FileAttributes.SparseFile | (uint)FileAttributes.Compressed)) != 0);
    }
    public static void Rename(SafeFileHandle handle, string destination)
    {
        // FILE_RENAME_INFO; ReplaceIfExists=false, RootDirectory=NULL, fully qualified target.
        var name = Encoding.Unicode.GetBytes(Extended(destination));
        var rootOffset = IntPtr.Size == 8 ? 8 : 4;
        var lengthOffset = rootOffset + IntPtr.Size;
        var nameOffset = lengthOffset + sizeof(uint);
        // Win32 normalizes this name before the native rename. Reserve a terminating WCHAR as well
        // as the counted name, so no uninitialized memory can be interpreted as a suffix.
        var size = nameOffset + name.Length + sizeof(char);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.Copy(new byte[size], 0, buffer, size);
            Marshal.WriteInt32(buffer, lengthOffset, name.Length);
            Marshal.Copy(name, 0, buffer + nameOffset, name.Length);
            if (!SetFileInformationByHandle(handle, 3, buffer, (uint)size)) throw new IOException("句柄重命名失败。", new Win32Exception(Marshal.GetLastPInvokeError()));
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    public static void Delete(SafeFileHandle handle)
    {
        var buffer = Marshal.AllocHGlobal(4);
        try
        {
            Marshal.WriteInt32(buffer, 1);
            if (!SetFileInformationByHandle(handle, 4, buffer, 4)) throw new IOException("句柄删除失败。", new Win32Exception(Marshal.GetLastPInvokeError()));
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
}
