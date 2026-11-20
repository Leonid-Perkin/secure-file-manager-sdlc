using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecureFileManager;

internal sealed class LinuxFiles : IDisposable
{
    private const int DirectoryFlag = 0x10000, NoFollow = 0x20000, CloseOnExec = 0x80000;
    private const int NonBlock = 0x800, Create = 0x40, Exclusive = 0x80, WriteOnly = 1;
    private const int Missing = 2, Exists = 17, NotDirectory = 20;
    private readonly SafeFileHandle root;

    [StructLayout(LayoutKind.Sequential)]
    private struct OpenHow { public ulong Flags, Mode, Resolve; }
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx { [FieldOffset(28)] public ushort Mode; }

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long OpenAt2(long number, int dir,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path, ref OpenHow how, nuint size);
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int OpenNative([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("libc", EntryPoint = "mkdirat", SetLastError = true)]
    private static extern int MkdirAt(int dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, uint mode);
    [DllImport("libc", EntryPoint = "renameat2", SetLastError = true)]
    private static extern int RenameAt(int oldDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string oldName,
        int newDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string newName, uint flags);
    [DllImport("libc", EntryPoint = "unlinkat", SetLastError = true)]
    private static extern int UnlinkAt(int dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, int flags);
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Stat(int dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, int flags, uint mask, out Statx result);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int SyncNative(int fd);

    public LinuxFiles(string trustedRoot)
    {
        if (!OperatingSystem.IsLinux() || RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
            throw new PlatformNotSupportedException("Требуется Linux x64/arm64 с openat2 (ядро 5.6 или новее).");
        root = Handle(OpenNative(trustedRoot, DirectoryFlag | NoFollow | CloseOnExec));
        try { using var probe = Open(root, ".", DirectoryFlag); }
        catch { root.Dispose(); throw; }
    }

    public static string Owner(long id) => "files/" + id.ToString(CultureInfo.InvariantCulture);
    private static int Fd(SafeFileHandle handle) => (int)handle.DangerousGetHandle();
    private static string Descriptor(SafeFileHandle handle) => $"/proc/self/fd/{Fd(handle)}";
    private static SafeFileHandle Handle(long fd) => fd < 0 ? throw Error() : new SafeFileHandle((nint)fd, true);
    private static IOException Error() => new LinuxIOException(Marshal.GetLastPInvokeError());
    private sealed class LinuxIOException(int code) : IOException(code switch
    {
        40 => "Символические ссылки запрещены.",
        18 => "Путь пересекает границу каталога или точки монтирования.",
        11 => "Путь изменился во время операции. Повторите попытку.",
        38 => "Ядро не поддерживает openat2.",
        _ => new Win32Exception(code).Message
    }) { public int Code { get; } = code; }

    private static SafeFileHandle Open(SafeFileHandle dir, string path, int flags, ulong mode = 0)
    {
        var how = new OpenHow { Flags = (ulong)(flags | CloseOnExec), Mode = mode, Resolve = 0x0f };
        return Handle(OpenAt2(437, Fd(dir), path, ref how, 24));
    }

    public static string Normalize(string path)
    {
        if (Path.IsPathRooted(path) || path.Contains('\\') || path.Any(char.IsControl))
            throw new UnauthorizedAccessException("Допускаются только относительные пути без управляющих символов.");
        var parts = new List<string>();
        foreach (var part in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".") continue;
            if (part == "..") throw new UnauthorizedAccessException("Путь вне личного каталога: компонент .. запрещён.");
            parts.Add(part);
        }
        return parts.Count == 0 ? "." : string.Join('/', parts);
    }

    public SafeFileHandle DirectoryAt(string path) => Open(root, path, DirectoryFlag);

    public void EnsureDirectory(string path)
    {
        string current = "";
        foreach (string part in path.Split('/'))
        {
            if (part == ".") continue;
            string next = current.Length == 0 ? part : current + "/" + part;
            using var parent = DirectoryAt(current.Length == 0 ? "." : current);
            if (MkdirAt(Fd(parent), part, 448) < 0 && Marshal.GetLastPInvokeError() != Exists)
                throw Error();
            using var verify = DirectoryAt(next);
            Sync(parent);
            current = next;
        }
    }

    private (SafeFileHandle Parent, string Name) Parent(string path)
    {
        int slash = path.LastIndexOf('/');
        return slash < 0 ? (DirectoryAt("."), path) : (DirectoryAt(path[..slash]), path[(slash + 1)..]);
    }

    public static void Sync(SafeFileHandle dir)
    {
        if (SyncNative(Fd(dir)) < 0) throw Error();
    }

    public FileStream Read(string path)
    {
        var handle = Open(root, path, NonBlock);
        try
        {
            if (Stat(Fd(handle), "", 0x1000, 1, out var stat) < 0) throw Error();
            if ((stat.Mode & 0xf000) != 0x8000) throw new IOException("Поддерживаются только обычные файлы.");
            return new FileStream(handle, FileAccess.Read);
        }
        catch { handle.Dispose(); throw; }
    }

    public long? Size(string path)
    {
        try { using var file = Read(path); return file.Length; }
        catch (LinuxIOException ex) when (ex.Code is Missing or NotDirectory) { return null; }
    }

    public bool IsDirectory(string path)
    {
        try { using var dir = DirectoryAt(path); return true; }
        catch (LinuxIOException ex) when (ex.Code is Missing or NotDirectory) { return false; }
    }

    public string[] Names(string path)
    {
        using var dir = DirectoryAt(path);
        return Directory.EnumerateFileSystemEntries(Descriptor(dir)).Select(Path.GetFileName).Select(n => n!).Order().ToArray();
    }

    public FileStream NewFile(string path)
    {
        var handle = Open(root, path, WriteOnly | Create | Exclusive, 384);
        try { return new FileStream(handle, FileAccess.Write); }
        catch { handle.Dispose(); throw; }
    }

    public void Publish(string source, string target, bool replace)
    {
        var (sourceParent, sourceName) = Parent(source);
        using var from = sourceParent;
        var (targetParent, targetName) = Parent(target);
        using var to = targetParent;
        if (RenameAt(Fd(from), sourceName, Fd(to), targetName, replace ? 0u : 1u) < 0) throw Error();
        Sync(to);
        Sync(from);
    }

    public void DeleteFile(string path)
    {
        var (parent, name) = Parent(path);
        using (parent)
        {
            if (UnlinkAt(Fd(parent), name, 0) < 0) throw Error();
            Sync(parent);
        }
    }

    public void Dispose() => root.Dispose();
}
