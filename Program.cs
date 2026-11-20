namespace SecureFileManager;

internal static class Program
{
    private static int Main()
    {
        try
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Требуется Linux.");
            string data = Path.GetFullPath(Environment.GetEnvironmentVariable("SFM_DATA_DIR")
                ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "secure-file-manager"));
            const UnixFileMode privateDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            Directory.CreateDirectory(data, privateDirectory);
            using var disk = new LinuxFiles(data);
            if (File.GetUnixFileMode(data) != privateDirectory)
                throw new IOException("Каталог данных должен иметь права 0700.");
            using var instance = new FileStream(Path.Combine(data, ".instance.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite);
            instance.Lock(0, 1);
            disk.EnsureDirectory(FileCommands.Staging);

            var store = new Store(Path.Combine(data, "data.sqlite"));
            var terminal = Terminal.OpenConsole();
            var audit = new AuditService(store);
            var auth = new AuthService(store, audit, () => Thread.Sleep(1000));
            var files = new FileCommands(data, disk, store, auth, audit, terminal);
            files.Recover();
            new ConsoleApp(terminal, auth, audit, files.Execute).Run();
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Работа остановлена: " + ex.Message);
            return 1;
        }
    }
}
