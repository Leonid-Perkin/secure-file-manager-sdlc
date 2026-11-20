using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Serialization;
using Microsoft.Data.Sqlite;

namespace SecureFileManager;

internal record User(long Id, string Name, bool Admin);
internal record FileIntent(string Id, long Owner, string Action, string Path);
internal record FileState(string Path, long Size, bool Deleted);

public sealed class Note
{
    public string Title { get; set; } = "";
    public string Text { get; set; } = "";
}

internal static class Program
{
    private static Store db = null!;
    private static User? current;
    private static string data = null!;
    private static LinuxFiles disk = null!;
    private const string Staging = ".sfm-stage";
    private sealed class StorageFailure(Exception inner) : IOException("Не удалось согласовать изменения; перезапустите приложение для восстановления.", inner);

    private static void Main()
    {
        try
        {
            data = Path.GetFullPath(Environment.GetEnvironmentVariable("SFM_DATA_DIR")
                ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "secure-file-manager"));
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Требуется Linux.");
            Directory.CreateDirectory(data, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            using var diskLifetime = disk = new LinuxFiles(data);
            if (File.GetUnixFileMode(data) != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute))
                throw new IOException("Каталог данных должен иметь права 0700.");
            using var instance = new FileStream(Path.Combine(data, ".instance.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite);
            instance.Lock(0, 1);
            disk.EnsureDirectory(Staging);
            db = new Store(Path.Combine(data, "data.sqlite"));
            Recover();
            if (!db.HasUsers())
            {
                Console.WriteLine("Первый запуск: создайте администратора.");
                long setup = db.BeginCommand(null, "init_admin");
                bool ready = false;
                try { Register(true); ready = true; }
                finally { db.FinishCommand(setup, ready); }
            }
            Console.WriteLine("Команды: help — справка, exit — выход.");
            while (true)
            {
                Console.Write(current is null ? "гость> " : $"{current.Name}> ");
                var line = Console.ReadLine();
                string cmd = line is null ? "exit" : line.Trim().ToLowerInvariant();
                string commandName = KnownCommands.Contains(cmd) ? cmd : "unknown";
                long attempt = db.BeginCommand(current?.Id, commandName);
                bool succeeded = false;
                try
                {
                    if (cmd is "exit" or "0")
                    {
                        db.Audit(current?.Id, "exit", null, true);
                        succeeded = true;
                        break;
                    }
                    if (cmd is "help" or "menu" or "?")
                    {
                        Help();
                        db.Audit(current?.Id, "help", null, true);
                        succeeded = true;
                        continue;
                    }
                    switch (cmd)
                    {
                        case "1": case "register": Register(false); break;
                        case "2": case "login": Login(); break;
                        case "3": case "logout":
                            RequireUser(); db.Audit(current!.Id, "logout", null, true); current = null; break;
                        case "4": case "drives": Run("drives", null, Drives); break;
                        case "5": case "list": FileAction("list", p => List(p)); break;
                        case "6": case "read": FileAction("read", p => Read(p)); break;
                        case "7": case "write": FileAction("write", p => Write(p)); break;
                        case "8": case "delete": FileAction("delete", p => Delete(p)); break;
                        case "9": case "mkdir": FileAction("mkdir", MakeDirectory); break;
                        case "10": case "zip": Zip(); break;
                        case "11": case "unzip": Unzip(); break;
                        case "12": case "users": Users(); break;
                        case "13": case "block": SetBlocked(true); break;
                        case "14": case "unblock": SetBlocked(false); break;
                        case "15": case "audit": Audit(); break;
                        case "16": case "save-note": FileAction("save-note", SaveNote); break;
                        case "17": case "read-note": FileAction("read-note", ReadNote); break;
                        default: db.Audit(current?.Id, "unknown_command", null, false); Console.WriteLine("Неизвестная команда. Введите help."); continue;
                    }
                    succeeded = true;
                }
                catch (Exception ex) when (ex is not (OutOfMemoryException or StorageFailure or SqliteException))
                {
                    Console.WriteLine("Ошибка: " + ex.Message);
                }
                finally
                {
                    db.FinishCommand(attempt, succeeded);
                }
            }
        }
        catch (Exception ex) { Console.Error.WriteLine("Работа остановлена: " + ex.Message); Environment.ExitCode = 1; }
    }

    private static readonly HashSet<string> KnownCommands = new(StringComparer.Ordinal)
    {
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17",
        "exit", "help", "menu", "?", "register", "login", "logout", "drives", "list", "read", "write",
        "delete", "mkdir", "zip", "unzip", "users", "block", "unblock", "audit", "save-note", "read-note"
    };

    private static void Help() => Console.WriteLine("""
        1 register  регистрация       2 login   вход          3 logout выход
        4 drives    накопители        5 list    каталог       6 read   чтение
        7 write     запись файла      8 delete  удалить файл  9 mkdir  создать каталог
        10 zip      создать ZIP       11 unzip  извлечь ZIP
        12 users    пользователи      13 block  блокировка    14 unblock разблокировка
        15 audit    журнал            0 exit    выход
        16 save-note сериализовать заметку в JSON/XML
        17 read-note десериализовать заметку из JSON/XML
        Пути вводятся относительно личного каталога. Для корня укажите точку.
        """);

    private static string Input(string prompt)
    {
        Console.Write(prompt);
        return Console.ReadLine() ?? throw new EndOfStreamException("Ввод завершён.");
    }

    private static string Password()
    {
        Console.Write("Пароль: ");
        if (Console.IsInputRedirected) return Console.ReadLine() ?? throw new EndOfStreamException();
        var s = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); return s.ToString(); }
            if (key.Key == ConsoleKey.Backspace && s.Length > 0) s.Length--;
            else if (!char.IsControl(key.KeyChar) && s.Length < 1024) s.Append(key.KeyChar);
        }
    }

    private static void Register(bool admin)
    {
        if (current is not null) { db.Audit(current.Id, "register_denied", null, false); throw new InvalidOperationException("Сначала выйдите из учётной записи."); }
        var name = Input("Логин (3–32 латинские буквы, цифры, _): ").Trim();
        var pass = Password();
        try
        {
            if (!Regex.IsMatch(name, @"\A[a-zA-Z0-9_]{3,32}\z")) throw new ArgumentException("Недопустимый логин.");
            if (pass.Length < 12 || pass.Length > 1024) throw new ArgumentException("Пароль должен содержать от 12 до 1024 символов.");
            long id = db.Register(name, pass, admin);
            db.Audit(id, admin ? "init_admin" : "register", null, true);
            Console.WriteLine("Учётная запись создана.");
        }
        catch { db.Audit(null, "register", name, false); throw; }
    }

    private static void Login()
    {
        if (current is not null) { db.Audit(current.Id, "login_denied", null, false); throw new InvalidOperationException("Сначала выйдите из учётной записи."); }
        var name = Input("Логин: ").Trim();
        var pass = Password();
        current = db.Authenticate(name, pass);
        db.Audit(current?.Id, "login", name, current is not null);
        if (current is null) { Thread.Sleep(1000); throw new UnauthorizedAccessException("Неверный логин, пароль или учётная запись заблокирована."); }
        Console.WriteLine("Вход выполнен.");
    }

    private static void RequireUser()
    {
        if (current is null) { db.Audit(null, "access_denied", null, false); throw new UnauthorizedAccessException("Необходим вход."); }
        if (!db.IsActive(current.Id)) { db.Audit(current.Id, "session_blocked", null, false); current = null; throw new UnauthorizedAccessException("Учётная запись заблокирована."); }
    }
    private static void RequireAdmin()
    {
        RequireUser();
        if (!current!.Admin)
        {
            db.Audit(current.Id, "admin_access_denied", null, false);
            throw new UnauthorizedAccessException("Требуются права администратора.");
        }
    }
    private static string Root()
    {
        RequireUser();
        string root = LinuxFiles.Owner(current!.Id);
        disk.EnsureDirectory(root);
        return root;
    }
    private static string Resolve(string relative)
    {
        string path = LinuxFiles.Normalize(relative);
        return path == "." ? Root() : Root() + "/" + path;
    }
    private static void Run(string action, string? path, Action work)
    {
        RequireUser();
        try { work(); }
        catch (Exception e) when (e is not StorageFailure) { db.Audit(current!.Id, action, path, false); throw; }
        if (action is "mkdir" or "delete" or "zip" or "unzip") return;
        try { db.Audit(current!.Id, action, path, true); }
        catch (Exception e) { throw new StorageFailure(e); }
    }
    private static void FileAction(string action, Action<string> work)
    {
        RequireUser();
        string path = Input("Путь: ");
        Run(action, path, () => work(Resolve(path)));
    }
    private static void Drives()
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            try { Console.WriteLine(d.IsReady ? $"{d.Name} {d.DriveType} {d.DriveFormat}: всего {d.TotalSize}, доступно {d.AvailableFreeSpace} байт" : $"{d.Name}: не готов"); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Console.WriteLine($"{d.Name}: {e.Message}"); }
        }
    }
    private static void List(string path)
    {
        foreach (var item in disk.Names(path))
        {
            try { Console.WriteLine((disk.IsDirectory(path + "/" + item) ? "[каталог] " : "[файл] ") + SafeDisplay(item)); }
            catch (IOException) { Console.WriteLine("[недоступно] " + SafeDisplay(item)); }
        }
    }
    private static string SafeDisplay(string text) => string.Concat(text.Select(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t') ? '�' : c));
    private static string ReadText(string path)
    {
        using var stream = disk.Read(path);
        var buffer = new byte[1_048_577];
        int count = stream.ReadAtLeast(buffer, buffer.Length, false);
        if (count == buffer.Length) throw new IOException("Файл превышает 1 МиБ.");
        return Encoding.UTF8.GetString(buffer, 0, count).TrimStart('\uFEFF');
    }
    private static void Read(string path) => Console.WriteLine(SafeDisplay(ReadText(path)));
    private static void Write(string path)
    {
        Console.WriteLine("Введите текст, отдельная строка .end завершает ввод:");
        var text = new StringBuilder();
        while (true)
        {
            string line = Console.ReadLine() ?? throw new EndOfStreamException("Ввод прерван; файл не изменён.");
            if (line == ".end") break;
            text.AppendLine(line);
            if (text.Length > 1_048_576) throw new IOException("Ограничение: 1 МиБ.");
        }
        string content = text.ToString();
        SaveContent(path, content);
    }
    private static void SaveContent(string path, string content)
    {
        if (Encoding.UTF8.GetByteCount(content) > 1_048_576) throw new IOException("Ограничение: 1 МиБ.");
        switch (Path.GetExtension(path).ToLowerInvariant())
        {
            case ".json": using (JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 64 })) { } break;
            case ".xml":
                    using (var reader = XmlReader.Create(new StringReader(content), SafeXmlSettings()))
                    while (reader.Read()) { }
                break;
        }
        bool existed = disk.Size(path) != null;
        Mutate(existed ? "modify" : "create", path, stage =>
        {
            using var stream = disk.NewFile(stage);
            stream.Write(Encoding.UTF8.GetBytes(content));
            stream.Flush(flushToDisk: true);
        }, stage => disk.Publish(stage, path, replace: existed));
        Console.WriteLine(existed ? "Файл изменён." : "Файл создан.");
    }
    private static XmlReaderSettings SafeXmlSettings() => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = 1_048_576
    };
    private static readonly JsonSerializerOptions NoteJsonOptions = new()
    {
        MaxDepth = 16,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true
    };
    private static void ValidateNote(Note? note)
    {
        if (note is null || string.IsNullOrWhiteSpace(note.Title) || note.Title.Length > 200 ||
            note.Text is null || note.Text.Length > 100_000)
            throw new InvalidDataException("Заголовок заметки обязателен (до 200 символов), текст — до 100000 символов.");
    }
    private static void SaveNote(string path)
    {
        string extension = Path.GetExtension(path).ToLowerInvariant();
        if (extension is not ".json" and not ".xml")
            throw new InvalidDataException("Для заметки используйте расширение .json или .xml.");
        var note = new Note { Title = Input("Заголовок: "), Text = Input("Текст (одна строка): ") };
        ValidateNote(note);
        string content;
        if (extension == ".json") content = JsonSerializer.Serialize(note, NoteJsonOptions);
        else
        {
            using var output = new StringWriter();
            using (var writer = XmlWriter.Create(output, new XmlWriterSettings { OmitXmlDeclaration = true, Indent = true }))
                new XmlSerializer(typeof(Note)).Serialize(writer, note);
            content = output.ToString();
        }
        SaveContent(path, content);
    }
    private static void ReadNote(string path)
    {
        string content = ReadText(path);
        Note? note;
        switch (Path.GetExtension(path).ToLowerInvariant())
        {
            case ".json":
                note = JsonSerializer.Deserialize<Note>(content, NoteJsonOptions);
                break;
            case ".xml":
                using (var reader = XmlReader.Create(new StringReader(content), SafeXmlSettings()))
                {
                    var serializer = new XmlSerializer(typeof(Note));
                    serializer.UnknownNode += (_, _) => throw new InvalidDataException("Неизвестный элемент XML заметки.");
                    serializer.UnknownAttribute += (_, _) => throw new InvalidDataException("Неизвестный атрибут XML заметки.");
                    note = serializer.Deserialize(reader) as Note;
                    while (reader.Read()) { }
                }
                break;
            default: throw new InvalidDataException("Для заметки используйте расширение .json или .xml.");
        }
        ValidateNote(note);
        Console.WriteLine(SafeDisplay($"Заголовок: {note!.Title}\nТекст: {note.Text}"));
    }
    private static void Delete(string path)
    {
        if (disk.Size(path) is null) throw new FileNotFoundException("Файл не найден.");
        Mutate("delete", path, _ => { }, _ => disk.DeleteFile(path));
    }
    private static void MakeDirectory(string path)
    {
        if (path == Root() || disk.IsDirectory(path))
        {
            db.Audit(current!.Id, "mkdir", Path.GetRelativePath(Root(), path), true);
            return;
        }
        Mutate("mkdir", path, _ => { }, _ => disk.EnsureDirectory(path));
    }
    private static void Zip()
    {
        RequireUser();
        string source = Input("Файл или каталог: "), target = Input("Новый ZIP: ");
        Run("zip", source + " -> " + target, () =>
        {
            string src = Resolve(source), dst = Resolve(target);
            if (src == Root() || dst == src || dst.StartsWith(src + "/", StringComparison.Ordinal))
                throw new IOException("Архив не может находиться внутри исходного каталога; корень архивировать нельзя.");
            if (disk.IsDirectory(dst) || disk.Size(dst) != null) throw new IOException("Файл назначения уже существует.");
            Mutate("zip", dst, stage =>
            {
                using var fs = disk.NewFile(stage);
                using (var zip = new ZipArchive(fs, ZipArchiveMode.Create, true))
                {
                    if (disk.IsDirectory(src)) AddDirectory(zip, src, src, 0);
                    else AddEntry(zip, src, Path.GetFileName(src));
                }
                fs.Flush(flushToDisk: true);
            }, stage => disk.Publish(stage, dst, replace: false));
        });
    }
    private static void AddEntry(ZipArchive zip, string path, string name)
    {
        using var input = disk.Read(path);
        using var output = zip.CreateEntry(name).Open();
        input.CopyTo(output);
    }
    private static void AddDirectory(ZipArchive zip, string root, string dir, int depth)
    {
        if (depth > 64) throw new IOException("Каталог слишком глубоко вложен.");
        foreach (string item in disk.Names(dir))
        {
            string path = dir + "/" + LinuxFiles.Normalize(item);
            string name = path[(root.Length + 1)..];
            if (disk.IsDirectory(path)) { zip.CreateEntry(name + "/"); AddDirectory(zip, root, path, depth + 1); }
            else AddEntry(zip, path, name);
        }
    }
    private static void Unzip()
    {
        RequireUser();
        string source = Input("ZIP: "), target = Input("Новый каталог назначения: ");
        Run("unzip", source + " -> " + target, () =>
        {
            string src = Resolve(source), dst = Resolve(target);
            if (disk.IsDirectory(dst) || disk.Size(dst) != null) throw new IOException("Каталог назначения уже существует.");
            using var inputZip = disk.Read(src);
            if (inputZip.Length > 128L * 1024 * 1024) throw new IOException("Архив превышает 128 МиБ.");
            using var zip = new ZipArchive(inputZip, ZipArchiveMode.Read);
            if (zip.Entries.Count > 1000) throw new IOException("Более 1000 элементов.");
            long total = 0;
            Mutate("unzip", dst, stage =>
            {
                disk.EnsureDirectory(stage);
                foreach (var entry in zip.Entries)
                {
                    if (((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000) throw new IOException("Ссылки в архиве запрещены.");
                    string relative;
                    try { relative = LinuxFiles.Normalize(entry.FullName); }
                    catch (UnauthorizedAccessException e) { throw new IOException("Выход из каталога архива или недопустимый путь.", e); }
                    if (relative == "." || relative.Count(c => c == '/') >= 64) throw new IOException("Недопустимый путь в архиве.");
                    string output = stage + "/" + relative;
                    if (entry.FullName.EndsWith('/')) { disk.EnsureDirectory(output); continue; }
                    disk.EnsureDirectory(output[..output.LastIndexOf('/')]);
                    using var input = entry.Open();
                    using var outputStream = disk.NewFile(output);
                    byte[] buffer = new byte[81920];
                    int n;
                    while ((n = input.Read(buffer)) > 0)
                    {
                        total += n;
                        if (total > 100L * 1024 * 1024) throw new IOException("Лимит распаковки: 100 МиБ.");
                        outputStream.Write(buffer, 0, n);
                    }
                    outputStream.Flush(flushToDisk: true);
                    using var parent = disk.DirectoryAt(output[..output.LastIndexOf('/')]);
                    LinuxFiles.Sync(parent);
                }
            }, stage => disk.Publish(stage, dst, replace: false));
        });
    }

    private static void Mutate(string action, string path, Action<string> prepare, Action<string> publish)
    {
        long owner = current!.Id;
        string relative = path[(LinuxFiles.Owner(owner).Length + 1)..];
        if (action != "mkdir")
        {
            using var parent = disk.DirectoryAt(path[..path.LastIndexOf('/')]);
        }
        var intent = new FileIntent(Guid.NewGuid().ToString("N"), owner, action, relative);
        db.BeginMutation(intent);
        string stage = Staging + "/" + intent.Id;
        try { prepare(stage); }
        catch
        {
            try { Cleanup(intent); db.CompleteMutation(intent, [], "mutation_aborted", false); }
            catch (Exception e) { throw new StorageFailure(e); }
            throw;
        }
        try
        {
            publish(stage);
            db.CompleteMutation(intent, Observed(intent), action, true);
        }
        catch (Exception e) { throw new StorageFailure(e); }
    }

    private static List<FileState> Observed(FileIntent intent)
    {
        string path = LinuxFiles.Owner(intent.Owner) + "/" + LinuxFiles.Normalize(intent.Path);
        var records = new List<FileState>();
        if (intent.Action == "mkdir") return records;
        if (intent.Action == "unzip")
        {
            if (disk.IsDirectory(path)) Scan(path, intent.Path, 0);
        }
        else
        {
            long? size = disk.Size(path);
            if (size.HasValue || intent.Action is "delete" or "modify")
                records.Add(new FileState(intent.Path, size ?? 0, !size.HasValue));
        }
        return records;

        void Scan(string directory, string relative, int depth)
        {
            if (depth > 64) throw new IOException("Каталог восстановления слишком глубоко вложен.");
            foreach (string name in disk.Names(directory))
            {
                string child = directory + "/" + LinuxFiles.Normalize(name);
                string rel = relative + "/" + name;
                if (disk.IsDirectory(child)) Scan(child, rel, depth + 1);
                else if (disk.Size(child) is long size) records.Add(new FileState(rel, size, false));
            }
        }
    }

    private static void Cleanup(FileIntent intent)
    {
        if (!Guid.TryParseExact(intent.Id, "N", out _)) throw new InvalidDataException("Неверный идентификатор намерения.");
        string stage = Path.Combine(data, Staging, intent.Id);
        if (Directory.Exists(stage)) Directory.Delete(stage, true);
        else File.Delete(stage);
        using var dir = disk.DirectoryAt(Staging);
        LinuxFiles.Sync(dir);
    }

    private static void Recover()
    {
        foreach (var intent in db.PendingMutations())
        {
            Cleanup(intent);
            string target = LinuxFiles.Owner(intent.Owner) + "/" + LinuxFiles.Normalize(intent.Path);
            string parent = target[..target.LastIndexOf('/')];
            while (!disk.IsDirectory(parent))
            {
                int slash = parent.LastIndexOf('/');
                parent = slash < 0 ? "." : parent[..slash];
            }
            using var directory = disk.DirectoryAt(parent);
            LinuxFiles.Sync(directory);
            db.CompleteMutation(intent, Observed(intent), "recovery_reconciled", true);
            Console.WriteLine($"Восстановление: метаданные операции {intent.Action} сверены с диском.");
        }
    }
    private static void Users() { RequireAdmin(); Run("users", null, () => Console.WriteLine(db.Users())); }
    private static void Audit() { RequireAdmin(); Run("audit", null, () => Console.WriteLine(db.Events())); }
    private static void SetBlocked(bool blocked)
    {
        RequireAdmin();
        string name = Input("Логин: ").Trim();
        Run(blocked ? "block" : "unblock", name, () => db.SetBlocked(current!.Id, name, blocked));
    }
}

internal sealed class Store
{
    private readonly string connection;
    public Store(string path)
    {
        connection = new SqliteConnectionStringBuilder { DataSource = path, ForeignKeys = true }.ToString();
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
              salt BLOB NOT NULL, password_hash BLOB NOT NULL, iterations INTEGER NOT NULL,
              admin INTEGER NOT NULL, blocked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
              path TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, size INTEGER NOT NULL,
              deleted INTEGER NOT NULL DEFAULT 0, UNIQUE(owner_id, path));
            CREATE TABLE IF NOT EXISTS operations(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              user_id INTEGER REFERENCES users(id), action TEXT NOT NULL, target TEXT, success INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS command_attempts(id INTEGER PRIMARY KEY,
              started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, finished_at TEXT,
              user_id INTEGER REFERENCES users(id), command TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('started','success','error')));
            CREATE TABLE IF NOT EXISTS file_intents(id TEXT PRIMARY KEY,
              owner_id INTEGER NOT NULL REFERENCES users(id),
              action TEXT NOT NULL CHECK(action IN ('create','modify','delete','zip','unzip','mkdir')),
              path TEXT NOT NULL, started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            """;
        cmd.ExecuteNonQuery();
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    private SqliteConnection Open()
    {
        var c = new SqliteConnection(connection);
        try
        {
            c.Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "PRAGMA synchronous=FULL";
            cmd.ExecuteNonQuery();
            return c;
        }
        catch { c.Dispose(); throw; }
    }
    public long BeginCommand(long? userId, string command)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO command_attempts(user_id,command,status) VALUES($u,$c,'started') RETURNING id";
        cmd.Parameters.AddWithValue("$u", (object?)userId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$c", command);
        return (long)cmd.ExecuteScalar()!;
    }
    public void FinishCommand(long id, bool success)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "UPDATE command_attempts SET status=$s,finished_at=CURRENT_TIMESTAMP WHERE id=$id AND status='started'";
        cmd.Parameters.AddWithValue("$s", success ? "success" : "error");
        cmd.Parameters.AddWithValue("$id", id);
        if (cmd.ExecuteNonQuery() != 1) throw new InvalidOperationException("Не удалось завершить запись попытки команды.");
    }
    public bool HasUsers() { using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT EXISTS(SELECT 1 FROM users)"; return (long)cmd.ExecuteScalar()! != 0; }
    public long Register(string name, string pass, bool admin)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(pass, salt, 600_000, HashAlgorithmName.SHA256, 32);
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO users(username,salt,password_hash,iterations,admin) VALUES($n,$s,$h,600000,$a) RETURNING id";
        cmd.Parameters.AddWithValue("$n", name); cmd.Parameters.AddWithValue("$s", salt); cmd.Parameters.AddWithValue("$h", hash); cmd.Parameters.AddWithValue("$a", admin ? 1 : 0);
        return (long)cmd.ExecuteScalar()!;
    }
    public User? Authenticate(string name, string pass)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,username,salt,password_hash,iterations,admin,blocked FROM users WHERE username=$n";
        cmd.Parameters.AddWithValue("$n", name);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) { Rfc2898DeriveBytes.Pbkdf2(pass, new byte[16], 600_000, HashAlgorithmName.SHA256, 32); return null; }
        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(pass, (byte[])r[2], r.GetInt32(4), HashAlgorithmName.SHA256, 32);
        return CryptographicOperations.FixedTimeEquals(actual, (byte[])r[3]) && r.GetInt32(6) == 0 ? new User(r.GetInt64(0), r.GetString(1), r.GetInt32(5) != 0) : null;
    }
    public bool IsActive(long id) { using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT EXISTS(SELECT 1 FROM users WHERE id=$id AND blocked=0)"; cmd.Parameters.AddWithValue("$id", id); return (long)cmd.ExecuteScalar()! != 0; }
    public void Audit(long? id, string action, string? target, bool success)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO operations(user_id,action,target,success) VALUES($u,$a,$t,$s)";
        cmd.Parameters.AddWithValue("$u", (object?)id ?? DBNull.Value); cmd.Parameters.AddWithValue("$a", action);
        cmd.Parameters.AddWithValue("$t", SafeTarget(target)); cmd.Parameters.AddWithValue("$s", success ? 1 : 0); cmd.ExecuteNonQuery();
    }
    public void BeginMutation(FileIntent intent)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO file_intents(id,owner_id,action,path) VALUES($i,$u,$a,$p)";
        cmd.Parameters.AddWithValue("$i", intent.Id);
        cmd.Parameters.AddWithValue("$u", intent.Owner);
        cmd.Parameters.AddWithValue("$a", intent.Action);
        cmd.Parameters.AddWithValue("$p", intent.Path);
        cmd.ExecuteNonQuery();
    }
    public List<FileIntent> PendingMutations()
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,owner_id,action,path FROM file_intents ORDER BY rowid";
        using var reader = cmd.ExecuteReader();
        var result = new List<FileIntent>();
        while (reader.Read()) result.Add(new(reader.GetString(0), reader.GetInt64(1), reader.GetString(2), reader.GetString(3)));
        return result;
    }
    public void CompleteMutation(FileIntent intent, IReadOnlyList<FileState> files, string action, bool success)
    {
        using var c = Open();
        using var tx = c.BeginTransaction();
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        foreach (var file in files)
        {
            cmd.CommandText = "INSERT INTO files(owner_id,path,size,deleted) VALUES($u,$p,$s,$d) ON CONFLICT(owner_id,path) DO UPDATE SET size=$s,deleted=$d";
            cmd.Parameters.AddWithValue("$u", intent.Owner);
            cmd.Parameters.AddWithValue("$p", file.Path);
            cmd.Parameters.AddWithValue("$s", file.Size);
            cmd.Parameters.AddWithValue("$d", file.Deleted ? 1 : 0);
            cmd.ExecuteNonQuery();
            cmd.Parameters.Clear();
        }
        cmd.CommandText = "INSERT INTO operations(user_id,action,target,success) VALUES($u,$a,$p,$s)";
        cmd.Parameters.AddWithValue("$u", intent.Owner);
        cmd.Parameters.AddWithValue("$a", action);
        cmd.Parameters.AddWithValue("$p", SafeTarget(action == "recovery_reconciled" ? $"{intent.Action}: {intent.Path}" : intent.Path));
        cmd.Parameters.AddWithValue("$s", success ? 1 : 0);
        cmd.ExecuteNonQuery();
        cmd.Parameters.Clear();
        cmd.CommandText = "DELETE FROM file_intents WHERE id=$i";
        cmd.Parameters.AddWithValue("$i", intent.Id);
        if (cmd.ExecuteNonQuery() != 1) throw new InvalidOperationException("Намерение отсутствует.");
        tx.Commit();
    }
    private static object SafeTarget(string? target) => target is null ? DBNull.Value :
        string.Concat(target.Take(1024).Select(c => char.IsControl(c) ? '�' : c));
    public string Users()
    {
        using var c = Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT id,username,admin,blocked FROM users ORDER BY id";
        using var r = cmd.ExecuteReader(); var b = new StringBuilder();
        while (r.Read()) b.AppendLine($"{r.GetInt64(0)} {r.GetString(1)} {(r.GetInt32(2) != 0 ? "администратор" : "пользователь")} {(r.GetInt32(3) != 0 ? "заблокирован" : "активен")}");
        return b.ToString();
    }
    public void SetBlocked(long actor, string name, bool blocked)
    {
        using var c = Open(); using var cmd = c.CreateCommand();
        cmd.CommandText = "UPDATE users SET blocked=$b WHERE username=$n AND id<>$id AND admin=0";
        cmd.Parameters.AddWithValue("$b", blocked ? 1 : 0); cmd.Parameters.AddWithValue("$n", name); cmd.Parameters.AddWithValue("$id", actor);
        if (cmd.ExecuteNonQuery() != 1) throw new InvalidOperationException("Пользователь не найден или является администратором.");
    }
    public string Events()
    {
        using var c = Open(); var b = new StringBuilder();
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT o.timestamp,COALESCE(u.username,'-'),o.action,COALESCE(o.target,''),o.success FROM operations o LEFT JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 200";
            using var r = cmd.ExecuteReader();
            while (r.Read()) b.AppendLine($"{r.GetString(0)} UTC | {r.GetString(1)} | {r.GetString(2)} | {r.GetString(3)} | {(r.GetInt32(4) != 0 ? "успех" : "ошибка")}");
        }
        b.AppendLine("Попытки команд (последние 200; started означает отсутствие завершения):");
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT a.started_at,COALESCE(u.username,'-'),a.command,a.status FROM command_attempts a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200";
            using var r = cmd.ExecuteReader();
            while (r.Read()) b.AppendLine($"{r.GetString(0)} UTC | {r.GetString(1)} | {r.GetString(2)} | {r.GetString(3)}");
        }
        return b.ToString();
    }
}
