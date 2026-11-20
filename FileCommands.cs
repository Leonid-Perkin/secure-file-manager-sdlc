using System.IO.Compression;
using System.Text;

namespace SecureFileManager;

internal sealed class FileCommands(string data, LinuxFiles disk, Store db, AuthService auth, AuditService audit, Terminal terminal)
{
    public const string Staging = ".sfm-stage";

    private string Root()
    {
        string root = LinuxFiles.Owner(auth.RequireUser().Id);
        disk.EnsureDirectory(root);
        return root;
    }

    private string Resolve(string relative)
    {
        string path = LinuxFiles.Normalize(relative);
        string root = Root();
        return path == "." ? root : root + "/" + path;
    }
    public void Execute(string command)
    {
        switch (command)
        {
            case "drives": audit.RunOperation(auth.RequireUser().Id, command, null, Drives); break;
            case "list": FileAction(command, List); break;
            case "read": FileAction(command, Read); break;
            case "write": FileAction(command, Write); break;
            case "delete": FileAction(command, Delete, recordedInMutation: true); break;
            case "mkdir": FileAction(command, MakeDirectory, recordedInMutation: true); break;
            case "zip": Zip(); break;
            case "unzip": Unzip(); break;
            case "save-note": FileAction(command, SaveNote); break;
            case "read-note": FileAction(command, ReadNote); break;
            default: throw new ArgumentException("Неизвестная файловая команда.", nameof(command));
        }
    }

    private void FileAction(string action, Action<string> work, bool recordedInMutation = false)
    {
        var user = auth.RequireUser();
        string path = terminal.Input("Путь: ");
        audit.RunOperation(user.Id, action, path, () => work(Resolve(path)), recordedInMutation);
    }

    private void Drives()
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            try { terminal.Output.WriteLine(d.IsReady ? $"{d.Name} {d.DriveType} {d.DriveFormat}: всего {d.TotalSize}, доступно {d.AvailableFreeSpace} байт" : $"{d.Name}: не готов"); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { terminal.Output.WriteLine($"{d.Name}: {e.Message}"); }
        }
    }
    private void List(string path)
    {
        foreach (var item in disk.Names(path))
        {
            try { terminal.Output.WriteLine((disk.IsDirectory(path + "/" + item) ? "[каталог] " : "[файл] ") + SafeDisplay(item)); }
            catch (IOException) { terminal.Output.WriteLine("[недоступно] " + SafeDisplay(item)); }
        }
    }
    private static string SafeDisplay(string text) => string.Concat(text.Select(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t') ? '�' : c));
    private string ReadText(string path)
    {
        using var stream = disk.Read(path);
        var buffer = new byte[DocumentCodec.MaxBytes + 1];
        int count = stream.ReadAtLeast(buffer, buffer.Length, false);
        if (count == buffer.Length) throw new IOException("Файл превышает 1 МиБ.");
        return Encoding.UTF8.GetString(buffer, 0, count).TrimStart('\uFEFF');
    }
    private void Read(string path) => terminal.Output.WriteLine(SafeDisplay(ReadText(path)));
    private void Write(string path)
    {
        terminal.Output.WriteLine("Введите текст, отдельная строка .end завершает ввод:");
        var text = new StringBuilder();
        while (true)
        {
            string line = terminal.Reader.ReadLine() ?? throw new EndOfStreamException("Ввод прерван; файл не изменён.");
            if (line == ".end") break;
            text.AppendLine(line);
            if (text.Length > DocumentCodec.MaxBytes) throw new IOException("Ограничение: 1 МиБ.");
        }
        string content = text.ToString();
        SaveContent(path, content);
    }
    private void SaveContent(string path, string content)
    {
        DocumentCodec.ValidateDocument(path, content);
        bool existed = disk.Size(path) != null;
        Mutate(existed ? "modify" : "create", path, stage =>
        {
            using var stream = disk.NewFile(stage);
            stream.Write(Encoding.UTF8.GetBytes(content));
            stream.Flush(flushToDisk: true);
        }, stage => disk.Publish(stage, path, replace: existed));
        terminal.Output.WriteLine(existed ? "Файл изменён." : "Файл создан.");
    }
    private void SaveNote(string path)
    {
        DocumentCodec.NoteFormat(path);
        var note = new Note { Title = terminal.Input("Заголовок: "), Text = terminal.Input("Текст (одна строка): ") };
        SaveContent(path, DocumentCodec.EncodeNote(path, note));
    }
    private void ReadNote(string path)
    {
        var note = DocumentCodec.DecodeNote(path, ReadText(path));
        terminal.Output.WriteLine(SafeDisplay($"Заголовок: {note.Title}\nТекст: {note.Text}"));
    }
    private void Delete(string path)
    {
        if (disk.Size(path) is null) throw new FileNotFoundException("Файл не найден.");
        Mutate("delete", path, _ => { }, _ => disk.DeleteFile(path));
    }
    private void MakeDirectory(string path)
    {
        if (path == Root() || disk.IsDirectory(path))
        {
            audit.Record(auth.RequireUser().Id, "mkdir", Path.GetRelativePath(Root(), path), true);
            return;
        }
        Mutate("mkdir", path, _ => { }, _ => disk.EnsureDirectory(path));
    }
    private void Zip()
    {
        var user = auth.RequireUser();
        string source = terminal.Input("Файл или каталог: "), target = terminal.Input("Новый ZIP: ");
        audit.RunOperation(user.Id, "zip", source + " -> " + target, () =>
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
        }, recordedInMutation: true);
    }
    private void AddEntry(ZipArchive zip, string path, string name)
    {
        using var input = disk.Read(path);
        using var output = zip.CreateEntry(name).Open();
        input.CopyTo(output);
    }
    private void AddDirectory(ZipArchive zip, string root, string dir, int depth)
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
    private void Unzip()
    {
        var user = auth.RequireUser();
        string source = terminal.Input("ZIP: "), target = terminal.Input("Новый каталог назначения: ");
        audit.RunOperation(user.Id, "unzip", source + " -> " + target, () =>
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
        }, recordedInMutation: true);
    }

    private void Mutate(string action, string path, Action<string> prepare, Action<string> publish)
    {
        long owner = auth.RequireUser().Id;
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

    private List<FileState> Observed(FileIntent intent)
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

    private void Cleanup(FileIntent intent)
    {
        if (!Guid.TryParseExact(intent.Id, "N", out _)) throw new InvalidDataException("Неверный идентификатор намерения.");
        string stage = Path.Combine(data, Staging, intent.Id);
        if (Directory.Exists(stage)) Directory.Delete(stage, true);
        else File.Delete(stage);
        using var dir = disk.DirectoryAt(Staging);
        LinuxFiles.Sync(dir);
    }

    public void Recover()
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
            terminal.Output.WriteLine($"Восстановление: метаданные операции {intent.Action} сверены с диском.");
        }
    }
}
