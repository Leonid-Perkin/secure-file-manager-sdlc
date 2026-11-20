using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace SecureFileManager;

internal record FileIntent(string Id, long Owner, string Action, string Path);
internal record FileState(string Path, long Size, bool Deleted);

internal sealed class Store : IAccounts, IAuditStore
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
        cmd.CommandText = """
            INSERT INTO users(username,salt,password_hash,iterations,admin)
            VALUES($n,$s,$h,600000,$a) RETURNING id
            """;
        cmd.Parameters.AddWithValue("$n", name);
        cmd.Parameters.AddWithValue("$s", salt);
        cmd.Parameters.AddWithValue("$h", hash);
        cmd.Parameters.AddWithValue("$a", admin ? 1 : 0);
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
    public string Events(int limit)
    {
        using var c = Open(); var b = new StringBuilder();
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT o.timestamp,COALESCE(u.username,'-'),o.action,COALESCE(o.target,''),o.success FROM operations o LEFT JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT $limit";
            cmd.Parameters.AddWithValue("$limit", limit);
            using var r = cmd.ExecuteReader();
            while (r.Read()) b.AppendLine($"{r.GetString(0)} UTC | {r.GetString(1)} | {r.GetString(2)} | {r.GetString(3)} | {(r.GetInt32(4) != 0 ? "успех" : "ошибка")}");
        }
        b.AppendLine($"Попытки команд (до {limit}; started — нет записи о завершении):");
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT a.started_at,COALESCE(u.username,'-'),a.command,a.status FROM command_attempts a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT $limit";
            cmd.Parameters.AddWithValue("$limit", limit);
            using var r = cmd.ExecuteReader();
            while (r.Read()) b.AppendLine($"{r.GetString(0)} UTC | {r.GetString(1)} | {r.GetString(2)} | {r.GetString(3)}");
        }
        return b.ToString();
    }
}
