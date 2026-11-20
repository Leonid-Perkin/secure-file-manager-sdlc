using System.Globalization;
using Microsoft.Data.Sqlite;

namespace SecureFileManager;

internal sealed class ConsoleApp(Terminal terminal, AuthService auth, AuditService audit, Action<string> executeFileCommand)
{
    private static readonly string[] NumberedCommands =
    [
        "exit", "register", "login", "logout", "drives", "list", "read", "write", "delete",
        "mkdir", "zip", "unzip", "users", "block", "unblock", "audit", "save-note", "read-note"
    ];

    internal static (string Name, string? Command) ParseCommand(string? input)
    {
        string name = input is null ? "exit" : input.Trim().ToLowerInvariant();
        if (name is "help" or "menu" or "?") return (name, "help");
        if (NumberedCommands.Contains(name, StringComparer.Ordinal)) return (name, name);
        if (int.TryParse(name, NumberStyles.None, CultureInfo.InvariantCulture, out int number) &&
            number < NumberedCommands.Length && name == number.ToString(CultureInfo.InvariantCulture))
            return (name, NumberedCommands[number]);
        return ("unknown", null);
    }

    public void Run()
    {
        if (auth.NeedsAdministrator)
        {
            terminal.Output.WriteLine("Первый запуск: создайте администратора.");
            audit.RunAttempt(null, "init_admin", () =>
            {
                Register(initialAdministrator: true);
                return true;
            });
        }

        terminal.Output.WriteLine("Команды: help — справка, exit — выход.");
        while (true)
        {
            terminal.Output.Write(auth.Current is { } user ? $"{user.Name}> " : "гость> ");
            terminal.Output.Flush();
            var (name, command) = ParseCommand(terminal.Reader.ReadLine());
            try
            {
                audit.RunAttempt(auth.Current?.Id, name, () => Dispatch(command));
            }
            catch (Exception ex) when (ex is not (OutOfMemoryException or StorageFailure or AuditFailure or SqliteException))
            {
                terminal.Output.WriteLine("Ошибка: " + ex.Message);
            }
            if (command == "exit") return;
        }
    }

    private bool Dispatch(string? command)
    {
        switch (command)
        {
            case "exit": audit.Record(auth.Current?.Id, "exit", null, true); break;
            case "help": Help(); audit.Record(auth.Current?.Id, "help", null, true); break;
            case "register": Register(initialAdministrator: false); break;
            case "login":
                auth.RequireSignedOut("login");
                auth.Login(terminal.Input("Логин: "), terminal.Password());
                terminal.Output.WriteLine("Вход выполнен.");
                break;
            case "logout": auth.Logout(); break;
            case "users": terminal.Output.WriteLine(auth.ListUsers()); break;
            case "block": case "unblock":
                auth.RequireAdmin();
                auth.SetBlocked(terminal.Input("Логин: "), blocked: command == "block");
                break;
            case "audit": terminal.Output.WriteLine(auth.AdminAction("audit", null, _ => audit.ReadEvents())); break;
            case null:
                audit.Record(auth.Current?.Id, "unknown_command", null, false);
                terminal.Output.WriteLine("Неизвестная команда. Введите help.");
                return false;
            default: executeFileCommand(command); break;
        }
        return true;
    }

    private void Register(bool initialAdministrator)
    {
        auth.RequireSignedOut("register");
        auth.Register(terminal.Input("Логин (3–32 латинские буквы, цифры, _): "), terminal.Password(), initialAdministrator);
        terminal.Output.WriteLine("Учётная запись создана.");
    }

    private void Help() => terminal.Output.WriteLine("""
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
}
