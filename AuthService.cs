using System.Text.RegularExpressions;

namespace SecureFileManager;

internal record User(long Id, string Name, bool Admin);

internal interface IAccounts
{
    bool HasUsers();
    long Register(string name, string pass, bool admin);
    User? Authenticate(string name, string pass);
    bool IsActive(long id);
    string Users();
    void SetBlocked(long actor, string name, bool blocked);
}

internal sealed class AuthService(IAccounts accounts, AuditService audit, Action delayFailedLogin)
{
    public User? Current { get; private set; }
    public bool NeedsAdministrator => !accounts.HasUsers();

    public void RequireSignedOut(string action)
    {
        if (Current is null) return;
        audit.Record(Current.Id, action + "_denied", null, false);
        throw new InvalidOperationException("Сначала выйдите из учётной записи.");
    }

    public void Register(string name, string password, bool initialAdministrator = false)
    {
        RequireSignedOut("register");
        name = name.Trim();
        long userId;
        try
        {
            if (!Regex.IsMatch(name, @"\A[a-zA-Z0-9_]{3,32}\z")) throw new ArgumentException("Недопустимый логин.");
            if (password.Length is < 12 or > 1024)
                throw new ArgumentException("Пароль должен содержать от 12 до 1024 символов.");
            if (initialAdministrator && !NeedsAdministrator)
                throw new InvalidOperationException("Первоначальная настройка уже выполнена.");
            userId = accounts.Register(name, password, initialAdministrator);
        }
        catch
        {
            audit.Record(null, "register", name, false);
            throw;
        }
        audit.Record(userId, initialAdministrator ? "init_admin" : "register", null, true);
    }

    public void Login(string name, string password)
    {
        RequireSignedOut("login");
        name = name.Trim();
        var user = accounts.Authenticate(name, password);
        audit.Record(user?.Id, "login", name, user is not null);
        if (user is null)
        {
            delayFailedLogin();
            throw new UnauthorizedAccessException("Неверный логин, пароль или учётная запись заблокирована.");
        }
        Current = user;
    }

    public void Logout()
    {
        audit.Record(RequireUser().Id, "logout", null, true);
        Current = null;
    }

    public User RequireUser()
    {
        var user = Current;
        if (user is null)
        {
            audit.Record(null, "access_denied", null, false);
            throw new UnauthorizedAccessException("Необходим вход.");
        }
        if (!accounts.IsActive(user.Id))
        {
            Current = null;
            audit.Record(user.Id, "session_blocked", null, false);
            throw new UnauthorizedAccessException("Учётная запись заблокирована.");
        }
        return user;
    }

    public User RequireAdmin()
    {
        var user = RequireUser();
        if (user.Admin) return user;
        audit.Record(user.Id, "admin_access_denied", null, false);
        throw new UnauthorizedAccessException("Требуются права администратора.");
    }

    public string ListUsers() => AdminAction("users", null, _ => accounts.Users());

    public void SetBlocked(string name, bool blocked)
    {
        name = name.Trim();
        AdminAction(blocked ? "block" : "unblock", name, actor =>
        {
            accounts.SetBlocked(actor, name, blocked);
            return true;
        });
    }

    public T AdminAction<T>(string action, string? target, Func<long, T> work)
    {
        long actor = RequireAdmin().Id;
        return audit.RunOperation(actor, action, target, () => work(actor));
    }
}
