namespace SecureFileManager.UnitTests;

internal sealed class InMemoryAudit : IAuditStore
{
    public List<(long? Actor, string Action, string? Target, bool Success)> EventsWritten { get; } = [];
    public List<string> Trace { get; } = [];
    public bool RejectStart { get; init; }
    public bool RejectFinish { get; init; }
    public bool RejectEvent { get; init; }

    public long BeginCommand(long? userId, string command)
    {
        if (RejectStart) throw new IOException("start failed");
        Trace.Add($"begin:{userId}:{command}");
        return 42;
    }

    public void FinishCommand(long id, bool success)
    {
        if (RejectFinish) throw new IOException("finish failed");
        Trace.Add($"finish:{id}:{success}");
    }

    public void Audit(long? id, string action, string? target, bool success)
    {
        if (RejectEvent) throw new IOException("event failed");
        EventsWritten.Add((id, action, target, success));
    }

    public string Events() => "events";
}

internal sealed class InMemoryAccounts : IAccounts
{
    public User? LoginResult { get; set; }
    public bool Active { get; set; } = true;
    public bool Configured { get; set; } = true;
    public List<(string Name, bool Admin)> Registrations { get; } = [];
    public List<(long Actor, string Name, bool Blocked)> Blocks { get; } = [];
    public int LoginCalls { get; private set; }

    public bool HasUsers() => Configured;
    public long Register(string name, string pass, bool admin)
    {
        Registrations.Add((name, admin));
        Configured = true;
        return 7;
    }
    public User? Authenticate(string name, string pass)
    {
        LoginCalls++;
        return LoginResult;
    }
    public bool IsActive(long id) => Active;
    public string Users() => "users";
    public void SetBlocked(long actor, string name, bool blocked) => Blocks.Add((actor, name, blocked));
}
