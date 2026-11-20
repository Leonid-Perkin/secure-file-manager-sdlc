namespace SecureFileManager;

internal interface IAuditStore
{
    long BeginCommand(long? userId, string command);
    void FinishCommand(long id, bool success);
    void Audit(long? id, string action, string? target, bool success);
    string Events();
}

internal sealed class StorageFailure(Exception inner) : IOException(
    "Не удалось согласовать изменения; перезапустите приложение для восстановления.", inner);

internal sealed class AuditFailure(Exception inner) : IOException("Не удалось записать журнал аудита.", inner);

internal sealed class AuditService(IAuditStore store)
{
    public void RunAttempt(long? userId, string command, Func<bool> execute)
    {
        long id;
        try { id = store.BeginCommand(userId, command); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { throw new AuditFailure(ex); }

        bool success = false;
        try { success = execute(); }
        finally
        {
            try { store.FinishCommand(id, success); }
            catch (Exception ex) when (ex is not OutOfMemoryException) { throw new AuditFailure(ex); }
        }
    }

    public void RunOperation(long userId, string action, string? target, Action execute, bool recordedInMutation = false)
    {
        RunOperation(userId, action, target, () =>
        {
            execute();
            return true;
        }, recordedInMutation);
    }

    public T RunOperation<T>(long userId, string action, string? target, Func<T> execute, bool recordedInMutation = false)
    {
        T result;
        try { result = execute(); }
        catch (Exception ex) when (ex is not (StorageFailure or AuditFailure or OutOfMemoryException))
        {
            Record(userId, action, target, false);
            throw;
        }
        if (!recordedInMutation) Record(userId, action, target, true);
        return result;
    }

    public void Record(long? userId, string action, string? target, bool success)
    {
        try { store.Audit(userId, action, target, success); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { throw new AuditFailure(ex); }
    }

    public string ReadEvents() => store.Events();
}
