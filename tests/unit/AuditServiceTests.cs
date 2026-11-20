namespace SecureFileManager.UnitTests;

public sealed class AuditServiceTests
{
    [Fact]
    public void RecordsAttemptBeforeExecuting()
    {
        var sink = new InMemoryAudit();
        new AuditService(sink).RunAttempt(7, "read", () =>
        {
            Assert.Equal(["begin:7:read"], sink.Trace);
            sink.Trace.Add("execute");
            return true;
        });
        Assert.Equal(["begin:7:read", "execute", "finish:42:True"], sink.Trace);
    }

    [Fact]
    public void RecordsFailureAndRethrowsTheOriginalError()
    {
        var sink = new InMemoryAudit();
        var audit = new AuditService(sink);
        var error = new EndOfStreamException();
        Assert.Same(error, Assert.Throws<EndOfStreamException>(() =>
            audit.RunAttempt(null, "read", () => throw error)));
        Assert.Equal(["begin::read", "finish:42:False"], sink.Trace);
    }

    [Fact]
    public void DoesNotExecuteWhenAuditStartFails()
    {
        var sink = new InMemoryAudit { RejectStart = true };
        var audit = new AuditService(sink);
        bool executed = false;
        Assert.Throws<AuditFailure>(() => audit.RunAttempt(null, "write", () => executed = true));
        Assert.False(executed);
        Assert.Empty(sink.Trace);
    }

    [Fact]
    public void SurfacesAuditFinishFailure()
    {
        var audit = new AuditService(new InMemoryAudit { RejectFinish = true });
        Assert.Throws<AuditFailure>(() => audit.RunAttempt(7, "read", () => true));
    }

    [Fact]
    public void DoesNotDuplicateSuccessRecordedWithMutation()
    {
        var sink = new InMemoryAudit();
        var audit = new AuditService(sink);
        audit.RunOperation(7, "delete", "sample.txt", () => { }, recordedInMutation: true);
        Assert.Empty(sink.EventsWritten);
        Assert.Throws<IOException>(() => audit.RunOperation(7, "delete", "sample.txt",
            () => throw new IOException(), recordedInMutation: true));
        Assert.Equal((7L, "delete", "sample.txt", false), Assert.Single(sink.EventsWritten));
    }
}
