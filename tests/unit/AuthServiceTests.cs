namespace SecureFileManager.UnitTests;

public sealed class AuthServiceTests
{
    private const string Password = "test-password-123";
    private readonly InMemoryAccounts accounts = new();
    private readonly InMemoryAudit sink = new();
    private readonly AuthService service;
    private int delays;

    public AuthServiceTests()
    {
        service = new AuthService(accounts, new AuditService(sink), () => delays++);
    }

    [Theory]
    [InlineData("a", Password)]
    [InlineData("name with spaces", Password)]
    [InlineData("valid_name", "short")]
    public void RejectsInvalidRegistrationWithoutCreatingAccount(string name, string password)
    {
        Assert.Throws<ArgumentException>(() => service.Register(name, password));
        Assert.Empty(accounts.Registrations);
        Assert.Equal(((long?)null, "register", name, false), Assert.Single(sink.EventsWritten));
    }

    [Fact]
    public void AdministratorCanOnlyBeCreatedDuringInitialSetup()
    {
        accounts.Configured = false;
        Assert.True(service.NeedsAdministrator);
        service.Register(" admin ", Password, initialAdministrator: true);
        Assert.Throws<InvalidOperationException>(() => service.Register("another", Password, initialAdministrator: true));
        Assert.Equal(("admin", true), Assert.Single(accounts.Registrations));
    }

    [Fact]
    public void FailedLoginLeavesNoSessionAndDoesNotRecordPassword()
    {
        Assert.Throws<UnauthorizedAccessException>(() => service.Login(" student ", Password));
        Assert.Null(service.Current);
        Assert.Equal(1, delays);
        Assert.Equal(((long?)null, "login", "student", false), Assert.Single(sink.EventsWritten));
    }

    [Fact]
    public void LoginDoesNotEstablishSessionWhenAuditFails()
    {
        accounts.LoginResult = new User(7, "student", false);
        var auth = new AuthService(accounts, new AuditService(new InMemoryAudit { RejectEvent = true }), () => { });
        Assert.Throws<AuditFailure>(() => auth.Login("student", Password));
        Assert.Null(auth.Current);
    }

    [Fact]
    public void NormalUserCannotChangeAccessAndBlockedSessionIsCleared()
    {
        accounts.LoginResult = new User(7, "student", false);
        service.Login("student", Password);
        Assert.Throws<UnauthorizedAccessException>(() => service.SetBlocked("other", blocked: true));
        Assert.Empty(accounts.Blocks);
        accounts.Active = false;
        Assert.Throws<UnauthorizedAccessException>(() => service.RequireUser());
        Assert.Null(service.Current);
        Assert.Contains((7L, "admin_access_denied", null, false), sink.EventsWritten);
        Assert.Contains((7L, "session_blocked", null, false), sink.EventsWritten);
    }

    [Fact]
    public void AdministratorCanBlockAndUnblockThenLogout()
    {
        accounts.LoginResult = new User(7, "admin", true);
        service.Login("admin", Password);
        service.SetBlocked("student", blocked: true);
        service.SetBlocked("student", blocked: false);
        service.Logout();
        Assert.Equal([(7L, "student", true), (7L, "student", false)], accounts.Blocks);
        Assert.Null(service.Current);
    }
}
