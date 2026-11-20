using System.Text.Json;
using System.Xml;

namespace SecureFileManager.UnitTests;

public sealed class CommandAndDocumentTests
{
    [Theory]
    [InlineData("  READ  ", "read", "read")]
    [InlineData("6", "6", "read")]
    [InlineData("?", "?", "help")]
    [InlineData(null, "exit", "exit")]
    [InlineData("006", "unknown", null)]
    [InlineData("arbitrary input", "unknown", null)]
    public void ParsesCommandWithoutLoggingUnrecognizedText(string? input, string name, string? command)
    {
        Assert.Equal((name, command), ConsoleApp.ParseCommand(input));
    }

    [Fact]
    public void DispatcherRoutesFileCommandAndKeepsUnknownInputOutOfAudit()
    {
        using var input = new StringReader("6\nprivate input\n0\n");
        using var output = new StringWriter();
        var sink = new InMemoryAudit();
        var audit = new AuditService(sink);
        var auth = new AuthService(new InMemoryAccounts(), audit, () => { });
        var commands = new List<string>();
        new ConsoleApp(new Terminal(input, output), auth, audit, commands.Add).Run();
        Assert.Equal(["read"], commands);
        Assert.Contains("Неизвестная команда", output.ToString());
        Assert.Contains("begin::unknown", sink.Trace);
        Assert.Contains("finish:42:False", sink.Trace);
        Assert.DoesNotContain(sink.Trace, line => line.Contains("private input"));
    }

    [Theory]
    [InlineData("note.json")]
    [InlineData("note.XML")]
    public void NoteRoundTripsInBothFormats(string path)
    {
        var note = new Note { Title = "Заметка", Text = "Текст <&> \"в кавычках\"" };
        var restored = DocumentCodec.DecodeNote(path, DocumentCodec.EncodeNote(path, note));
        Assert.Equal(note.Title, restored.Title);
        Assert.Equal(note.Text, restored.Text);
    }

    [Fact]
    public void RejectsUnknownJsonFieldAndInvalidTitle()
    {
        Assert.Throws<JsonException>(() =>
            DocumentCodec.DecodeNote("note.json", """{"Title":"Заметка","Text":"Текст","Extra":true}"""));
        Assert.Throws<InvalidDataException>(() =>
            DocumentCodec.EncodeNote("note.json", new Note { Title = " " }));
    }

    [Fact]
    public void RejectsDtdAndOversizedUtf8Documents()
    {
        Assert.Throws<XmlException>(() => DocumentCodec.ValidateDocument("file.xml", "<!DOCTYPE root><root/>"));
        Assert.Throws<IOException>(() =>
            DocumentCodec.ValidateDocument("file.txt", new string('я', DocumentCodec.MaxBytes / 2 + 1)));
    }

    [Theory]
    [InlineData(".", ".")]
    [InlineData("docs//./note.txt", "docs/note.txt")]
    public void NormalizesFileCommandPaths(string input, string expected)
    {
        Assert.Equal(expected, LinuxFiles.Normalize(input));
    }

    [Theory]
    [InlineData("/outside")]
    [InlineData("docs/../note.txt")]
    [InlineData("docs\\note.txt")]
    public void RejectsPathsOutsideFileCommandPolicy(string input)
    {
        Assert.Throws<UnauthorizedAccessException>(() => LinuxFiles.Normalize(input));
    }
}
