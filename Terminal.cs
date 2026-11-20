using System.Text;

namespace SecureFileManager;

internal sealed class Terminal(TextReader reader, TextWriter output, Func<string>? hiddenPassword = null)
{
    public TextReader Reader { get; } = reader;
    public TextWriter Output { get; } = output;

    public string Input(string prompt)
    {
        Output.Write(prompt);
        Output.Flush();
        return Reader.ReadLine() ?? throw new EndOfStreamException("Ввод завершён.");
    }

    public string Password()
    {
        if (hiddenPassword is null) return Input("Пароль: ");
        Output.Write("Пароль: ");
        Output.Flush();
        return hiddenPassword();
    }

    public static Terminal OpenConsole() =>
        new(Console.In, Console.Out, Console.IsInputRedirected ? null : ReadHiddenPassword);

    private static string ReadHiddenPassword()
    {
        var text = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); return text.ToString(); }
            if (key.Key == ConsoleKey.Backspace && text.Length > 0) text.Length--;
            else if (!char.IsControl(key.KeyChar) && text.Length < 1024) text.Append(key.KeyChar);
        }
    }
}
