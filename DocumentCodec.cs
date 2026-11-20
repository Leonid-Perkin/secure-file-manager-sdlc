using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml;
using System.Xml.Serialization;

namespace SecureFileManager;

public sealed class Note
{
    public string Title { get; set; } = "";
    public string Text { get; set; } = "";
}

internal static class DocumentCodec
{
    public const int MaxBytes = 1_048_576;
    private static readonly JsonSerializerOptions NoteJsonOptions = new()
    {
        MaxDepth = 16,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true
    };

    public static void ValidateDocument(string path, string content)
    {
        CheckSize(content);
        switch (Path.GetExtension(path).ToLowerInvariant())
        {
            case ".json":
                using (JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 64 })) { }
                break;
            case ".xml":
                using (var reader = XmlReader.Create(new StringReader(content), SafeXmlSettings()))
                    while (reader.Read()) { }
                break;
        }
    }

    public static string NoteFormat(string path)
    {
        string extension = Path.GetExtension(path).ToLowerInvariant();
        if (extension is not (".json" or ".xml"))
            throw new InvalidDataException("Для заметки используйте расширение .json или .xml.");
        return extension;
    }

    public static string EncodeNote(string path, Note note)
    {
        ValidateNote(note);
        if (NoteFormat(path) == ".json") return JsonSerializer.Serialize(note, NoteJsonOptions);
        using var output = new StringWriter();
        using (var writer = XmlWriter.Create(output, new XmlWriterSettings { OmitXmlDeclaration = true, Indent = true }))
            new XmlSerializer(typeof(Note)).Serialize(writer, note);
        return output.ToString();
    }

    public static Note DecodeNote(string path, string content)
    {
        CheckSize(content);
        Note? note;
        if (NoteFormat(path) == ".json")
            note = JsonSerializer.Deserialize<Note>(content, NoteJsonOptions);
        else
        {
            using var reader = XmlReader.Create(new StringReader(content), SafeXmlSettings());
            var serializer = new XmlSerializer(typeof(Note));
            serializer.UnknownNode += (_, _) => throw new InvalidDataException("Неизвестный элемент XML заметки.");
            serializer.UnknownAttribute += (_, _) => throw new InvalidDataException("Неизвестный атрибут XML заметки.");
            note = serializer.Deserialize(reader) as Note;
            while (reader.Read()) { }
        }
        return ValidateNote(note);
    }

    private static void CheckSize(string content)
    {
        if (Encoding.UTF8.GetByteCount(content) > MaxBytes) throw new IOException("Ограничение: 1 МиБ.");
    }

    private static XmlReaderSettings SafeXmlSettings() => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = MaxBytes
    };

    private static Note ValidateNote(Note? note)
    {
        if (note is null || string.IsNullOrWhiteSpace(note.Title) || note.Title.Length > 200 ||
            note.Text is null || note.Text.Length > 100_000)
            throw new InvalidDataException("Заголовок заметки обязателен (до 200 символов), текст — до 100000 символов.");
        return note;
    }
}
