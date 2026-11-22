using System.Text;

namespace LinuxMailRelay365;

// Keep the existing UI language indices: Russian=0, English=1, Hebrew=2.
// English is the first-run default, regardless of the Windows display language.
internal static class UiLanguagePreference
{
    internal const int DefaultIndex = 1;
    private const string FileName = "ui-language.txt";

    internal static string FilePath(string dataDirectory) => Path.Combine(dataDirectory, FileName);

    internal static int Parse(string? code) => code?.Trim().ToLowerInvariant() switch
    {
        "ru" => 0,
        "en" => 1,
        "he" => 2,
        _ => DefaultIndex
    };

    internal static string Code(int index) => index switch
    {
        0 => "ru",
        2 => "he",
        _ => "en"
    };

    internal static int Load(string dataDirectory)
    {
        try
        {
            var file = FilePath(dataDirectory);
            return File.Exists(file) ? Parse(File.ReadAllText(file)) : DefaultIndex;
        }
        catch (IOException) { return DefaultIndex; }
        catch (UnauthorizedAccessException) { return DefaultIndex; }
    }

    internal static void Save(string dataDirectory, int index)
    {
        Directory.CreateDirectory(dataDirectory);
        var target = FilePath(dataDirectory);
        var temporary = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, Code(index) + Environment.NewLine, new UTF8Encoding(false));
            File.Move(temporary, target, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    internal static bool SelfTest()
    {
        string directory = Path.Combine(Path.GetTempPath(), "LMR365-language-" + Guid.NewGuid().ToString("N"));
        try
        {
            if (Load(directory) != DefaultIndex ||
                Parse("ru") != 0 || Parse("en") != 1 || Parse("he") != 2 ||
                Parse("unknown") != DefaultIndex || Parse(null) != DefaultIndex ||
                Code(0) != "ru" || Code(1) != "en" || Code(2) != "he")
                return false;

            foreach (var index in new[] { 0, 2, 1 })
            {
                Save(directory, index);
                if (Load(directory) != index) return false;
            }

            File.WriteAllText(FilePath(directory), "invalid");
            return Load(directory) == DefaultIndex;
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }
}
