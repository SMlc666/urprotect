using System.Text;
using UrProtect.Core.Infrastructure;

namespace UrProtect.Cli.Rendering;

/// <summary>Owns CLI stream rendering and delegates report publication to Infrastructure.</summary>
internal static class CommandOutputWriter
{
    internal static void WriteJson(TextWriter writer, string json)
    {
        writer.WriteLine(json);
    }

    internal static void WriteAtomicJson(string path, string json)
    {
        var publication = FileSystemAdapter.PublishAtomic(
            path,
            Encoding.UTF8.GetBytes(json + "\n"));
        if (!publication.IsSuccess)
        {
            var diagnostic = publication.Diagnostics.FirstOrDefault(d => d.IsError);
            throw new IOException(diagnostic.IsError ? diagnostic.Message : "The report could not be published.");
        }
    }
}
