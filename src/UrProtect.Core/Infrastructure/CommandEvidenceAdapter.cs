using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace UrProtect.Core.Infrastructure;

/// <summary>Infrastructure-owned command and build identity evidence.</summary>
public static class CommandEvidenceAdapter
{
    public static string ComputeCommandDigest(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var canonical = string.Join('\0', arguments.Select(argument => argument ?? string.Empty)) + '\0';
        return Sha256(Encoding.UTF8.GetBytes(canonical));
    }

    public static string ComputeEnvironmentDigest(int maximumEntries)
    {
        var values = Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>()
            .Select(entry => $"{entry.Key}={entry.Value}")
            .OrderBy(value => value, StringComparer.Ordinal)
            .Take(maximumEntries)
            .ToArray();
        return Sha256(Encoding.UTF8.GetBytes(string.Join('\0', values) + '\0'));
    }

    public static string ComputeAssemblyBuildSha256(
        Assembly assembly,
        string fallbackIdentity)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        try
        {
            var location = assembly.Location;
            if (!string.IsNullOrWhiteSpace(location) && File.Exists(location))
            {
                return Sha256(File.ReadAllBytes(location));
            }
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // Single-file and test-host deployments may not expose a readable path.
        }

        return Sha256(Encoding.UTF8.GetBytes(fallbackIdentity));
    }

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
