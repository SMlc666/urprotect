using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.Protect;

public sealed record ProtectedImagePublicationResult(
    bool Published,
    ProtectedImageRoleRecord? Role,
    IReadOnlyList<Diagnostic> Diagnostics);

/// <summary>
/// Publishes the Protected Image bytes and role record as one bounded, verified
/// publication. The caller can retain a SHA256SUMS file by supplying a manifest
/// path; no destination is replaced until all temporary content is verified.
/// </summary>
public static class ProtectedImagePublisher
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static ProtectedImagePublicationResult Publish(
        ProtectedImageEmissionResult emission,
        string artifactPath,
        string rolePath,
        string? manifestPath = null,
        string? stagePath = null,
        ProtectedImageStageRecord? stageRecord = null)
    {
        ArgumentNullException.ThrowIfNull(emission);
        var diagnostics = new DiagnosticBag();
        var artifactBytes = emission.ArtifactBytes;
        var emissionRole = emission.Role;
        if (!emission.IsSuccess || artifactBytes is null || emissionRole is null)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageMalformed,
                "A failed Protected Image emission cannot be published.");
            return new ProtectedImagePublicationResult(false, null, diagnostics.ToArray());
        }

        try
        {
            var artifactFullPath = Path.GetFullPath(artifactPath);
            var roleFullPath = Path.GetFullPath(rolePath);
            var manifestFullPath = manifestPath is null ? null : Path.GetFullPath(manifestPath);
            if ((stagePath is null) != (stageRecord is null))
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageMalformed,
                    "Protected Image stage path and stage record must be supplied together.");
                return new ProtectedImagePublicationResult(false, null, diagnostics.ToArray());
            }

            var stageFullPath = stagePath is null ? null : Path.GetFullPath(stagePath);
            var destinations = new[] { artifactFullPath, roleFullPath }
                .Concat(manifestFullPath is null ? Array.Empty<string>() : new[] { manifestFullPath })
                .Concat(stageFullPath is null ? Array.Empty<string>() : new[] { stageFullPath })
                .ToArray();
            if (destinations.Distinct(GetPathComparer()).Count() != destinations.Length)
            {
                diagnostics.Error(
                    DiagnosticCode.OutputPathConflict,
                    "Protected Image publication paths must be distinct.");
                return new ProtectedImagePublicationResult(false, null, diagnostics.ToArray());
            }

            EnsureParentDirectory(artifactFullPath);
            EnsureParentDirectory(roleFullPath);
            if (manifestFullPath is not null)
            {
                EnsureParentDirectory(manifestFullPath);
            }

            if (stageFullPath is not null)
            {
                EnsureParentDirectory(stageFullPath);
            }

            var role = emissionRole with
            {
                RawArtifactPath = artifactPath,
                RawArtifactRetained = true,
            };
            var artifactHash = ProtectedImageAbiV1.ComputeArtifactSha256(artifactBytes);
            if (!string.Equals(artifactHash, role.ArtifactSha256, StringComparison.OrdinalIgnoreCase)
                || role.ArtifactSize != artifactBytes.LongLength)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageIntegrityMismatch,
                    "Protected Image role metadata does not match the emitted artifact.");
                return new ProtectedImagePublicationResult(false, null, diagnostics.ToArray());
            }

            if (!ValidateRoleBinding(role, artifactBytes, diagnostics))
            {
                return new ProtectedImagePublicationResult(false, null, diagnostics.ToArray());
            }

            var roleJson = JsonSerializer.Serialize(role, JsonOptions) + "\n";
            var roleBytes = Encoding.UTF8.GetBytes(roleJson);
            if (stageRecord is not null && !ValidateStageBinding(
                    stageRecord,
                    role,
                    artifactPath,
                    rolePath,
                    manifestPath,
                    diagnostics))
            {
                return new ProtectedImagePublicationResult(false, null, diagnostics.ToArray());
            }

            var stageBytes = stageRecord is null
                ? null
                : SerializeStage(stageRecord, diagnostics);
            if (stageRecord is not null && stageBytes is null)
            {
                return new ProtectedImagePublicationResult(false, null, diagnostics.ToArray());
            }

            byte[]? manifestBytes = null;
            if (manifestFullPath is not null)
            {
                var roleHash = Convert.ToHexString(SHA256.HashData(roleBytes)).ToLowerInvariant();
                var artifactManifestPath = ManifestEntryPath(manifestFullPath, artifactFullPath);
                var roleManifestPath = ManifestEntryPath(manifestFullPath, roleFullPath);
                var manifest = $"{artifactHash}  {artifactManifestPath}\n"
                    + $"{roleHash}  {roleManifestPath}\n";
                if (stageFullPath is not null && stageBytes is not null)
                {
                    var stageHash = Convert.ToHexString(SHA256.HashData(stageBytes)).ToLowerInvariant();
                    var stageManifestPath = ManifestEntryPath(manifestFullPath, stageFullPath);
                    manifest += $"{stageHash}  {stageManifestPath}\n";
                }

                manifestBytes = Encoding.UTF8.GetBytes(manifest);
            }

            var temporaryPaths = new List<string>();
            var movedPaths = new List<string>();
            try
            {
                var artifactTemporary = CreateTemporaryPath(artifactFullPath);
                temporaryPaths.Add(artifactTemporary);
                WriteAndVerify(artifactTemporary, artifactBytes, artifactBytes);

                var roleTemporary = CreateTemporaryPath(roleFullPath);
                temporaryPaths.Add(roleTemporary);
                WriteAndVerify(roleTemporary, roleBytes, roleBytes);

                string? manifestTemporary = null;
                if (manifestFullPath is not null && manifestBytes is not null)
                {
                    manifestTemporary = CreateTemporaryPath(manifestFullPath);
                    temporaryPaths.Add(manifestTemporary);
                    WriteAndVerify(manifestTemporary, manifestBytes, manifestBytes);
                }

                string? stageTemporary = null;
                if (stageFullPath is not null && stageBytes is not null)
                {
                    stageTemporary = CreateTemporaryPath(stageFullPath);
                    temporaryPaths.Add(stageTemporary);
                    WriteAndVerify(stageTemporary, stageBytes, stageBytes);
                }

                MoveNew(artifactTemporary, artifactFullPath);
                movedPaths.Add(artifactFullPath);
                MoveNew(roleTemporary, roleFullPath);
                movedPaths.Add(roleFullPath);
                if (manifestTemporary is not null && manifestFullPath is not null)
                {
                    MoveNew(manifestTemporary, manifestFullPath);
                    movedPaths.Add(manifestFullPath);
                }

                if (stageTemporary is not null && stageFullPath is not null)
                {
                    MoveNew(stageTemporary, stageFullPath);
                    movedPaths.Add(stageFullPath);
                }

                return new ProtectedImagePublicationResult(true, role, diagnostics.ToArray());
            }
            finally
            {
                foreach (var temporaryPath in temporaryPaths)
                {
                    TryDelete(temporaryPath);
                }

                if (movedPaths.Count > 0 && movedPaths.Count < destinations.Length)
                {
                    foreach (var movedPath in movedPaths)
                    {
                        TryDelete(movedPath);
                    }
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            diagnostics.Error(DiagnosticCode.OutputIoFailure, exception.Message);
            return new ProtectedImagePublicationResult(false, null, diagnostics.ToArray());
        }
    }

    public static bool WriteStage(
        string stagePath,
        ProtectedImageStageRecord stage,
        out IReadOnlyList<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(stage);
        var diagnosticBag = new DiagnosticBag();
        if (!stage.Validate(diagnosticBag))
        {
            diagnostics = diagnosticBag.ToArray();
            return false;
        }

        try
        {
            var fullPath = Path.GetFullPath(stagePath);
            EnsureParentDirectory(fullPath);
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(stage, JsonOptions) + "\n");
            var temporaryPath = CreateTemporaryPath(fullPath);
            try
            {
                WriteAndVerify(temporaryPath, bytes, bytes);
                File.Move(temporaryPath, fullPath, overwrite: true);
            }
            finally
            {
                TryDelete(temporaryPath);
            }

            diagnostics = diagnosticBag.ToArray();
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            diagnosticBag.Error(DiagnosticCode.OutputIoFailure, exception.Message);
            diagnostics = diagnosticBag.ToArray();
            return false;
        }
    }

    private static byte[]? SerializeStage(ProtectedImageStageRecord stage, DiagnosticBag diagnostics)
    {
        if (!stage.Validate(diagnostics))
        {
            return null;
        }

        return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(stage, JsonOptions) + "\n");
    }

    private static void EnsureParentDirectory(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"The Protected Image output directory does not exist: {directory}");
        }
    }

    private static string CreateTemporaryPath(string destination)
    {
        var temporaryPath = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        if (File.Exists(temporaryPath))
        {
            throw new IOException("Could not reserve a Protected Image temporary output path.");
        }

        return temporaryPath;
    }

    private static void WriteAndVerify(string path, byte[] bytes, byte[] expected)
    {
        using (var stream = new FileStream(
                   path,
                   FileMode.CreateNew,
                   FileAccess.Write,
                   FileShare.None,
                   bufferSize: 64 * 1024,
                   options: FileOptions.SequentialScan))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }

        var published = File.ReadAllBytes(path);
        if (!published.AsSpan().SequenceEqual(expected))
        {
            throw new IOException("Protected Image publication bytes changed before rename.");
        }
    }

    private static void MoveNew(string temporaryPath, string destination)
    {
        File.Move(temporaryPath, destination, overwrite: false);
    }

    private static bool ValidateRoleBinding(
        ProtectedImageRoleRecord role,
        byte[] artifactBytes,
        DiagnosticBag diagnostics)
    {
        var decoded = ProtectedImageCodec.Decode(
            artifactBytes,
            role.SourceSha256,
            role.RequestSha256);
        diagnostics.AddRange(decoded.Diagnostics);
        if (!decoded.IsSuccess || decoded.Image is null)
        {
            return false;
        }

        var image = decoded.Image;
        var valid = true;
        void RoleMismatch(string message)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRoleMismatch, message);
            valid = false;
        }

        if (role.SchemaVersion != 1)
        {
            RoleMismatch("Protected Image role schema version is unsupported.");
        }

        if (!string.Equals(role.ArtifactRole, ProtectedImageAbiV1.ArtifactRole, StringComparison.Ordinal)
            || !string.Equals(role.AbiId, ProtectedImageAbiV1.AbiId, StringComparison.Ordinal)
            || role.AbiVersion != ProtectedImageAbiV1.AbiVersion
            || !string.Equals(role.Architecture, ProtectedImageAbiV1.Architecture, StringComparison.Ordinal))
        {
            RoleMismatch("Protected Image role ABI identity does not match the artifact codec.");
        }

        if (!string.Equals(role.UnitId, image.UnitId, StringComparison.Ordinal)
            || !string.Equals(role.Profile, image.Profile.ToCliValue(), StringComparison.Ordinal)
            || !string.Equals(role.ProducerId, image.ProducerId, StringComparison.Ordinal)
            || !string.Equals(role.RehydratorConsumerId, image.RehydratorConsumerId, StringComparison.Ordinal))
        {
            RoleMismatch("Protected Image role identity does not match the artifact metadata.");
        }

        if (!string.Equals(role.SourceSha256, image.SourceSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(role.ProducerBuildSha256, image.ProducerBuildSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(role.RequestSha256, image.RequestSha256, StringComparison.OrdinalIgnoreCase))
        {
            RoleMismatch("Protected Image role digest bindings do not match the artifact metadata.");
        }

        var expectedSelectors = image.Selectors;
        var expectedPasses = image.Passes.Select(ProtectionPassOrdering.Describe).ToArray();
        if (role.Selectors is null
            || role.Passes is null
            || !role.Selectors.SequenceEqual(expectedSelectors, StringComparer.Ordinal)
            || !role.Passes.SequenceEqual(expectedPasses, StringComparer.Ordinal))
        {
            RoleMismatch("Protected Image role request details do not match the artifact metadata.");
        }

        return valid && !diagnostics.HasErrors;
    }

    private static bool ValidateStageBinding(
        ProtectedImageStageRecord stage,
        ProtectedImageRoleRecord role,
        string artifactPath,
        string rolePath,
        string? manifestPath,
        DiagnosticBag diagnostics)
    {
        var valid = true;
        void Mismatch(string message)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRoleMismatch, message);
            valid = false;
        }

        if (!string.Equals(stage.ArtifactSha256, role.ArtifactSha256, StringComparison.OrdinalIgnoreCase)
            || stage.ArtifactSize != role.ArtifactSize
            || !string.Equals(stage.UnitId, role.UnitId, StringComparison.Ordinal)
            || !string.Equals(stage.Profile, role.Profile, StringComparison.Ordinal)
            || !string.Equals(stage.SourceSha256, role.SourceSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(stage.RequestSha256, role.RequestSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(stage.ProducerId, role.ProducerId, StringComparison.Ordinal)
            || !string.Equals(stage.ProducerBuildSha256, role.ProducerBuildSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(stage.RehydratorConsumerId, role.RehydratorConsumerId, StringComparison.Ordinal))
        {
            Mismatch("Protected Image stage bindings do not match the role record.");
        }

        if (!string.Equals(stage.ArtifactPath, artifactPath, StringComparison.Ordinal)
            || !string.Equals(stage.RolePath, rolePath, StringComparison.Ordinal)
            || !string.Equals(stage.RawEvidenceManifestPath, manifestPath, StringComparison.Ordinal))
        {
            Mismatch("Protected Image stage paths do not match the publication destinations.");
        }

        if (!stage.PublicationComplete
            || !string.Equals(stage.ArtifactRole, ProtectedImageAbiV1.ArtifactRole, StringComparison.Ordinal)
            || !string.Equals(stage.AbiId, ProtectedImageAbiV1.AbiId, StringComparison.Ordinal)
            || stage.AbiVersion != ProtectedImageAbiV1.AbiVersion)
        {
            Mismatch("Protected Image stage does not bind a complete ABI publication.");
        }

        return valid;
    }

    private static string ManifestEntryPath(string manifestPath, string destinationPath)
    {
        var manifestDirectory = Path.GetDirectoryName(manifestPath)
            ?? throw new IOException("The Protected Image checksum manifest has no parent directory.");
        var relative = Path.GetRelativePath(manifestDirectory, destinationPath);
        return relative.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');
    }

    private static StringComparer GetPathComparer() =>
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
