using System.Security.Cryptography;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Application.Protection;

/// <summary>
/// Projects the canonical HostContext ABI into the semantic proof context only
/// after the profile's exact dynamic entry symbol and executable extent validate.
/// </summary>
public static class HostContextProofContextFactory
{
    public static Aarch64HostContextProofContext? TryCreate(
        ElfFile file,
        ProtectedImageProfile profile,
        string entrySymbol)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(entrySymbol);
        if (profile != ProtectedImageProfile.HostContextEntry
            || file.Header.Type != ElfConstants.TypeDyn
            || file.Kind != ElfFileKind.SharedObject
            || file.ProgramHeaders.Any(header => header.Type == ElfConstants.PtInterp)
            || !HostContextContract.TryValidateEntryName(entrySymbol, out _))
        {
            return null;
        }

        var entrySymbols = file.FunctionSymbols
            .Where(symbol => symbol.IsDynamic
                && string.Equals(symbol.Name, entrySymbol, StringComparison.Ordinal)
                && symbol.Size > 0
                && symbol.TryGetEnd(out _))
            .ToArray();
        if (entrySymbols.Length != 1)
        {
            return null;
        }

        var entry = entrySymbols[0];
        var executableOwners = file.LoadMap.Segments.Count(segment =>
            segment.IsExecutable
            && segment.ContainsVirtualAddress(entry.Value, entry.Size));
        if (executableOwners != 1
            || !file.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(entry.Value),
                entry.Size,
                out _))
        {
            return null;
        }

        var sourceSha256 = Convert.ToHexString(SHA256.HashData(file.Bytes.Span)).ToLowerInvariant();
        return new Aarch64HostContextProofContext(
            entry,
            sourceSha256,
            HostContextContract.AbiVersion,
            HostContextContract.MinimumContextSize,
            HostContextContract.ThreadLifetimeContextSize,
            HostContextContract.StructSizeOffset,
            HostContextContract.CapabilitiesOffset,
            HostContextContract.UserDataOffset,
            HostContextContract.EmitDiagnosticCallbackOffset,
            HostContextContract.CreateImageThreadCallbackOffset,
            HostContextContract.JoinImageThreadCallbackOffset,
            (ulong)HostContextCapability.ThreadLifetime);
    }
}
