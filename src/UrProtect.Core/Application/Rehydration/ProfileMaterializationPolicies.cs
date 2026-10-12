using UrProtect.Core.Application.Protection;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Application.Rehydration;

/// <summary>
/// Profile policy owns acceptance and output invariants. Physical bytes remain the
/// responsibility of the shared ELF layout planner/materializer.
/// </summary>
public interface IProfileMaterializationPolicy
{
    ProtectedImageProfile Profile { get; }

    bool ValidateSource(ElfFile source, RehydrationOptions options, DiagnosticBag diagnostics);

    bool ValidateOutput(ElfFile output, RehydrationOptions options, DiagnosticBag diagnostics);
}

/// <summary>Current standalone image policy; the native execveat adapter remains separate.</summary>
public sealed class OuterExecveatMaterializationPolicy : IProfileMaterializationPolicy
{
    public ProtectedImageProfile Profile => ProtectedImageProfile.OuterExecveat;

    public bool ValidateSource(ElfFile source, RehydrationOptions options, DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(diagnostics);
        // The outer profile preserves the existing generic ELF layout contract.
        // Native PT_INTERP/interpreter acceptance is owned by ElfPackService and
        // the existing anonymous memfd+execveat adapter, not this materializer.
        return true;
    }

    public bool ValidateOutput(ElfFile output, RehydrationOptions options, DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(diagnostics);
        return true;
    }
}

/// <summary>
/// HostContext entry-image policy. It never dispatches through the outer
/// execveat policy; it validates the bounded ET_DYN handoff subset independently
/// before and after the shared physical layout operation.
/// </summary>
public sealed class HostContextEntryMaterializationPolicy : IProfileMaterializationPolicy
{
    public ProtectedImageProfile Profile => ProtectedImageProfile.HostContextEntry;

    public bool ValidateSource(ElfFile source, RehydrationOptions options, DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(diagnostics);
        var valid = true;

        if (source.Header.Type != ElfConstants.TypeDyn || source.Kind != ElfFileKind.SharedObject)
        {
            diagnostics.Error(
                DiagnosticCode.UnsupportedPackInput,
                "The host-context-entry profile requires an AArch64 ET_DYN shared-object entry image.");
            valid = false;
        }

        if (source.ProgramHeaders.Any(header => header.Type == ElfConstants.PtInterp))
        {
            diagnostics.Error(
                DiagnosticCode.UnsupportedInterpreter,
                "The host-context-entry profile does not permit a process interpreter.");
            valid = false;
        }

        var entryName = options.ExpectedEntrySymbol ?? HostContextContract.EntrySymbol;
        if (!HostContextContract.TryValidateEntryName(entryName, out var entryError))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageMalformed,
                entryError ?? "The HostContext entry symbol is invalid.");
            valid = false;
        }

        var entrySymbols = source.FunctionSymbols
            .Where(symbol => symbol.IsDynamic
                && string.Equals(symbol.Name, entryName, StringComparison.Ordinal)
                && symbol.Size > 0
                && symbol.TryGetEnd(out _))
            .ToArray();
        if (entrySymbols.Length != 1)
        {
            diagnostics.Error(
                entrySymbols.Length == 0 ? DiagnosticCode.FunctionNotFound : DiagnosticCode.FunctionSelectorAmbiguous,
                $"The HostContext entry symbol '{entryName}' must resolve to exactly one bounded dynamic function.");
            valid = false;
        }
        else
        {
            var entry = entrySymbols[0];
            if (!source.LoadMap.Segments.Any(segment =>
                    segment.IsExecutable
                    && segment.ContainsVirtualAddress(entry.Value, entry.Size)))
            {
                diagnostics.Error(
                    DiagnosticCode.AddressUnmapped,
                    "The HostContext entry symbol is not wholly contained in an executable PT_LOAD.",
                    entry.Value);
                valid = false;
            }
        }

        if (options.HostContextAbiVersion != HostContextContract.AbiVersion
            || !HostContextContract.HasRequiredCapabilities(
                options.HostContextRequiredCapabilities,
                HostContextContract.MandatoryCapabilities)
            || !HostContextContract.HasOnlySupportedCapabilities(options.HostContextRequiredCapabilities))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageUnsupported,
                "The HostContext ABI version or required capabilities are outside the current v3 subset.");
            valid = false;
        }

        var unsupportedDynamicTags = new HashSet<ulong>
        {
            ElfConstants.DtRpath,
            ElfConstants.DtRunPath,
            ElfConstants.DtTextRel,
            ElfConstants.DtRel,
            ElfConstants.DtRelSz,
            ElfConstants.DtRelEnt,
            ElfConstants.DtVerdef,
            ElfConstants.DtVerdefNum,
        };
        unsupportedDynamicTags.UnionWith(ElfConstants.AndroidPackedRelocationTags);
        foreach (var entry in source.DynamicEntries)
        {
            if (unsupportedDynamicTags.Contains(entry.Tag))
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageUnsupported,
                    $"HostContext preflight rejects unsupported dynamic tag 0x{entry.Tag:X}.");
                valid = false;
            }
        }

        if (source.ProgramHeaders.Any(header =>
                header.Type == ElfConstants.PtGnuStack && (header.Flags & ElfConstants.PfX) != 0))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageUnsupported,
                "HostContext preflight rejects an executable PT_GNU_STACK request.");
            valid = false;
        }

        foreach (var tls in source.TlsMetadata.Segments)
        {
            if (tls.MemorySize == 0
                || (tls.Permissions & ElfConstants.PfR) == 0
                || (tls.Permissions & ElfConstants.PfX) != 0
                || (tls.Permissions & ~(ElfConstants.PfR | ElfConstants.PfW)) != 0
                || tls.OwningLoadProgramHeaderIndex < 0
                || tls.OwningLoadProgramHeaderIndex >= source.ProgramHeaders.Count)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageUnsupported,
                    "HostContext PT_TLS requires one non-empty readable non-executable segment with a mapped owner.");
                valid = false;
                continue;
            }

            var owner = source.ProgramHeaders[tls.OwningLoadProgramHeaderIndex];
            if (owner.Type != ElfConstants.PtLoad
                || (owner.Flags & (ElfConstants.PfR | ElfConstants.PfW))
                    != (ElfConstants.PfR | ElfConstants.PfW)
                || tls.FileSize > owner.FileSize
                || tls.TemplateFileOffset.Value < owner.Offset
                || tls.TemplateFileOffset.Value - owner.Offset
                    > owner.FileSize - tls.FileSize
                || tls.TemplateAddress.Value < owner.VirtualAddress
                || tls.MemorySize > owner.MemorySize
                || tls.TemplateAddress.Value - owner.VirtualAddress
                    > owner.MemorySize - tls.MemorySize
                || tls.TemplateFileOffset.Value - owner.Offset
                    != tls.TemplateAddress.Value - owner.VirtualAddress)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageUnsupported,
                    "HostContext PT_TLS requires a congruent writable PT_LOAD owner and preserved template range.");
                valid = false;
            }
        }

        return valid && !diagnostics.HasErrors;
    }

    public bool ValidateOutput(ElfFile output, RehydrationOptions options, DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(diagnostics);
        var valid = output.Header.Type == ElfConstants.TypeDyn
            && output.Kind == ElfFileKind.SharedObject
            && !output.ProgramHeaders.Any(header => header.Type == ElfConstants.PtInterp);
        if (!valid)
        {
            diagnostics.Error(
                DiagnosticCode.NativeImageMalformed,
                "The HostContext Native Image is not an interpreter-free AArch64 ET_DYN entry image.");
            return false;
        }

        var entryName = options.ExpectedEntrySymbol ?? HostContextContract.EntrySymbol;
        var entry = output.FunctionSymbols
            .Where(symbol => symbol.IsDynamic
                && string.Equals(symbol.Name, entryName, StringComparison.Ordinal)
                && symbol.Size > 0)
            .ToArray();
        if (entry.Length != 1
            || !output.LoadMap.Segments.Any(segment =>
                segment.IsExecutable
                && segment.ContainsVirtualAddress(entry[0].Value, entry[0].Size)))
        {
            diagnostics.Error(
                DiagnosticCode.NativeImageMalformed,
                "The HostContext Native Image lost its bounded executable entry mapping.");
            return false;
        }

        return !diagnostics.HasErrors;
    }
}

/// <summary>Explicit profile dispatch; no profile falls through to another policy.</summary>
public static class ProfileMaterializationPolicies
{
    public static bool TryGet(
        ProtectedImageProfile profile,
        out IProfileMaterializationPolicy? policy,
        DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);
        policy = profile switch
        {
            ProtectedImageProfile.OuterExecveat => new OuterExecveatMaterializationPolicy(),
            ProtectedImageProfile.HostContextEntry => new HostContextEntryMaterializationPolicy(),
            _ => null,
        };
        if (policy is null)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageProfileMismatch, "The Protected Image profile has no current materialization policy.");
            return false;
        }

        return true;
    }
}
