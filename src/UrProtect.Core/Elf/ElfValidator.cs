using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.Elf;

public static class ElfValidator
{
    public static ElfValidationReport Validate(ElfFile file)
    {
        ArgumentNullException.ThrowIfNull(file);
        var diagnostics = new DiagnosticBag();
        if (!file.Header.IsAarch64)
        {
            diagnostics.Error(DiagnosticCode.UnsupportedMachine, "The ELF machine is not AArch64.");
        }

        if (file.Header.Type is not (ElfConstants.TypeDyn or ElfConstants.TypeExec))
        {
            diagnostics.Error(DiagnosticCode.UnsupportedFileType, "Only ET_DYN and ET_EXEC are supported.");
        }

        if (file.LoadMap.Segments.Count == 0)
        {
            diagnostics.Error(DiagnosticCode.MissingLoadSegment, "The ELF has no PT_LOAD segment.");
        }

        if (file.ProgramHeaders.Count(header => header.Type == ElfConstants.PtInterp) > 1)
        {
            diagnostics.Error(
                DiagnosticCode.InvalidProgramHeader,
                "The ELF has multiple PT_INTERP segments.");
        }

        var requiresDynamicSegment = file.Kind is ElfFileKind.PieExecutable
            or ElfFileKind.StaticPieExecutable
            or ElfFileKind.DynamicExecutable
            or ElfFileKind.SharedObject;
        if (requiresDynamicSegment && !file.ProgramHeaders.Any(header => header.Type == ElfConstants.PtDynamic))
        {
            diagnostics.Error(
                DiagnosticCode.MissingDynamicSegment,
                "A dynamic executable or shared object requires a PT_DYNAMIC segment.");
        }

        if ((file.Kind is ElfFileKind.PieExecutable
            or ElfFileKind.StaticPieExecutable
            or ElfFileKind.DynamicExecutable
            or ElfFileKind.StaticExecutable)
            && !file.LoadMap.Segments.Any(segment =>
                segment.IsExecutable && segment.ContainsVirtualAddress(file.Header.Entry, sizeof(uint))))
        {
            diagnostics.Error(
                DiagnosticCode.AddressUnmapped,
                "The executable entry point is not inside an executable PT_LOAD segment.",
                file.Header.Entry);
        }

        foreach (var segment in file.LoadMap.Segments)
        {
            if (segment.FileSize > segment.MemorySize)
            {
                diagnostics.Error(
                    DiagnosticCode.InvalidSegment,
                    "A load segment's file size exceeds its memory size.",
                    segment.FileOffset);
            }
        }

        foreach (var relocation in file.RelaRelocations)
        {
            if (relocation.Kind == Aarch64RelocationKind.Unknown)
            {
                var diagnosticOffset = file.LoadMap.TryVirtualAddressToFileOffset(
                    relocation.SourceAddress,
                    out var sourceOffset)
                    ? sourceOffset
                    : (ulong?)null;
                diagnostics.Warning(
                    DiagnosticCode.UnsupportedRelocation,
                    $"AArch64 relocation type {relocation.Type} is preserved but not semantically classified.",
                    diagnosticOffset);
            }
        }

        return new ElfValidationReport(diagnostics.ToArray());
    }
}
