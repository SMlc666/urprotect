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

        if (!file.Header.IsDynamic)
        {
            diagnostics.Error(DiagnosticCode.UnsupportedFileType, "Only ET_DYN is supported.");
        }

        if (file.LoadMap.Segments.Count == 0)
        {
            diagnostics.Error(DiagnosticCode.MissingLoadSegment, "The ELF has no PT_LOAD segment.");
        }

        if (!file.ProgramHeaders.Any(header => header.Type == ElfConstants.PtDynamic))
        {
            diagnostics.Error(
                DiagnosticCode.MissingDynamicSegment,
                "The supported ET_DYN profile requires a PT_DYNAMIC segment.");
        }

        if (file.Kind == ElfFileKind.PieExecutable
            && !file.LoadMap.Segments.Any(segment =>
                segment.IsExecutable && segment.ContainsVirtualAddress(file.Header.Entry, sizeof(uint))))
        {
            diagnostics.Error(
                DiagnosticCode.AddressUnmapped,
                "The PIE entry point is not inside an executable PT_LOAD segment.",
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

        return new ElfValidationReport(diagnostics.ToArray());
    }
}
