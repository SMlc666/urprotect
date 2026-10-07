using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.ArtifactProtocol;

namespace UrProtect.Core.Application.Protection;

internal static class FunctionProtectionSelectionValidator
{
    internal static void ValidateSelectedRanges(
        ElfFile file,
        IReadOnlyList<ElfFunctionSymbol> selected,
        DiagnosticBag diagnostics)
    {
        for (var index = 0; index < selected.Count; index++)
        {
            var function = selected[index];
            if (!function.TryGetEnd(out var end))
            {
                diagnostics.Error(
                    DiagnosticCode.FunctionResourceUnavailable,
                    $"Function '{function.Name}' has an overflowing symbol range.",
                    function.Value);
                continue;
            }

            var segments = file.LoadMap.Segments
                .Where(segment => segment.IsExecutable && segment.ContainsVirtualAddress(function.Value, function.Size))
                .ToArray();
            if (segments.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.FunctionResourceUnavailable,
                    $"Function '{function.Name}' must be wholly contained in exactly one executable load segment.",
                    function.Value);
            }

            for (var otherIndex = index + 1; otherIndex < selected.Count; otherIndex++)
            {
                var other = selected[otherIndex];
                if (!other.TryGetEnd(out var otherEnd))
                {
                    continue;
                }

                if (function.Value < otherEnd
                    && other.Value < end
                    && !(function.Value == other.Value && function.Size == other.Size))
                {
                    diagnostics.Error(
                        DiagnosticCode.FunctionResourceUnavailable,
                        $"Selected function ranges '{function.Name}' and '{other.Name}' overlap.",
                        function.Value);
                }
            }

            foreach (var other in file.FunctionSymbols)
            {
                if (other.Table == function.Table && other.TableIndex == function.TableIndex
                    || !other.TryGetEnd(out var otherEnd)
                    || (function.Value == other.Value && function.Size == other.Size))
                {
                    continue;
                }

                if (function.Value < otherEnd && other.Value < end)
                {
                    diagnostics.Error(
                        DiagnosticCode.FunctionResourceUnavailable,
                        $"Selected function '{function.Name}' overlaps an unselected symbol '{other.Name}'; transformation would change an unselected function.",
                        function.Value);
                }
            }
        }
    }

}
