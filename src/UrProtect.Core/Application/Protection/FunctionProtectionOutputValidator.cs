using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.ArtifactProtocol;

namespace UrProtect.Core.Application.Protection;

public sealed partial class FunctionProtectionService
{
    private bool ValidateRewrittenOutput(
        ElfFile source,
        ElfFile rewrittenFile,
        byte[] rewrittenBytes,
        ProtectedCode protectedCode,
        ElfLayoutPlan layoutPlan,
        IReadOnlyList<ElfFunctionSymbol> selected,
        DiagnosticBag diagnostics)
    {
        var changedRanges = selected
            .Where(function => function.TryGetEnd(out _))
            .Select(function =>
            {
                source.LoadMap.TryVirtualAddressToFileOffset(function.Value, function.Size, out var offset);
                return new FileRange(offset, function.Size);
            })
            .ToArray();
        var layoutRanges = layoutPlan.Edits
            .Where(edit => edit.Offset.Value < (ulong)source.Bytes.Length)
            .Select(edit => new FileRange(
                edit.Offset.Value,
                Math.Min((ulong)edit.Bytes.Length, (ulong)source.Bytes.Length - edit.Offset.Value)))
            .ToArray();
        var sourceSpan = source.Bytes.Span;
        var rewrittenSpan = rewrittenBytes.AsSpan();
        if (rewrittenSpan.Length < sourceSpan.Length)
        {
            diagnostics.Error(
                DiagnosticCode.WrapperMalformed,
                "The protected ELF is shorter than the source image.");
            return false;
        }

        for (ulong offset = 0; offset < (ulong)sourceSpan.Length; offset++)
        {
            if (changedRanges.Any(range => range.Contains(offset))
                || layoutRanges.Any(range => range.Contains(offset)))
            {
                continue;
            }

            if (sourceSpan[checked((int)offset)] != rewrittenSpan[checked((int)offset)])
            {
                diagnostics.Error(
                    DiagnosticCode.WrapperMalformed,
                    "The protected layout changed bytes outside selected functions and its planned layout edits.",
                    offset);
                return false;
            }
        }

        foreach (var patch in protectedCode.Patches)
        {
            if (!rewrittenFile.LoadMap.TryVirtualAddressToFileOffset(
                    patch.SourceAddress,
                    patch.SourceSize,
                    out var sourceOffset)
                || sourceOffset > int.MaxValue
                || sourceOffset + patch.SourceSize > (ulong)rewrittenSpan.Length)
            {
                diagnostics.Error(
                    DiagnosticCode.WrapperMalformed,
                    "A transformed function is not file-backed in the rewritten image.",
                    patch.SourceAddress);
                return false;
            }

            var firstWord = BinaryPrimitives.ReadUInt32LittleEndian(
                rewrittenSpan.Slice(checked((int)sourceOffset), sizeof(uint)));
            var decoded = decoder.Decode(firstWord, patch.SourceAddress);
            if (!decoded.IsSuccess
                || decoded.Instruction?.ControlFlow != Aarch64ControlFlowKind.DirectBranch
                || decoded.Instruction.DirectTarget != patch.TargetAddress)
            {
                diagnostics.Error(
                    DiagnosticCode.WrapperMalformed,
                    "A transformed function does not contain the expected entry branch.",
                    patch.SourceAddress);
                return false;
            }

            for (ulong offset = 0; offset < patch.SourceSize; offset += sizeof(uint))
            {
                var instructionEncoding = BinaryPrimitives.ReadUInt32LittleEndian(
                    rewrittenSpan.Slice(checked((int)(sourceOffset + offset)), sizeof(uint)));
                var instruction = decoder.Decode(instructionEncoding, patch.SourceAddress + offset);
                if (!instruction.IsSuccess)
                {
                    diagnostics.Error(
                        DiagnosticCode.WrapperMalformed,
                        "A transformed function could not be decoded after emission.",
                        patch.SourceAddress + offset);
                    return false;
                }
            }
        }

        if (!rewrittenFile.LoadMap.TryVirtualAddressToFileOffset(
                protectedCode.VirtualAddress,
                checked((ulong)protectedCode.Bytes.Length),
                out var protectedOffset)
            || protectedOffset > int.MaxValue
            || protectedOffset + (ulong)protectedCode.Bytes.Length > (ulong)rewrittenSpan.Length)
        {
            diagnostics.Error(
                DiagnosticCode.WrapperMalformed,
                "The emitted protected code is not file-backed in the rewritten image.",
                protectedCode.VirtualAddress);
            return false;
        }

        for (var index = 0; index < protectedCode.Bytes.Length; index += sizeof(uint))
        {
            var encoding = BinaryPrimitives.ReadUInt32LittleEndian(
                rewrittenSpan.Slice(checked((int)protectedOffset + index), sizeof(uint)));
            var address = protectedCode.VirtualAddress + checked((ulong)index);
            if (!decoder.Decode(encoding, address).IsSuccess)
            {
                diagnostics.Error(
                    DiagnosticCode.WrapperMalformed,
                    "The emitted protected code could not be decoded after publication.",
                    address);
                return false;
            }
        }

        return true;
    }

}
