using System.Buffers.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Aarch64;

public readonly record struct InstructionCandidate(
    ulong FileOffset,
    ulong VirtualAddress,
    uint Encoding,
    Aarch64DecodeResult Decode);

public sealed record Aarch64AnalysisReport(
    IReadOnlyList<InstructionCandidate> Candidates,
    IReadOnlyList<Diagnostic> Diagnostics);

public sealed class Aarch64Analyzer
{
    private const ulong MaxInstructionsPerRegion = 1_000_000;
    private readonly IAarch64Decoder decoder;

    public Aarch64Analyzer(IAarch64Decoder decoder)
    {
        this.decoder = decoder ?? throw new ArgumentNullException(nameof(decoder));
    }

    public Aarch64AnalysisReport Analyze(ElfFile file)
    {
        ArgumentNullException.ThrowIfNull(file);
        var candidates = new List<InstructionCandidate>();
        var diagnostics = new DiagnosticBag();

        foreach (var start in FindStarts(file))
        {
            var segment = start.Segment;
            if (start.VirtualAddress < segment.VirtualAddress)
            {
                continue;
            }

            var segmentDelta = start.VirtualAddress - segment.VirtualAddress;
            if (segmentDelta >= segment.FileSize
                || segmentDelta % sizeof(uint) != 0)
            {
                continue;
            }

            var remainingBytes = segment.FileSize - segmentDelta;
            var instructionCount = Math.Min(
                remainingBytes / sizeof(uint),
                MaxInstructionsPerRegion);
            for (ulong index = 0; index < instructionCount; index++)
            {
                ulong fileOffset = default;
                if (!TryAdd(segment.FileOffset, segmentDelta, out var firstFileOffset)
                    || !TryMultiply(index, sizeof(uint), out var instructionDelta)
                    || !TryAdd(firstFileOffset, instructionDelta, out fileOffset)
                    || fileOffset > int.MaxValue
                    || fileOffset > (ulong)file.Bytes.Length - sizeof(uint))
                {
                    diagnostics.Error(
                        DiagnosticCode.TableOutOfBounds,
                        "An executable segment instruction range is outside the input.",
                        fileOffset);
                    break;
                }

                if (!TryAdd(start.VirtualAddress, instructionDelta, out var virtualAddress))
                {
                    diagnostics.Error(
                        DiagnosticCode.AddressOverflow,
                        "An executable instruction address overflowed.",
                        fileOffset);
                    break;
                }

                var encoding = BinaryPrimitives.ReadUInt32LittleEndian(
                    file.Bytes.Span.Slice((int)fileOffset, sizeof(uint)));
                var decode = decoder.Decode(encoding, virtualAddress);
                candidates.Add(new InstructionCandidate(
                    fileOffset,
                    virtualAddress,
                    encoding,
                    decode));

                if (decode.Status == Aarch64DecodeStatus.UnknownEncoding)
                {
                    diagnostics.Warning(
                        DiagnosticCode.UnknownInstruction,
                        decode.Diagnostic,
                        fileOffset);
                    break;
                }

                if (decode.Status == Aarch64DecodeStatus.UnsupportedFeature)
                {
                    diagnostics.Warning(
                        DiagnosticCode.UnsupportedInstructionFeature,
                        decode.Diagnostic,
                        fileOffset);
                    break;
                }

                if (decode.Status == Aarch64DecodeStatus.BackendUnavailable)
                {
                    diagnostics.Error(
                        DiagnosticCode.AsmStoneUnavailable,
                        decode.Diagnostic,
                        fileOffset);
                    break;
                }

                if (decode.Instruction is { } instruction
                    && (instruction.Properties.HasFlag(Aarch64InstructionProperties.Terminator)
                        || instruction.ControlFlow is Aarch64ControlFlowKind.IndirectBranch
                            or Aarch64ControlFlowKind.Return))
                {
                    break;
                }
            }
        }

        return new Aarch64AnalysisReport(candidates, diagnostics.ToArray());
    }

    private static IEnumerable<(LoadSegment Segment, ulong VirtualAddress)> FindStarts(ElfFile file)
    {
        var starts = new HashSet<ulong>();
        if (file.Header.Entry != 0)
        {
            starts.Add(file.Header.Entry);
        }

        foreach (var symbol in file.DynamicSymbols)
        {
            if (symbol.Value != 0)
            {
                starts.Add(symbol.Value);
            }
        }

        foreach (var relocation in file.RelaRelocations)
        {
            if (relocation.Offset != 0)
            {
                starts.Add(relocation.Offset);
            }
        }

        foreach (var virtualAddress in starts)
        {
            var segment = file.LoadMap.Segments.FirstOrDefault(candidate =>
                candidate.IsExecutable && candidate.ContainsVirtualAddress(virtualAddress));
            if (segment.IsExecutable)
            {
                yield return (segment, virtualAddress);
            }
        }
    }

    private static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        result = left + right;
        return result >= left;
    }

    private static bool TryMultiply(ulong left, ulong right, out ulong result)
    {
        if (left != 0 && right > ulong.MaxValue / left)
        {
            result = default;
            return false;
        }

        result = left * right;
        return true;
    }
}
