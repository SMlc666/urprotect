using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;

namespace UrProtect.Core.ElfLayout;

internal static class ElfLayoutBranchEncoding
{
    private const uint BranchOpcodeMask = 0xFC000000u;
    private const uint BranchOpcode = 0x14000000u;
    private const uint CallOpcode = 0x94000000u;
    private static readonly Aarch64InstructionEncoder InstructionEncoder = new();

    public static bool IsBranchOpcode(uint opcode) =>
        (opcode & BranchOpcodeMask) is BranchOpcode or CallOpcode;

    public static bool TryEncode(
        uint opcode,
        ulong source,
        ulong target,
        out byte[] encoding,
        out long? displacement)
    {
        encoding = Array.Empty<byte>();
        displacement = null;
        if (!IsBranchOpcode(opcode)
            || (source & 3) != 0
            || (target & 3) != 0
            || !TryGetDisplacement(source, target, out var delta)
            || delta < ElfLayoutLimits.Branch26MinimumDisplacement
            || delta >= ElfLayoutLimits.Branch26MaximumDisplacementExclusive)
        {
            return false;
        }

        var family = (opcode & BranchOpcodeMask) == CallOpcode
            ? Aarch64InstructionEncodingFamily.Call26
            : Aarch64InstructionEncodingFamily.Branch26;
        var result = InstructionEncoder.TryEncode(new Aarch64InstructionEncodeRequest(
            SourceEncoding: opcode,
            SourceAddress: source,
            OutputAddress: source,
            Family: family,
            TargetOrImmediate: target));
        if (!result.IsSuccess)
        {
            return false;
        }

        encoding = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(encoding, result.Encoding);
        displacement = delta;
        return true;
    }

    private static bool TryGetDisplacement(ulong source, ulong target, out long displacement)
    {
        if (target >= source)
        {
            var delta = target - source;
            if (delta > long.MaxValue)
            {
                displacement = 0;
                return false;
            }

            displacement = (long)delta;
            return true;
        }

        var reverse = source - target;
        if (reverse > (ulong)long.MaxValue + 1)
        {
            displacement = 0;
            return false;
        }

        displacement = reverse == (ulong)long.MaxValue + 1
            ? long.MinValue
            : -(long)reverse;
        return true;
    }
}
