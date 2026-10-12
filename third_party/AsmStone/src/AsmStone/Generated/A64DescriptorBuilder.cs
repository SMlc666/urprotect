using AsmStone.Model;

namespace AsmStone.Generated;

internal static class A64DescriptorBuilder
{
    public static A64InstructionDescriptor Build(
        A64CompiledInstruction instruction,
        A64InstructionCode code)
    {
        var fields = new A64FieldDescriptor[instruction.Fields.Length];
        for (var index = 0; index < instruction.Fields.Length; index++)
        {
            var field = instruction.Fields[index];
            var mappings = field.Mappings
                .Select(mapping => new A64FieldBitMapping(
                    mapping.EncodingBit,
                    mapping.FieldBit))
                .ToArray();
            fields[index] = new A64FieldDescriptor(
                new A64FieldId(index),
                field.Name,
                field.Width,
                field.IsContiguous,
                field.EncodingShift,
                field.FieldShift,
                field.ValueMask,
                mappings);
        }

        var operands = instruction.Bindings
            .Select(binding => BuildOperand(instruction, binding))
            .ToArray();

        A64MemoryDescriptor? memory = null;
        if (instruction.Memory is { } memoryBinding)
        {
            memory = new A64MemoryDescriptor(
                FieldId(memoryBinding.BaseFieldIndex),
                FieldId(memoryBinding.OffsetFieldIndex),
                FieldId(memoryBinding.IndexFieldIndex),
                FieldId(memoryBinding.ModifierFieldIndex),
                memoryBinding.FixedOffset,
                memoryBinding.Mode,
                A64GeneratedMemory.AccessSize(instruction),
                A64GeneratedMemory.Ordering(instruction))
            {
                BaseName = memoryBinding.BaseName,
                OffsetName = memoryBinding.OffsetName,
                IndexName = memoryBinding.IndexName,
                ModifierName = memoryBinding.ModifierName,
            };
        }

        return new A64InstructionDescriptor(
            code,
            instruction.Info.Name,
            instruction.Info.Mnemonic,
            instruction.Info.Mask,
            instruction.Info.Value,
            instruction.Info.Flags,
            instruction.Info.HasCompleteEncoding,
            DecoderRule(instruction.Source.DecoderMethod),
            instruction.Predicates,
            fields,
            operands,
            memory,
            instruction.Info.Assembly);
    }

    private static A64OperandDescriptor BuildOperand(
        A64CompiledInstruction instruction,
        A64CompiledBinding binding)
    {
        return new A64OperandDescriptor(
            binding.Name,
            Kind(binding.Kind),
            binding.Direction,
            binding.IsImplicit,
            FieldId(binding.FieldIndex),
            FieldId(binding.SecondaryFieldIndex),
            binding.RegisterClass,
            binding.RegisterConstraint,
            binding.RegisterWidth,
            binding.FieldWidth,
            binding.ElementWidth,
            binding.ShapeCount,
            binding.LaneCount,
            binding.GroupStride,
            binding.RegisterIndexBias,
            binding.RegisterIndexScale,
            binding.Scale,
            binding.IsSigned,
            binding.AllowsStackPointer,
            binding.AllowsZeroRegister,
            binding.ImmediateSemanticKind,
            binding.EnumKind,
            binding.PredicateMode,
            binding.MatrixRegisterKind,
            binding.FixedModifierKind,
            binding.FixedModifierAmount,
            binding.FractionalBits,
            PcRelative(binding),
            binding.TiedTo,
            binding.Type,
            Codec(binding.Codec));
    }

    private static A64FieldId FieldId(int index)
    {
        return index < 0 ? A64FieldId.Invalid : new A64FieldId(index);
    }

    private static A64OperandCodecDescriptor Codec(A64GeneratedOperand? codec)
    {
        return codec is null
            ? new A64OperandCodecDescriptor(
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty)
            : new A64OperandCodecDescriptor(
                codec.Name,
                codec.OperandType,
                codec.DecoderMethod,
                codec.EncoderMethod,
                codec.PrintMethod,
                codec.ParserMatchClass,
                codec.RegClass,
                codec.ElementSize,
                codec.Type);
    }

    private static A64OperandKind Kind(A64CompiledOperandKind kind)
    {
        return kind switch
        {
            A64CompiledOperandKind.Register => A64OperandKind.Register,
            A64CompiledOperandKind.VectorList => A64OperandKind.VectorRegisterList,
            A64CompiledOperandKind.RegisterGroup => A64OperandKind.RegisterGroup,
            A64CompiledOperandKind.RegisterPair => A64OperandKind.RegisterPair,
            A64CompiledOperandKind.SystemRegister => A64OperandKind.SystemRegister,
            A64CompiledOperandKind.MatrixTileMask => A64OperandKind.MatrixTileMask,
            A64CompiledOperandKind.MatrixRegister => A64OperandKind.MatrixRegister,
            A64CompiledOperandKind.ModifiedRegister => A64OperandKind.ModifiedRegister,
            A64CompiledOperandKind.RegisterModifier => A64OperandKind.RegisterModifier,
            A64CompiledOperandKind.PcRelative => A64OperandKind.Target,
            A64CompiledOperandKind.FloatingImmediate => A64OperandKind.FloatingImmediate,
            A64CompiledOperandKind.EncodedField => A64OperandKind.EncodedField,
            _ => A64OperandKind.Immediate,
        };
    }

    private static A64PcRelativeInfo PcRelative(A64CompiledBinding binding)
    {
        if (binding.Kind != A64CompiledOperandKind.PcRelative)
        {
            return A64PcRelativeInfo.None;
        }

        var kind = binding.Type switch
        {
            "adrlabel" => A64PcRelativeKind.Adr21,
            "adrplabel" => A64PcRelativeKind.Adrp21,
            "am_b_target" => A64PcRelativeKind.Branch26,
            "am_bl_target" => A64PcRelativeKind.Branch26,
            "am_brcmpcond" => A64PcRelativeKind.Branch9,
            "am_brcond" => A64PcRelativeKind.Branch19,
            "am_tbrcond" => A64PcRelativeKind.Branch14,
            "am_ldrlit" => A64PcRelativeKind.Literal19,
            "am_pauth_pcrel" => A64PcRelativeKind.PAuth16,
            _ => A64PcRelativeKind.Generic,
        };

        var relocation = binding.Type switch
        {
            "adrlabel" => A64RelocationKind.AArch64AdrPrelLo21,
            "adrplabel" => A64RelocationKind.AArch64AdrpPage21,
            "am_b_target" => A64RelocationKind.AArch64Jump26,
            "am_bl_target" => A64RelocationKind.AArch64Call26,
            "am_brcmpcond" => A64RelocationKind.AArch64Condbr9,
            "am_brcond" => A64RelocationKind.AArch64Condbr19,
            "am_tbrcond" => A64RelocationKind.AArch64Tstbr14,
            "am_ldrlit" => A64RelocationKind.AArch64LdPrelLo19,
            "am_pauth_pcrel" => A64RelocationKind.AArch64PAuth,
            _ => A64RelocationKind.None,
        };

        return new A64PcRelativeInfo(
            kind,
            binding.FieldWidth,
            binding.PcRelativeScale,
            1 << binding.PcRelativeScale,
            binding.IsPageRelative,
            relocation);
    }

    private static A64DecoderRuleKind DecoderRule(string decoderMethod)
    {
        return decoderMethod switch
        {
            "" => A64DecoderRuleKind.None,
            "DecodeAddSubImmShift" => A64DecoderRuleKind.AddSubImmediate,
            "DecodeMoveImmInstruction" => A64DecoderRuleKind.MoveWideImmediate,
            "DecodeAddSubERegInstruction" => A64DecoderRuleKind.AddSubExtendedRegister,
            "DecodeThreeAddrSRegInstruction" => A64DecoderRuleKind.ShiftedRegister,
            "DecodeSystemPStateImm0_15Instruction"
                or "DecodeSystemPStateImm0_1Instruction"
                => A64DecoderRuleKind.SystemPStateImmediate,
            "DecodeCPYMemOpInstruction" => A64DecoderRuleKind.CopyMemory,
            "DecodeSETMemOpInstruction" => A64DecoderRuleKind.SetMemory,
            "DecodeSETMemGoOpInstruction" => A64DecoderRuleKind.SetMemoryGo,
            "DecodeLogicalImmInstruction" => A64DecoderRuleKind.LogicalImmediate,
            "DecodeSVELogicalImmInstruction" => A64DecoderRuleKind.SveLogicalImmediate,
            "DecodeUnconditionalBranch" => A64DecoderRuleKind.UnconditionalBranch,
            "DecodeAdrInstruction" => A64DecoderRuleKind.Adr,
            "DecodeTestAndBranch" => A64DecoderRuleKind.TestAndBranch,
            _ => A64DecoderRuleKind.Unknown,
        };
    }
}
