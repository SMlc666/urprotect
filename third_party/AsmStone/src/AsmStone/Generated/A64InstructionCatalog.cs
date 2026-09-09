using AsmStone.Encoding;
using AsmStone.Model;

namespace AsmStone.Generated;

public readonly record struct A64EncodingInfo(
    string Name,
    string Mnemonic,
    uint Mask,
    uint Value,
    string Assembly,
    string DecoderMethod,
    string Predicates,
    string VariableFields,
    string FieldEncoding,
    string OperandBindings,
    string InputOperands,
    string OutputOperands,
    string Constraints,
    bool HasCompleteEncoding,
    A64InstructionFlags Flags);

public readonly record struct A64FieldValue(string Name, uint Value, int Width = 0);

public sealed record A64DecodedEncoding(
    A64EncodingInfo Encoding,
    IReadOnlyList<A64FieldValue> Fields)
{
    internal A64CompiledInstruction Metadata { get; } = default!;

    internal A64DecodedEncoding(
        A64EncodingInfo encoding,
        IReadOnlyList<A64FieldValue> fields,
        A64CompiledInstruction metadata)
        : this(encoding, fields)
    {
        Metadata = metadata;
    }
}

public readonly record struct A64OperandEncodingInfo(
    string Name,
    string OperandType,
    string DecoderMethod,
    string EncoderMethod,
    string PrintMethod,
    string ParserMatchClass,
    string RegisterClass,
    string ElementSize,
    string ValueType);

public static class A64InstructionCatalog
{
    private static readonly IReadOnlyDictionary<string, A64GeneratedOperand> byOperandName =
        A64GeneratedOperandTable.All.ToDictionary(operand => operand.Name, StringComparer.Ordinal);
    private static readonly A64CompiledInstruction[] compiled = BuildCompiled();
    private static readonly int[] bucketOffsets;
    private static readonly int[] bucketCandidates;

    public static int Count => A64GeneratedInstructionTable.All.Length;

    public static int OperandTypeCount => A64GeneratedOperandTable.All.Length;

    public static string SourceCommit => A64GeneratedInstructionTable.SourceCommit;

    public static string TablegenInputSha256 => A64GeneratedInstructionTable.TablegenInputSha256;

    public static int SourceRecordCount => A64GeneratedInstructionTable.SourceRecordCount;

    public static int SourceCompleteEncodingCount => A64GeneratedInstructionTable.SourceCompleteEncodingCount;

    public static int SourceOperandTypeCount => A64GeneratedInstructionTable.SourceOperandTypeCount;

    public static IEnumerable<A64EncodingInfo> Enumerate()
    {
        foreach (var candidate in A64GeneratedInstructionTable.All)
        {
            yield return ToEncodingInfo(candidate);
        }
    }

    public static bool TryLookup(uint encoding, out A64EncodingInfo info)
    {
        return TryLookup(encoding, A64FeatureSet.All, out info);
    }

    public static bool TryLookup(
        uint encoding,
        A64FeatureSet features,
        out A64EncodingInfo info)
    {
        ArgumentNullException.ThrowIfNull(features);
        if (TryGetExact(encoding, out var exactCandidate))
        {
            if (features.SupportsAll(exactCandidate.Predicates)
                && A64GeneratedDecoderConstraints.Accept(exactCandidate, encoding, features))
            {
                info = exactCandidate.Info;
                return true;
            }

            info = default;
            return false;
        }

        var bucket = GetBucket(encoding);
        for (var bucketIndex = bucket.Start; bucketIndex < bucket.End; bucketIndex++)
        {
            var candidate = compiled[bucketCandidates[bucketIndex]];
            var source = candidate.Source;
            if (!source.HasCompleteEncoding
                || (encoding & source.Mask) != source.Value
                || !features.SupportsAll(candidate.Predicates)
                || !A64GeneratedDecoderConstraints.Accept(candidate, encoding, features))
            {
                continue;
            }

            info = candidate.Info;
            return true;
        }

        info = default;
        return false;
    }

    public static bool TryFindUnsupported(
        uint encoding,
        A64FeatureSet features,
        out A64EncodingInfo info)
    {
        ArgumentNullException.ThrowIfNull(features);
        if (TryGetExact(encoding, out var exactCandidate))
        {
            if (!features.SupportsAll(exactCandidate.Predicates)
                && A64GeneratedDecoderConstraints.Accept(exactCandidate, encoding, features))
            {
                info = exactCandidate.Info;
                return true;
            }

            info = default;
            return false;
        }

        var bucket = GetBucket(encoding);
        for (var bucketIndex = bucket.Start; bucketIndex < bucket.End; bucketIndex++)
        {
            var candidate = compiled[bucketCandidates[bucketIndex]];
            var source = candidate.Source;
            if (!source.HasCompleteEncoding
                || (encoding & source.Mask) != source.Value
                || features.SupportsAll(candidate.Predicates)
                || !A64GeneratedDecoderConstraints.Accept(candidate, encoding, features))
            {
                continue;
            }

            info = candidate.Info;
            return true;
        }

        info = default;
        return false;
    }

    public static bool TryGetByName(string name, out A64EncodingInfo info)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (byCompiledName.TryGetValue(name, out var candidate))
        {
            info = candidate.Info;
            return true;
        }

        info = default;
        return false;
    }

    public static bool TryDecode(uint encoding, out A64DecodedEncoding decoded)
    {
        return TryDecode(encoding, A64FeatureSet.All, out decoded);
    }

    public static bool TryDecode(
        uint encoding,
        A64FeatureSet features,
        out A64DecodedEncoding decoded)
    {
        if (!TryFindCompiled(encoding, features, out var candidate))
        {
            decoded = default!;
            return false;
        }

        var fields = new A64FieldValue[candidate.Fields.Length];
        for (var index = 0; index < candidate.Fields.Length; index++)
        {
            var field = candidate.Fields[index];
            field.TryRead(encoding, out var value);
            fields[index] = new A64FieldValue(field.Name, value, field.Width);
        }

        decoded = new A64DecodedEncoding(candidate.Info, fields, candidate);
        return true;
    }

    public static bool TryEncodeFields(
        string name,
        IReadOnlyDictionary<string, uint> fields,
        A64FeatureSet features,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(features);
        encoding = 0;
        diagnostic = A64Diagnostic.None;
        if (!byCompiledName.TryGetValue(name, out var candidate))
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.InvalidInstruction,
                $"Generated instruction '{name}' was not found.");
            return false;
        }

        var source = candidate.Source;
        if (!source.HasCompleteEncoding)
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.InvalidInstruction,
                $"Generated instruction '{name}' has a partial encoding.");
            return false;
        }

        if (!features.SupportsAll(candidate.Predicates))
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.UnsupportedFeature,
                $"Generated instruction '{name}' requires predicates: {source.Predicates}.");
            return false;
        }

        foreach (var field in fields.Keys)
        {
            if (!candidate.TryGetField(field, out var fieldSpec)
                || fieldSpec.Mappings.Length == 0)
            {
                diagnostic = new A64Diagnostic(
                    A64DiagnosticCode.InvalidOperand,
                    $"Generated instruction '{name}' has no encoded field named '{field}'.");
                return false;
            }
        }

        foreach (var field in candidate.Fields)
        {
            if (!fields.ContainsKey(field.Name))
            {
                diagnostic = new A64Diagnostic(
                    A64DiagnosticCode.InvalidOperand,
                    $"Generated instruction '{name}' requires encoded field '{field.Name}'.");
                return false;
            }
        }

        encoding = source.Value;
        foreach (var field in fields)
        {
            candidate.TryGetField(field.Key, out var fieldSpec);
            var width = fieldSpec.Width;
            if (width < 32 && (field.Value >> width) != 0)
            {
                encoding = 0;
                diagnostic = new A64Diagnostic(
                    A64DiagnosticCode.OutOfRange,
                    $"Generated field '{field.Key}' does not fit {width} bits.");
                return false;
            }

            foreach (var mapping in fieldSpec.Mappings)
            {
                var bit = (field.Value >> mapping.FieldBit) & 1u;
                encoding = (encoding & ~(1u << mapping.EncodingBit)) | (bit << mapping.EncodingBit);
            }
        }

        return true;
    }

    public static bool TryEncodeFields(
        string name,
        ReadOnlySpan<A64FieldValue> fields,
        A64FeatureSet features,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(features);
        encoding = 0;
        diagnostic = A64Diagnostic.None;
        if (!byCompiledName.TryGetValue(name, out var candidate))
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.InvalidInstruction,
                $"Generated instruction '{name}' was not found.");
            return false;
        }

        var source = candidate.Source;
        if (!source.HasCompleteEncoding)
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.InvalidInstruction,
                $"Generated instruction '{name}' has a partial encoding.");
            return false;
        }

        if (!features.SupportsAll(candidate.Predicates))
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.UnsupportedFeature,
                $"Generated instruction '{name}' requires predicates: {source.Predicates}.");
            return false;
        }

        for (var index = 0; index < fields.Length; index++)
        {
            var field = fields[index];
            if (!candidate.TryGetField(field.Name, out var fieldSpec)
                || fieldSpec.Mappings.Length == 0)
            {
                diagnostic = new A64Diagnostic(
                    A64DiagnosticCode.InvalidOperand,
                    $"Generated instruction '{name}' has no encoded field named '{field.Name}'.");
                return false;
            }

            for (var duplicate = index + 1; duplicate < fields.Length; duplicate++)
            {
                if (string.Equals(fields[duplicate].Name, field.Name, StringComparison.Ordinal))
                {
                    diagnostic = new A64Diagnostic(
                        A64DiagnosticCode.InvalidOperand,
                        $"Generated instruction '{name}' received duplicate encoded field '{field.Name}'.");
                    return false;
                }
            }
        }

        for (var index = 0; index < candidate.Fields.Length; index++)
        {
            var expected = candidate.Fields[index].Name;
            var found = false;
            for (var fieldIndex = 0; fieldIndex < fields.Length; fieldIndex++)
            {
                if (string.Equals(fields[fieldIndex].Name, expected, StringComparison.Ordinal))
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                diagnostic = new A64Diagnostic(
                    A64DiagnosticCode.InvalidOperand,
                    $"Generated instruction '{name}' requires encoded field '{expected}'.");
                return false;
            }
        }

        encoding = source.Value;
        for (var index = 0; index < fields.Length; index++)
        {
            var input = fields[index];
            candidate.TryGetField(input.Name, out var fieldSpec);
            var width = fieldSpec.Width;
            if (width < 32 && (input.Value >> width) != 0)
            {
                encoding = 0;
                diagnostic = new A64Diagnostic(
                    A64DiagnosticCode.OutOfRange,
                    $"Generated field '{input.Name}' does not fit {width} bits.");
                return false;
            }

            for (var mappingIndex = 0; mappingIndex < fieldSpec.Mappings.Length; mappingIndex++)
            {
                var mapping = fieldSpec.Mappings[mappingIndex];
                var bit = (input.Value >> mapping.FieldBit) & 1u;
                encoding = (encoding & ~(1u << mapping.EncodingBit)) | (bit << mapping.EncodingBit);
            }
        }

        return true;
    }

    public static bool TryEncodeFields(
        string name,
        ReadOnlySpan<A64FieldValue> fields,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        return TryEncodeFields(name, fields, A64FeatureSet.All, out encoding, out diagnostic);
    }

    public static bool TryEncodeFields(
        string name,
        IReadOnlyDictionary<string, uint> fields,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        return TryEncodeFields(name, fields, A64FeatureSet.All, out encoding, out diagnostic);
    }

    internal static bool TryGetCompiledByName(
        string name,
        out A64CompiledInstruction instruction)
    {
        ArgumentNullException.ThrowIfNull(name);
        return byCompiledName.TryGetValue(name, out instruction!);
    }

    internal static bool TryFindCompiled(
        uint encoding,
        A64FeatureSet features,
        out A64CompiledInstruction instruction)
    {
        ArgumentNullException.ThrowIfNull(features);
        if (TryGetExact(encoding, out var exactCandidate))
        {
            if (features.SupportsAll(exactCandidate.Predicates)
                && A64GeneratedDecoderConstraints.Accept(exactCandidate, encoding, features))
            {
                instruction = exactCandidate;
                return true;
            }

            instruction = default!;
            return false;
        }

        var bucket = GetBucket(encoding);
        for (var bucketIndex = bucket.Start; bucketIndex < bucket.End; bucketIndex++)
        {
            var candidate = compiled[bucketCandidates[bucketIndex]];
            var source = candidate.Source;
            if (!source.HasCompleteEncoding
                || (encoding & source.Mask) != source.Value
                || !features.SupportsAll(candidate.Predicates)
                || !A64GeneratedDecoderConstraints.Accept(candidate, encoding, features))
            {
                continue;
            }

            instruction = candidate;
            return true;
        }

        instruction = default!;
        return false;
    }

    private static A64CompiledInstruction[] BuildCompiled()
    {
        var result = new A64CompiledInstruction[A64GeneratedInstructionTable.All.Length];
        for (var index = 0; index < result.Length; index++)
        {
            var source = A64GeneratedInstructionTable.All[index];
            var info = ToEncodingInfo(source);
            var fields = ParseFields(source.FieldEncoding);
            var bindings = ParseBindings(source.OperandBindings, fields, source.Assembly);
            var ties = ParseTies(source.Constraints);
            for (var bindingIndex = 0; bindingIndex < bindings.Length; bindingIndex++)
            {
                var binding = bindings[bindingIndex];
                var tiedTo = ties.TryGetValue(binding.Name, out var explicitTie)
                    ? explicitTie
                    : binding.Name.StartsWith('_')
                        ? binding.Name[1..]
                        : binding.Name == "offset"
                            && binding.Type == "imm32_0_15"
                            && IndexOfBinding(bindings, "imm4") >= 0
                            ? "imm4"
                            : null;
                if (tiedTo is not null)
                {
                    bindings[bindingIndex] = binding with { TiedTo = tiedTo };
                }
            }
            var contextualElementWidth = bindings
                .Where(binding => binding.RegisterClass == A64RegisterClass.SveVector)
                .Select(binding => binding.ElementWidth)
                .FirstOrDefault(width => width != 0);
            if (contextualElementWidth != 0)
            {
                bindings = bindings
                    .Select(binding => binding.RegisterClass == A64RegisterClass.Predicate
                        && binding.ElementWidth == 0
                        ? binding with { ElementWidth = contextualElementWidth }
                        : binding)
                    .ToArray();
            }
        var predicates = source.Predicates.Length == 0
            ? Array.Empty<string>()
            : source.Predicates.Split('|', StringSplitOptions.RemoveEmptyEntries);
            var memory = A64GeneratedMemory.TryGet(info, out var memoryBinding)
                ? CompileMemory(memoryBinding, fields, bindings)
                : (A64GeneratedMemoryBinding?)null;
            var operandCount = CountOperands(fields, bindings, memory);
            var uncollapsedOperandCount = CountOperands(fields, bindings, null);
            result[index] = new A64CompiledInstruction(
                source,
                info,
                fields,
                bindings,
                predicates,
                operandCount,
                uncollapsedOperandCount,
                memory);
        }

        return result;
    }

    private static bool TryGetExact(uint encoding, out A64CompiledInstruction candidate)
    {
        if (A64GeneratedInstructionTable.TryGetExact(encoding, out var index))
        {
            candidate = compiled[index];
            return true;
        }

        candidate = default!;
        return false;
    }

    private static A64CompiledField[] ParseFields(string encodingMap)
    {
        var fields = new List<A64CompiledField>();
        foreach (var field in encodingMap.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = field.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            var mappings = new List<A64CompiledFieldMapping>();
            foreach (var mapping in field[(separator + 1)..].Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = mapping.Split(':');
                if (parts.Length == 2
                    && int.TryParse(parts[0], out var encodingBit)
                    && int.TryParse(parts[1], out var fieldBit)
                    && encodingBit is >= 0 and <= 31
                    && fieldBit is >= 0 and <= 31)
                {
                    mappings.Add(new A64CompiledFieldMapping(encodingBit, fieldBit));
                }
            }

            if (mappings.Count != 0)
            {
                fields.Add(new A64CompiledField(field[..separator], mappings.ToArray()));
            }
        }

        return fields.ToArray();
    }

    private static A64CompiledBinding[] ParseBindings(
        string encoded,
        A64CompiledField[] fields,
        string assembly)
    {
        var bindings = new List<A64CompiledBinding>();
        foreach (var item in encoded.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = item.Split(':', 3);
            if (parts.Length == 3)
            {
                byOperandName.TryGetValue(parts[1], out var codec);
                var fieldIndex = IndexOfField(fields, parts[0]);
                var secondaryFieldIndex = -1;
                var kind = ClassifyOperand(parts[1], codec);
                var registerType = parts[1];
                if (kind == A64CompiledOperandKind.ModifiedRegister
                    && A64GeneratedOperandShapes.TryGetModifiedRegister(parts[1], out var shape))
                {
                    fieldIndex = IndexOfField(fields, shape.RegisterField);
                    secondaryFieldIndex = IndexOfField(fields, shape.ModifierField);
                    registerType = shape.RegisterType;
                }

                var binding = new A64CompiledBinding(
                    parts[0],
                    parts[1],
                    parts[2],
                    codec,
                    fieldIndex,
                    secondaryFieldIndex,
                    kind);
                var shapeCount = 0;
                var elementWidth = 0;
                if (kind == A64CompiledOperandKind.VectorList)
                {
                    A64GeneratedOperandShapes.TryGetVectorList(parts[1], out shapeCount, out elementWidth);
                }
                else if (kind == A64CompiledOperandKind.RegisterGroup)
                {
                    A64GeneratedOperandShapes.TryGetRegisterGroup(parts[1], out shapeCount, out _);
                    elementWidth = A64GeneratedOperandShapes.ElementWidth(parts[1]);
                }

                var matrixKind = A64GeneratedOperandShapes.TryGetMatrixRegister(
                    parts[1],
                    out var parsedMatrixKind,
                    out var matrixElementWidth)
                    ? parsedMatrixKind
                    : default;
                if (elementWidth == 0)
                {
                    elementWidth = matrixElementWidth != 0
                        ? matrixElementWidth
                        : A64GeneratedOperandShapes.ElementWidth(parts[1]);
                }
                if (elementWidth == 0 && A64SVEImmediate.IsOptionalLsl(parts[1]))
                {
                    elementWidth = A64SVEImmediate.ElementWidth(parts[1]);
                }
                if (RegisterClass(parts[1]) == A64RegisterClass.Predicate
                    && string.Equals(codec?.ElementSize, "ElementSizeNone", StringComparison.Ordinal))
                {
                    elementWidth = 0;
                }

                bindings.Add(binding with
                {
                    FieldWidth = fieldIndex >= 0 ? fields[fieldIndex].Width : 32,
                    Scale = ReadScale(type: parts[1], printMethod: codec?.PrintMethod ?? string.Empty),
                    RegisterWidth = RegisterWidth(registerType),
                    RegisterClass = RegisterClass(registerType),
                    AllowsStackPointer = registerType.Contains("sp", StringComparison.OrdinalIgnoreCase),
                    AllowsZeroRegister = AllowsZeroRegister(registerType),
                    RegisterConstraint = A64GeneratedOperandShapes.TryGetRegisterConstraint(
                        registerType,
                        out var registerConstraint)
                        ? registerConstraint
                        : A64RegisterConstraint.Any,
                    RegisterIndexBias = A64GeneratedOperandShapes.RegisterIndexBias(registerType),
                    RegisterIndexScale = A64GeneratedOperandShapes.RegisterIndexScale(registerType),
                    ShapeCount = shapeCount,
                    ElementWidth = elementWidth,
                    GroupStride = A64GeneratedOperandShapes.GroupStride(parts[1]),
                    FractionalBits = A64FixedPointImmediate.FractionalBits(parts[1]),
                    LaneCount = LaneCount(parts[1], elementWidth),
                    IsPageRelative = parts[1].Contains("adrplabel", StringComparison.OrdinalIgnoreCase),
                    PcRelativeScale = kind == A64CompiledOperandKind.PcRelative
                        ? parts[1].Contains("adrplabel", StringComparison.OrdinalIgnoreCase) ? 12
                        : parts[1].Contains("adrlabel", StringComparison.OrdinalIgnoreCase) ? 0 : 2
                        : 0,
                    IsSigned = IsSigned(parts[1], codec),
                    ImmediateSemanticKind = ImmediateSemanticKind(parts[1]),
                    EnumKind = EnumKind(parts[1]),
                    SemanticDomain = parts[1],
                    PredicateMode = PredicateMode(parts[0], assembly),
                    MatrixRegisterKind = matrixKind,
                    FixedModifierKind = FixedModifierKind(parts[1]),
                    FixedModifierAmount = FixedModifierAmount(parts[1]),
                });
            }
        }

        return bindings.ToArray();
    }

    private static Dictionary<string, string> ParseTies(string constraints)
    {
        var ties = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var constraint in constraints.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var equals = constraint.IndexOf('=');
            if (equals <= 0)
            {
                continue;
            }

            var left = constraint[..equals].Trim();
            var right = constraint[(equals + 1)..].Trim();
            if (left.StartsWith("@", StringComparison.Ordinal)
                || !left.StartsWith('$')
                || !right.StartsWith('$'))
            {
                continue;
            }

            left = left[1..];
            right = right[1..];
            var separator = right.IndexOfAny([' ', '\t']);
            if (separator >= 0)
            {
                right = right[..separator];
            }

            right = right.TrimEnd(',');
            if (left.Length == 0 || right.Length == 0)
            {
                continue;
            }

            ties[left] = right;
            ties[right] = left;
        }

        return ties;
    }

    private static int IndexOfField(A64CompiledField[] fields, string name)
    {
        for (var index = 0; index < fields.Length; index++)
        {
            if (string.Equals(fields[index].Name, name, StringComparison.Ordinal))
            {
                return index;
            }
        }

        return -1;
    }

    private static A64CompiledOperandKind ClassifyOperand(
        string type,
        A64GeneratedOperand? codec)
    {
        if (A64GeneratedOperandShapes.TryGetModifiedRegister(type, out _))
        {
            return A64CompiledOperandKind.ModifiedRegister;
        }

        if (type == "arith_extendlsl64")
        {
            return A64CompiledOperandKind.RegisterModifier;
        }

        if (type == "hinte_uimm16")
        {
            return A64CompiledOperandKind.Immediate;
        }

        if (type is "mrs_sysreg_op" or "msr_sysreg_op") return A64CompiledOperandKind.SystemRegister;
        if (type == "MatrixTileList") return A64CompiledOperandKind.MatrixTileMask;
        if (A64GeneratedOperandShapes.TryGetMatrixRegister(type, out _, out _))
        {
            return A64CompiledOperandKind.MatrixRegister;
        }
        if (A64GeneratedOperandShapes.TryGetRegisterPair(type, out _, out _))
        {
            return A64CompiledOperandKind.RegisterPair;
        }
        if (type is "logical_imm32" or "logical_imm64") return A64CompiledOperandKind.LogicalImmediate;
        if (type == "simdimmtype10") return A64CompiledOperandKind.SimdImmediate;
        if (A64MoveWideImmediate.IsImmediate(type)) return A64CompiledOperandKind.MoveWideImmediate;
        if (A64MoveWideImmediate.IsShift(type)) return A64CompiledOperandKind.MoveWideShift;
        if (A64FloatingImmediate.IsFloatingImmediate(type)) return A64CompiledOperandKind.FloatingImmediate;
        if (A64VectorShift.IsVectorShift(type)) return A64CompiledOperandKind.VectorShift;
        if (type == "sve_incdec_imm") return A64CompiledOperandKind.SveIncrement;
        if (A64BitIndex.IsBitIndex(type)) return A64CompiledOperandKind.BitIndex;
        if (A64EnumImmediate.IsEncodedEnum(type)) return A64CompiledOperandKind.EnumImmediate;
        if (A64GeneratedOperandShapes.TryGetVectorList(type, out _, out _)) return A64CompiledOperandKind.VectorList;
        if (A64GeneratedOperandShapes.TryGetRegisterGroup(type, out _, out _)) return A64CompiledOperandKind.RegisterGroup;
        if (codec is not null && codec.OperandType == "OPERAND_PCREL") return A64CompiledOperandKind.PcRelative;
        if (codec is not null && IsRegisterType(type, codec)) return A64CompiledOperandKind.Register;
        if (codec is not null && IsImmediateType(type, codec)) return A64CompiledOperandKind.Immediate;
        return A64CompiledOperandKind.EncodedField;
    }

    private static bool IsRegisterType(string type, A64GeneratedOperand codec)
    {
        return type.StartsWith("GPR", StringComparison.Ordinal)
            || type.StartsWith("FPR", StringComparison.Ordinal)
            || type.StartsWith("V", StringComparison.Ordinal)
                && !type.StartsWith("VectorIndex", StringComparison.Ordinal)
            || type.StartsWith("ZPR", StringComparison.Ordinal)
            || type.StartsWith("PPR", StringComparison.Ordinal)
            || type.StartsWith("PNR", StringComparison.Ordinal)
            || type.StartsWith("Z_", StringComparison.Ordinal)
            || type.StartsWith("MatrixIndexGPR", StringComparison.Ordinal);
    }

    private static bool IsImmediateType(string type, A64GeneratedOperand codec)
    {
        return codec.OperandType is "OPERAND_IMMEDIATE"
            or "OPERAND_SHIFTED_IMMEDIATE"
            or "OPERAND_IMM_UINT8"
            or "OPERAND_IMM_UINT1"
            or "OPERAND_IMM_UINT4plus1"
            or "OPERAND_IMM_UINT5"
            or "OPERAND_IMPLICIT_IMM_0"
            || type.StartsWith("imm", StringComparison.OrdinalIgnoreCase)
            || type.StartsWith("simm", StringComparison.OrdinalIgnoreCase)
            || type.StartsWith("uimm", StringComparison.OrdinalIgnoreCase)
            || type.Contains("Imm", StringComparison.Ordinal);
    }

    private static bool IsSigned(string type, A64GeneratedOperand? codec)
    {
        return type.StartsWith("simm", StringComparison.OrdinalIgnoreCase)
            || codec?.ParserMatchClass.StartsWith("SImm", StringComparison.Ordinal) == true;
    }

    private static int RegisterWidth(string type)
    {
        if (A64GeneratedOperandShapes.TryGetRegisterPair(type, out _, out var pairWidth))
        {
            return pairWidth;
        }

        if (type.StartsWith("ZPR", StringComparison.Ordinal)
            || type.StartsWith("ZZ", StringComparison.Ordinal)
            || type.StartsWith("Z_", StringComparison.Ordinal))
        {
            return A64GeneratedOperandShapes.ElementWidth(type);
        }

        if (type.StartsWith("PPR", StringComparison.Ordinal)
            || type.StartsWith("PNR", StringComparison.Ordinal))
        {
            return 0;
        }

        var start = type.StartsWith("GPR", StringComparison.Ordinal)
            || type.StartsWith("FPR", StringComparison.Ordinal) ? 3
            : type.StartsWith("MatrixIndexGPR", StringComparison.Ordinal) ? "MatrixIndexGPR".Length
            : type.StartsWith("V", StringComparison.Ordinal) ? 1
            : 0;
        if (start == 0)
        {
            return 0;
        }

        var width = 0;
        while (start < type.Length && char.IsDigit(type[start]))
        {
            width = width * 10 + type[start++] - '0';
        }

        return width;
    }

    private static A64RegisterClass RegisterClass(string type)
    {
        if (type.Contains("asZPR", StringComparison.Ordinal))
        {
            return A64RegisterClass.SveVector;
        }

        if (type.StartsWith("PP_", StringComparison.Ordinal))
        {
            return A64RegisterClass.Predicate;
        }

        if (A64GeneratedOperandShapes.TryGetRegisterPair(type, out var pairClass, out _))
        {
            return pairClass;
        }

        if (type.StartsWith("GPR", StringComparison.Ordinal)
            || type.StartsWith("MatrixIndexGPR", StringComparison.Ordinal))
        {
            return A64RegisterClass.General;
        }

        if (type.StartsWith("FPR", StringComparison.Ordinal)) return A64RegisterClass.FloatingPoint;
        if (type.StartsWith("V", StringComparison.Ordinal)) return A64RegisterClass.Vector;
        if (type.StartsWith("ZPR", StringComparison.Ordinal)
            || type.StartsWith("ZZ", StringComparison.Ordinal)
            || type.StartsWith("Z_", StringComparison.Ordinal)) return A64RegisterClass.SveVector;
        if (type.StartsWith("PPR", StringComparison.Ordinal)
            || type.StartsWith("PNR", StringComparison.Ordinal)) return A64RegisterClass.Predicate;
        return A64RegisterClass.Special;
    }

    private static int LaneCount(string type, int elementWidth)
    {
        if (!type.StartsWith("VectorIndex", StringComparison.Ordinal)
            && !A64GeneratedOperandShapes.IsSveExtendedDuplicateIndex(type))
        {
            return 0;
        }

        if (type.Contains("timm", StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        if (A64GeneratedOperandShapes.IsSveExtendedDuplicateIndex(type))
        {
            return elementWidth switch
            {
                8 => 64,
                16 => 32,
                32 => 16,
                64 => 8,
                128 => 4,
                _ => 0,
            };
        }

        return elementWidth switch
        {
            8 => 16,
            16 => 8,
            32 => 4,
            64 => 2,
            _ => 0,
        };
    }

    private static A64ImmediateSemanticKind ImmediateSemanticKind(string type)
    {
        if (A64EnumImmediate.IsEncodedEnum(type))
        {
            return A64ImmediateSemanticKind.Enum;
        }

        if (type is "logical_imm32" or "logical_imm64")
        {
            return A64ImmediateSemanticKind.LogicalImmediate;
        }

        if (type == "simdimmtype10")
        {
            return A64ImmediateSemanticKind.SimdImmediate;
        }

        if (A64FloatingImmediate.IsFloatingImmediate(type))
        {
            return A64ImmediateSemanticKind.FloatingImmediate;
        }

        if (A64SVEImmediate.IsOptionalLsl(type))
        {
            return A64ImmediateSemanticKind.SveOptionalShift;
        }

        if (type == "hinte_uimm16")
        {
            return A64ImmediateSemanticKind.HinteImmediate;
        }

        if (A64MoveWideImmediate.IsImmediate(type))
        {
            return A64ImmediateSemanticKind.MoveWideImmediate;
        }

        if (type == "sve_incdec_imm")
        {
            return A64ImmediateSemanticKind.SveIncrement;
        }

        if (A64BitIndex.IsBitIndex(type))
        {
            return A64ImmediateSemanticKind.BitIndex;
        }

        if (type.StartsWith("VectorIndex", StringComparison.Ordinal))
        {
            return A64ImmediateSemanticKind.LaneIndex;
        }

        if (A64GeneratedOperandShapes.IsSveExtendedDuplicateIndex(type))
        {
            return A64ImmediateSemanticKind.LaneIndex;
        }

        if (type.StartsWith("complexrotate", StringComparison.Ordinal))
        {
            return A64ImmediateSemanticKind.ComplexRotation;
        }

        if (type.StartsWith("fixedpoint", StringComparison.Ordinal))
        {
            return A64ImmediateSemanticKind.FixedPoint;
        }

        return type.Contains("shift", StringComparison.OrdinalIgnoreCase)
            ? A64ImmediateSemanticKind.Shift
            : A64ImmediateSemanticKind.Plain;
    }

    private static A64EnumKind EnumKind(string type)
    {
        return type switch
        {
            "sve_pred_enum" => A64EnumKind.SvePredicatePattern,
            "sve_prfop" => A64EnumKind.SvePrefetch,
            "sve_vec_len_specifier_enum" => A64EnumKind.SveVectorLength,
            "svcr_op" => A64EnumKind.Svcr,
            "TIndexhint_op" => A64EnumKind.TIndexHint,
            "ccode" or "inv_ccode" => A64EnumKind.ConditionCode,
            "barrier_op" or "barrier_nxs_op" => A64EnumKind.Barrier,
            "prfop" or "rprfop" => A64EnumKind.Prefetch,
            "sys_cr_op" => A64EnumKind.SystemControlRegister,
            "pstatefield1_op" or "pstatefield4_op" => A64EnumKind.PStateField,
            _ => A64EnumKind.Unknown,
        };
    }

    private static A64PredicateMode PredicateMode(string name, string assembly)
    {
        var marker = "$" + name;
        var index = assembly.IndexOf(marker, StringComparison.Ordinal);
        if (index < 0 || index + marker.Length >= assembly.Length)
        {
            return A64PredicateMode.None;
        }

        var suffix = assembly.AsSpan(index + marker.Length);
        return suffix.StartsWith("/m", StringComparison.Ordinal)
            ? A64PredicateMode.Merge
            : suffix.StartsWith("/z", StringComparison.Ordinal)
                ? A64PredicateMode.Zero
                : A64PredicateMode.None;
    }

    private static A64RegisterModifierKind FixedModifierKind(string type)
    {
        if (type.Contains("ExtUXTW", StringComparison.Ordinal)) return A64RegisterModifierKind.Uxtw;
        if (type.Contains("ExtSXTW", StringComparison.Ordinal)) return A64RegisterModifierKind.Sxtw;
        if (type.Contains("ExtLSL", StringComparison.Ordinal)) return A64RegisterModifierKind.Lsl;
        return A64RegisterModifierKind.Unknown;
    }

    private static int FixedModifierAmount(string type)
    {
        var marker = type.IndexOf("Ext", StringComparison.Ordinal);
        if (marker < 0)
        {
            return 0;
        }

        var index = marker + 3;
        while (index < type.Length && !char.IsDigit(type[index])) index++;
        var amount = 0;
        while (index < type.Length && char.IsDigit(type[index]))
        {
            amount = amount * 10 + type[index++] - '0';
        }

        return amount;
    }

    private static bool AllowsZeroRegister(string type)
    {
        return type.StartsWith("GPR32z", StringComparison.Ordinal)
            || type.StartsWith("GPR64z", StringComparison.Ordinal)
            || type is "GPR32" or "GPR64";
    }

    private static int ReadScale(string type, string printMethod)
    {
        if (TryReadAngleValue(printMethod, "Scale<", out var printScale)
            || TryReadAngleValue(printMethod, "scale<", out printScale))
        {
            return printScale;
        }

        var immediate = type.IndexOf("imm", StringComparison.OrdinalIgnoreCase);
        if (immediate >= 0)
        {
            var index = immediate + 3;
            while (index < type.Length && char.IsDigit(type[index])) index++;
            if (index < type.Length && (type[index] is 's' or 'S'))
            {
                index++;
                var start = index;
                var scale = 0;
                while (index < type.Length && char.IsDigit(type[index]))
                {
                    scale = scale * 10 + type[index++] - '0';
                }

                if (index != start && scale != 0) return scale;
            }
        }

        return 1;
    }

    private static bool TryReadAngleValue(string text, string marker, out int value)
    {
        var markerIndex = text.IndexOf(marker, StringComparison.Ordinal);
        if (markerIndex < 0)
        {
            value = 0;
            return false;
        }

        var index = markerIndex + marker.Length;
        value = 0;
        var start = index;
        while (index < text.Length && char.IsDigit(text[index]))
        {
            value = value * 10 + text[index++] - '0';
        }

        return index != start && index < text.Length && text[index] == '>';
    }

    private static int CountOperands(
        A64CompiledField[] fields,
        A64CompiledBinding[] bindings,
        A64GeneratedMemoryBinding? memory)
    {
        var count = 0;
        foreach (var binding in bindings)
        {
            if (A64GeneratedOperandShapes.TryGetModifiedRegister(binding.Type, out _)
                || ContainsField(fields, binding.Name))
            {
                count++;
            }
        }

        if (memory is { } memoryBinding)
        {
            if (memoryBinding.OffsetName is not null && ContainsField(fields, memoryBinding.OffsetName))
            {
                count--;
            }

            if (memoryBinding.IndexName is not null && ContainsField(fields, memoryBinding.IndexName))
            {
                count--;
            }

            if (memoryBinding.ModifierName is not null && ContainsField(fields, memoryBinding.ModifierName))
            {
                count--;
            }
        }

        return Math.Max(count, 0);
    }

    private static A64GeneratedMemoryBinding CompileMemory(
        A64GeneratedMemoryBinding memory,
        A64CompiledField[] fields,
        A64CompiledBinding[] bindings)
    {
        var offsetName = memory.OffsetName;
        if (offsetName == "offset"
            && IndexOfField(fields, offsetName) < 0
            && IndexOfField(fields, "imm4") >= 0
            && IndexOfBinding(bindings, offsetName) >= 0)
        {
            offsetName = "imm4";
        }

        return memory with
        {
            BaseFieldIndex = IndexOfField(fields, memory.BaseName),
            OffsetName = offsetName,
            OffsetFieldIndex = offsetName is { } resolvedOffsetName ? IndexOfField(fields, resolvedOffsetName) : -1,
            IndexFieldIndex = memory.IndexName is { } indexName ? IndexOfField(fields, indexName) : -1,
            ModifierFieldIndex = memory.ModifierName is { } modifierName ? IndexOfField(fields, modifierName) : -1,
            BaseBindingIndex = IndexOfBinding(bindings, memory.BaseName),
            OffsetBindingIndex = offsetName is { } offsetBindingName ? IndexOfBinding(bindings, offsetBindingName) : -1,
            IndexBindingIndex = memory.IndexName is { } indexBindingName ? IndexOfBinding(bindings, indexBindingName) : -1,
            ModifierBindingIndex = memory.ModifierName is { } modifierBindingName ? IndexOfBinding(bindings, modifierBindingName) : -1,
        };
    }

    private static int IndexOfBinding(A64CompiledBinding[] bindings, string name)
    {
        for (var index = 0; index < bindings.Length; index++)
        {
            if (string.Equals(bindings[index].Name, name, StringComparison.Ordinal))
            {
                return index;
            }
        }

        return -1;
    }

    private static bool ContainsField(A64CompiledField[] fields, string name)
    {
        foreach (var field in fields)
        {
            if (string.Equals(field.Name, name, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static A64EncodingInfo ToEncodingInfo(A64GeneratedInstruction candidate)
    {
        return new A64EncodingInfo(
            candidate.Name,
            candidate.Mnemonic,
            candidate.Mask,
            candidate.Value,
            candidate.Assembly,
            candidate.DecoderMethod,
            candidate.Predicates,
            candidate.VariableFields,
            candidate.FieldEncoding,
            candidate.OperandBindings,
            candidate.InputOperands,
            candidate.OutputOperands,
            candidate.Constraints,
            candidate.HasCompleteEncoding,
            MapFlags(candidate.Flags));
    }

    private static A64InstructionFlags MapFlags(A64GeneratedFlags flags)
    {
        var result = A64InstructionFlags.None;
        if ((flags & A64GeneratedFlags.Branch) != 0)
        {
            result |= A64InstructionFlags.IsBranch;
        }

        if ((flags & A64GeneratedFlags.Call) != 0)
        {
            result |= A64InstructionFlags.IsCall;
        }

        if ((flags & A64GeneratedFlags.Return) != 0)
        {
            result |= A64InstructionFlags.IsReturn;
        }

        if ((flags & A64GeneratedFlags.Load) != 0)
        {
            result |= A64InstructionFlags.IsLoad;
        }

        if ((flags & A64GeneratedFlags.Store) != 0)
        {
            result |= A64InstructionFlags.IsStore;
        }

        if ((flags & A64GeneratedFlags.Compare) != 0)
        {
            result |= A64InstructionFlags.IsCompare;
        }

        if ((flags & A64GeneratedFlags.Barrier) != 0)
        {
            result |= A64InstructionFlags.IsBarrier;
        }

        if ((flags & A64GeneratedFlags.Terminator) != 0)
        {
            result |= A64InstructionFlags.IsTerminator;
        }

        if ((flags & A64GeneratedFlags.SideEffects) != 0)
        {
            result |= A64InstructionFlags.HasSideEffects;
        }

        if ((flags & A64GeneratedFlags.WritesBack) != 0)
        {
            result |= A64InstructionFlags.WritesBack;
        }

        if ((flags & A64GeneratedFlags.Atomic) != 0)
        {
            result |= A64InstructionFlags.IsAtomic;
        }

        if ((flags & A64GeneratedFlags.System) != 0)
        {
            result |= A64InstructionFlags.IsSystem;
        }

        if ((flags & A64GeneratedFlags.ReadsNzcv) != 0)
        {
            result |= A64InstructionFlags.ReadsNzcv;
        }

        if ((flags & A64GeneratedFlags.WritesNzcv) != 0)
        {
            result |= A64InstructionFlags.WritesNzcv | A64InstructionFlags.SetsFlags;
        }

        if ((flags & A64GeneratedFlags.ReadsFpcr) != 0)
        {
            result |= A64InstructionFlags.ReadsFpcr;
        }

        if ((flags & A64GeneratedFlags.WritesFpcr) != 0)
        {
            result |= A64InstructionFlags.WritesFpcr;
        }

        if ((flags & A64GeneratedFlags.ReadsFfr) != 0)
        {
            result |= A64InstructionFlags.ReadsFfr;
        }

        if ((flags & A64GeneratedFlags.WritesFfr) != 0)
        {
            result |= A64InstructionFlags.WritesFfr;
        }

        if ((flags & A64GeneratedFlags.MayRaiseFpException) != 0)
        {
            result |= A64InstructionFlags.MayRaiseFpException;
        }

        return result;
    }

    private static (int[] Offsets, int[] Candidates) BuildBuckets()
    {
        const int keyBits = 20;
        const int keyCount = 1 << keyBits;
        const uint keyMask = keyCount - 1u;
        var counts = new int[keyCount];
        for (var index = 0; index < A64GeneratedInstructionTable.All.Length; index++)
        {
            var candidate = A64GeneratedInstructionTable.All[index];
            var highMask = (candidate.Mask >> 12) & keyMask;
            var highValue = (candidate.Value >> 12) & highMask;
            var variableBits = (~highMask) & keyMask;
            for (var variable = variableBits; ; variable = (variable - 1) & variableBits)
            {
                counts[highValue | variable]++;
                if (variable == 0)
                {
                    break;
                }
            }
        }

        var offsets = new int[keyCount + 1];
        for (var index = 0; index < keyCount; index++)
        {
            offsets[index + 1] = offsets[index] + counts[index];
        }

        var candidates = new int[offsets[keyCount]];
        var cursors = new int[keyCount];
        Array.Copy(offsets, cursors, keyCount);
        for (var index = 0; index < A64GeneratedInstructionTable.All.Length; index++)
        {
            var candidate = A64GeneratedInstructionTable.All[index];
            var highMask = (candidate.Mask >> 12) & keyMask;
            var highValue = (candidate.Value >> 12) & highMask;
            var variableBits = (~highMask) & keyMask;
            for (var variable = variableBits; ; variable = (variable - 1) & variableBits)
            {
                var bucket = (int)(highValue | variable);
                candidates[cursors[bucket]++] = index;
                if (variable == 0)
                {
                    break;
                }
            }
        }

        return (offsets, candidates);
    }

    private static CandidateRange GetBucket(uint encoding)
    {
        var key = (int)(encoding >> 12);
        return new CandidateRange(bucketOffsets[key], bucketOffsets[key + 1]);
    }

    private static readonly IReadOnlyDictionary<string, A64CompiledInstruction> byCompiledName =
        compiled.ToDictionary(candidate => candidate.Source.Name, StringComparer.Ordinal);

    static A64InstructionCatalog()
    {
        (bucketOffsets, bucketCandidates) = BuildBuckets();
    }

    public static bool TryGetOperand(string name, out A64OperandEncodingInfo info)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (byOperandName.TryGetValue(name, out var operand))
        {
            info = new A64OperandEncodingInfo(
                operand.Name,
                operand.OperandType,
                operand.DecoderMethod,
                operand.EncoderMethod,
                operand.PrintMethod,
                operand.ParserMatchClass,
                operand.RegClass,
                operand.ElementSize,
                operand.Type);
            return true;
        }

        info = default;
        return false;
    }
}

internal readonly record struct CandidateRange(int Start, int End);
