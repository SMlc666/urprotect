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
    // Keep the generated source tables resident, but materialize compiled plans only
    // for instructions that are actually decoded, encoded, or inspected.
    private static readonly WeakReference<A64CompiledInstruction>?[] compiled =
        new WeakReference<A64CompiledInstruction>?[A64GeneratedInstructionTable.All.Length];
    private static readonly Lazy<(int[] Offsets, ushort[] Candidates)> buckets = new(BuildBuckets);

    public static int Count => A64GeneratedInstructionTable.All.Length;

    public static int OperandTypeCount => A64GeneratedOperandTable.All.Length;

    public static bool TryGetCode(string name, out A64InstructionCode code)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (byCompiledName.TryGetValue(name, out var index))
        {
            code = new A64InstructionCode(index);
            return true;
        }

        code = A64InstructionCode.Invalid;
        return false;
    }

    public static bool TryGetDescriptor(
        A64InstructionCode code,
        out A64InstructionDescriptor descriptor)
    {
        if ((uint)code.Value < (uint)A64GeneratedInstructionTable.All.Length)
        {
            descriptor = GetCompiled(code.Value).GetDescriptor();
            return true;
        }

        descriptor = default!;
        return false;
    }

    public static bool TryGetDescriptor(
        string name,
        out A64InstructionDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(name);
        return byCompiledName.TryGetValue(name, out var index)
            ? TryGetDescriptor(new A64InstructionCode(index), out descriptor)
            : SetMissingDescriptor(out descriptor);
    }

    private static bool SetMissingDescriptor(
        out A64InstructionDescriptor descriptor)
    {
        descriptor = default!;
        return false;
    }

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

    public static IEnumerable<A64InstructionDescriptor> EnumerateDescriptors()
    {
        for (var index = 0; index < A64GeneratedInstructionTable.All.Length; index++)
        {
            yield return GetCompiled(index).GetDescriptor();
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
        var candidates = buckets.Value.Candidates;
        for (var bucketIndex = bucket.Start; bucketIndex < bucket.End; bucketIndex++)
        {
            var instructionIndex = candidates[bucketIndex];
            var source = A64GeneratedInstructionTable.All[instructionIndex];
            if (!source.HasCompleteEncoding
                || (encoding & source.Mask) != source.Value
                || !features.SupportsAll(source.Predicates))
            {
                continue;
            }

            var candidate = GetCompiled(instructionIndex);
            if (!A64GeneratedDecoderConstraints.Accept(candidate, encoding, features))
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
        var candidates = buckets.Value.Candidates;
        for (var bucketIndex = bucket.Start; bucketIndex < bucket.End; bucketIndex++)
        {
            var instructionIndex = candidates[bucketIndex];
            var source = A64GeneratedInstructionTable.All[instructionIndex];
            if (!source.HasCompleteEncoding
                || (encoding & source.Mask) != source.Value
                || features.SupportsAll(source.Predicates))
            {
                continue;
            }

            var candidate = GetCompiled(instructionIndex);
            if (!A64GeneratedDecoderConstraints.Accept(candidate, encoding, features))
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
        if (byCompiledName.TryGetValue(name, out var instructionIndex))
        {
            info = GetCompiled(instructionIndex).Info;
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
        if (!byCompiledName.TryGetValue(name, out var instructionIndex))
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.InvalidInstruction,
                $"Generated instruction '{name}' was not found.");
            return false;
        }

        var candidate = GetCompiled(instructionIndex);
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
        if (!byCompiledName.TryGetValue(name, out var instructionIndex))
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.InvalidInstruction,
                $"Generated instruction '{name}' was not found.");
            return false;
        }

        var candidate = GetCompiled(instructionIndex);
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

    internal static bool TryGetCompiledByCode(
        A64InstructionCode code,
        out A64CompiledInstruction instruction)
    {
        if ((uint)code.Value < (uint)A64GeneratedInstructionTable.All.Length)
        {
            instruction = GetCompiled(code.Value);
            return true;
        }

        instruction = default!;
        return false;
    }

    internal static bool TryGetCompiledByName(
        string name,
        out A64CompiledInstruction instruction)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (byCompiledName.TryGetValue(name, out var instructionIndex))
        {
            instruction = GetCompiled(instructionIndex);
            return true;
        }

        instruction = default!;
        return false;
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
        var candidates = buckets.Value.Candidates;
        for (var bucketIndex = bucket.Start; bucketIndex < bucket.End; bucketIndex++)
        {
            var instructionIndex = candidates[bucketIndex];
            var source = A64GeneratedInstructionTable.All[instructionIndex];
            if (!source.HasCompleteEncoding
                || (encoding & source.Mask) != source.Value
                || !features.SupportsAll(source.Predicates))
            {
                continue;
            }

            var candidate = GetCompiled(instructionIndex);
            if (!A64GeneratedDecoderConstraints.Accept(candidate, encoding, features))
            {
                continue;
            }

            instruction = candidate;
            return true;
        }

        instruction = default!;
        return false;
    }

    private static A64CompiledInstruction BuildCompiled(int index)
    {
        var source = A64GeneratedInstructionTable.All[index];
        var info = ToEncodingInfo(source);
        var fields = BuildFields(index);
        var bindings = BuildTypedBindings(index);
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

        var predicates = BuildPredicates(index);
        var memory = A64GeneratedMemory.TryGet(index, out var memoryBinding)
            ? CompileMemory(memoryBinding, fields, bindings)
            : (A64GeneratedMemoryBinding?)null;
        var operandCount = CountOperands(fields, bindings, memory);
        var uncollapsedOperandCount = CountOperands(fields, bindings, null);
        return new A64CompiledInstruction(
            new A64InstructionCode(index),
            source,
            info,
            fields,
            bindings,
            predicates,
            operandCount,
            uncollapsedOperandCount,
            memory);
    }

    private static A64CompiledInstruction GetCompiled(int index)
    {
        if ((uint)index >= (uint)A64GeneratedInstructionTable.All.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        var weak = System.Threading.Volatile.Read(ref compiled[index]);
        if (weak is not null && weak.TryGetTarget(out var cached))
        {
            return cached;
        }

        var created = BuildCompiled(index);
        var replacement = new WeakReference<A64CompiledInstruction>(created);
        var observed = System.Threading.Interlocked.CompareExchange(ref compiled[index], replacement, weak);
        if (observed is not null && observed.TryGetTarget(out var raced))
        {
            return raced;
        }

        return created;
    }

    private static bool TryGetExact(uint encoding, out A64CompiledInstruction candidate)
    {
        if (A64GeneratedInstructionTable.TryGetExact(encoding, out var index))
        {
            candidate = GetCompiled(index);
            return true;
        }

        candidate = default!;
        return false;
    }

    private static string[] BuildPredicates(int instructionIndex)
    {
        if ((uint)instructionIndex >= (uint)A64GeneratedInstructionTable.All.Length)
        {
            throw new InvalidDataException(
                $"Generated predicate table has no entry for instruction index {instructionIndex}.");
        }

        return A64GeneratedPredicateTable.Get(instructionIndex);
    }

    private static A64CompiledField[] BuildFields(int instructionIndex)
    {
        if ((uint)instructionIndex >= (uint)A64GeneratedInstructionTable.All.Length)
        {
            throw new InvalidDataException(
                $"Generated field table has no entry for instruction index {instructionIndex}.");
        }

        return A64GeneratedFieldTable.Get(instructionIndex)
            .Select(field => new A64CompiledField(
                field.Name,
                field.Mappings
                    .Select(mapping => new A64CompiledFieldMapping(
                        mapping.EncodingBit,
                        mapping.FieldBit))
                    .ToArray()))
            .ToArray();
    }

    private static A64CompiledBinding[] BuildTypedBindings(int instructionIndex)
    {
        if ((uint)instructionIndex >= (uint)A64GeneratedInstructionTable.All.Length)
        {
            throw new InvalidDataException(
                $"Generated binding table has no entry for instruction index {instructionIndex}.");
        }

        var generated = A64GeneratedBindingTable.Get(instructionIndex);
        var result = new A64CompiledBinding[generated.Length];
        for (var bindingIndex = 0; bindingIndex < generated.Length; bindingIndex++)
        {
            var data = generated[bindingIndex];
            if (!data.IsTypedPlan)
            {
                throw new InvalidDataException(
                    $"Generated binding table has an untyped plan for instruction index {instructionIndex}.");
            }

            A64GeneratedOperand? codec = byOperandName.TryGetValue(data.Type, out var operand)
                ? operand
                : null;
            result[bindingIndex] = new A64CompiledBinding(
                data.Name,
                data.Type,
                data.Direction,
                codec,
                data.FieldIndex,
                data.SecondaryFieldIndex,
                data.Kind)
            {
                TiedTo = data.TiedTo,
                PredicateMode = data.PredicateMode,
                FieldWidth = data.FieldWidth,
                Scale = data.Scale,
                RegisterWidth = data.RegisterWidth,
                RegisterIndexBias = data.RegisterIndexBias,
                RegisterIndexScale = data.RegisterIndexScale,
                RegisterClass = data.RegisterClass,
                AllowsStackPointer = data.AllowsStackPointer,
                AllowsZeroRegister = data.AllowsZeroRegister,
                RegisterConstraint = data.RegisterConstraint,
                ShapeCount = data.ShapeCount,
                ElementWidth = data.ElementWidth,
                GroupStride = data.GroupStride,
                FractionalBits = data.FractionalBits,
                LaneCount = data.LaneCount,
                IsPageRelative = data.IsPageRelative,
                PcRelativeScale = data.PcRelativeScale,
                IsSigned = data.IsSigned,
                ImmediateSemanticKind = data.ImmediateSemanticKind,
                EnumKind = data.EnumKind,
                SemanticDomain = data.SemanticDomain,
                MatrixRegisterKind = data.MatrixRegisterKind,
                FixedModifierKind = data.FixedModifierKind,
                FixedModifierAmount = data.FixedModifierAmount,
            };
        }

        return result;
    }

    private static int CountOperands(
        A64CompiledField[] fields,
        A64CompiledBinding[] bindings,
        A64GeneratedMemoryBinding? memory)
    {
        var count = 0;
        foreach (var binding in bindings)
        {
            if (binding.Kind == A64CompiledOperandKind.ModifiedRegister
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

    private static (int[] Offsets, ushort[] Candidates) BuildBuckets()
    {
        const int keyBits = 8;
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

        var candidates = new ushort[offsets[keyCount]];
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
                candidates[cursors[bucket]++] = checked((ushort)index);
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
        var key = (int)((encoding >> 12) & 0xFFu);
        var bucketData = buckets.Value;
        return new CandidateRange(bucketData.Offsets[key], bucketData.Offsets[key + 1]);
    }

    private static readonly IReadOnlyDictionary<string, int> byCompiledName =
        Enumerable.Range(0, A64GeneratedInstructionTable.All.Length)
            .ToDictionary(index => A64GeneratedInstructionTable.All[index].Name, StringComparer.Ordinal);

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
