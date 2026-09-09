using AsmStone.Generated;

namespace AsmStone.Model;

/// <summary>
/// A zero-allocation view over a generated AArch64 instruction encoding.
/// </summary>
public readonly ref struct A64RawInstruction
{
    private readonly A64CompiledInstruction? plan;

    internal A64RawInstruction(
        A64CompiledInstruction plan,
        uint encoding,
        ulong address)
    {
        this.plan = plan;
        Encoding = encoding;
        Address = address;
    }

    /// <summary>Gets the original 32-bit instruction word.</summary>
    public uint Encoding { get; }

    /// <summary>Gets the address associated with the instruction word.</summary>
    public ulong Address { get; }

    /// <summary>Gets the generated TableGen source name.</summary>
    public string SourceName => plan?.Info.Name ?? string.Empty;

    /// <summary>Gets the generated instruction mnemonic.</summary>
    public string Mnemonic => plan?.Info.Mnemonic ?? string.Empty;

    /// <summary>Gets the generated instruction effect flags.</summary>
    public A64InstructionFlags Flags => plan?.Info.Flags ?? A64InstructionFlags.None;

    /// <summary>Gets the number of encoded fields in this instruction.</summary>
    public int FieldCount => plan?.Fields.Length ?? 0;

    /// <summary>Gets a decoded field by its zero-based generated field index.</summary>
    public A64RawField GetField(int index)
    {
        var instruction = plan ?? throw new InvalidOperationException("The raw instruction view is empty.");
        var field = instruction.Fields[index];
        field.TryRead(Encoding, out var value);
        return new A64RawField(field.Name, value, field.Width);
    }

    /// <summary>Finds and decodes a generated field by name.</summary>
    public bool TryGetField(string name, out A64RawField field)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (plan is not null
            && plan.TryGetField(name, out var fieldPlan)
            && fieldPlan.TryRead(Encoding, out var value))
        {
            field = new A64RawField(fieldPlan.Name, value, fieldPlan.Width);
            return true;
        }

        field = default;
        return false;
    }
}

/// <summary>One generated field decoded from an AArch64 instruction word.</summary>
public readonly record struct A64RawField(string Name, uint Value, int Width);
