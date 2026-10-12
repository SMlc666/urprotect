namespace AsmStone.Model;

public readonly record struct A64InstructionCode(int Value)
{
    public static A64InstructionCode Invalid => new(-1);

    public bool IsValid => Value >= 0;
}

public readonly record struct A64FieldId(int Value)
{
    public static A64FieldId Invalid => new(-1);

    public bool IsValid => Value >= 0;
}
