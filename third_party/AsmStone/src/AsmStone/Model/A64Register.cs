namespace AsmStone.Model;

public enum A64RegisterClass
{
    General,
    Vector,
    FloatingPoint,
    SveVector,
    Predicate,
    System,
    Special,
}

public enum A64RegisterRole
{
    None,
    StackPointer,
    Zero,
}

public readonly record struct A64Register(
    A64RegisterClass Class,
    byte Index,
    byte Width,
    A64RegisterRole Role = A64RegisterRole.None)
{
    public static A64Register X(int index) => General(index, 64);

    public static A64Register W(int index) => General(index, 32);

    public static A64Register Sp(int width = 64) => new(
        A64RegisterClass.General,
        31,
        checked((byte)width),
        A64RegisterRole.StackPointer);

    public static A64Register Zr(int width = 64) => new(
        A64RegisterClass.General,
        31,
        checked((byte)width),
        A64RegisterRole.Zero);

    public static A64Register Vector(int index, int width = 128) => new(
        A64RegisterClass.Vector,
        checked((byte)index),
        checked((byte)width));

    public static A64Register FloatingPoint(int index, int width) => new(
        A64RegisterClass.FloatingPoint,
        checked((byte)index),
        checked((byte)width));

    public static A64Register SveVector(int index, int elementWidth = 0) => new(
        A64RegisterClass.SveVector,
        checked((byte)index),
        checked((byte)elementWidth));

    public bool IsGeneral => Class == A64RegisterClass.General;

    public bool IsStackPointer => Role == A64RegisterRole.StackPointer;

    public bool IsZeroRegister => Role == A64RegisterRole.Zero;

    public override string ToString()
    {
        if (Class == A64RegisterClass.General)
        {
            if (Role == A64RegisterRole.StackPointer)
            {
                return Width == 32 ? "wsp" : "sp";
            }

            if (Role == A64RegisterRole.Zero)
            {
                return Width == 32 ? "wzr" : "xzr";
            }

            return $"{(Width == 32 ? 'w' : 'x')}{Index}";
        }

        return Class switch
        {
            A64RegisterClass.Vector => $"v{Index}",
            A64RegisterClass.FloatingPoint => Width switch
            {
                8 => $"b{Index}",
                16 => $"h{Index}",
                32 => $"s{Index}",
                64 => $"d{Index}",
                128 => $"q{Index}",
                _ => $"f{Index}",
            },
            A64RegisterClass.SveVector => $"z{Index}",
            A64RegisterClass.Predicate => $"p{Index}",
            _ => $"r{Index}",
        };
    }

    private static A64Register General(int index, int width)
    {
        if ((uint)index > 30)
        {
            throw new ArgumentOutOfRangeException(nameof(index), "General register index must be between 0 and 30.");
        }

        if (width is not (32 or 64))
        {
            throw new ArgumentOutOfRangeException(nameof(width), "General register width must be 32 or 64.");
        }

        return new A64Register(A64RegisterClass.General, checked((byte)index), checked((byte)width));
    }
}
