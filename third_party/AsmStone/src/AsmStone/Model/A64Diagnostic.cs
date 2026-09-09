namespace AsmStone.Model;

public enum A64DiagnosticCode
{
    None,
    BufferTooSmall,
    UnknownEncoding,
    UnsupportedFeature,
    InvalidInstruction,
    InvalidOperand,
    OutOfRange,
    MisalignedTarget,
    InvalidSyntax,
}

public readonly record struct A64Diagnostic(
    A64DiagnosticCode Code,
    string Message)
{
    public static A64Diagnostic None => new(A64DiagnosticCode.None, string.Empty);

    public bool IsError => Code != A64DiagnosticCode.None;

    public override string ToString() => $"{Code}: {Message}";
}
