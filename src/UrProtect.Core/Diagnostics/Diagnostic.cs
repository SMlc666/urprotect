namespace UrProtect.Core.Diagnostics;

public enum DiagnosticSeverity
{
    Info,
    Warning,
    Error,
}

public enum DiagnosticCode
{
    None,
    InputTooSmall,
    InvalidMagic,
    UnsupportedClass,
    UnsupportedEndianness,
    UnsupportedMachine,
    UnsupportedFileType,
    InvalidHeader,
    TableOutOfBounds,
    InvalidProgramHeader,
    UnsupportedExtendedNumbering,
    UnknownProgramHeaderType,
    InvalidSegment,
    InvalidAlignment,
    NoteMalformed,
    MissingLoadSegment,
    MissingDynamicSegment,
    DynamicTableMalformed,
    DynamicTableUnterminated,
    DynamicPointerUnmapped,
    SymbolVersionTableMalformed,
    VersionNeedTableMalformed,
    RelocationTableMalformed,
    SymbolTableMalformed,
    UnsupportedDynamicTag,
    UnsupportedRelocation,
    UnknownInstruction,
    UnsupportedInstructionFeature,
    AddressOverflow,
    AddressUnmapped,
    OutputIdentityMismatch,
    OutputPathConflict,
    InputIoFailure,
    OutputIoFailure,
    AsmStoneUnavailable,
    InvalidArgument,
}

public readonly record struct Diagnostic(
    DiagnosticSeverity Severity,
    DiagnosticCode Code,
    string Message,
    ulong? Offset = null)
{
    public bool IsError => Severity == DiagnosticSeverity.Error;

    public override string ToString()
    {
        var location = Offset is ulong offset ? $" @0x{offset:X}" : string.Empty;
        return $"{Severity} {Code}{location}: {Message}";
    }
}

public sealed class DiagnosticBag : IReadOnlyList<Diagnostic>
{
    private readonly List<Diagnostic> items = new();

    public int Count => items.Count;

    public bool HasErrors => items.Any(item => item.IsError);

    public Diagnostic this[int index] => items[index];

    public void Add(Diagnostic diagnostic) => items.Add(diagnostic);

    public void Info(DiagnosticCode code, string message, ulong? offset = null) =>
        Add(new Diagnostic(DiagnosticSeverity.Info, code, message, offset));

    public void Warning(DiagnosticCode code, string message, ulong? offset = null) =>
        Add(new Diagnostic(DiagnosticSeverity.Warning, code, message, offset));

    public void Error(DiagnosticCode code, string message, ulong? offset = null) =>
        Add(new Diagnostic(DiagnosticSeverity.Error, code, message, offset));

    public IEnumerator<Diagnostic> GetEnumerator() => items.GetEnumerator();

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

    public IReadOnlyList<Diagnostic> ToArray() => items.ToArray();
}
