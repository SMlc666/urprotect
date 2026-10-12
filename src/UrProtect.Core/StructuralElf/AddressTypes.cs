namespace UrProtect.Core.StructuralElf;

public readonly record struct FileOffset(ulong Value);

public readonly record struct VirtualAddress(ulong Value);

public readonly record struct RuntimeAddress(ulong Value);
