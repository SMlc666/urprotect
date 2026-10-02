using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Protect;

public readonly record struct FunctionSelector(
    string? Name,
    ElfSymbolTableKind? Table = null,
    uint? TableIndex = null,
    ulong? Address = null)
{
    public static FunctionSelector ByName(string name) =>
        new(name ?? throw new ArgumentNullException(nameof(name)));

    public static FunctionSelector ByIdentity(
        ElfSymbolTableKind table,
        uint tableIndex,
        string? name = null,
        ulong? address = null) =>
        new(name, table, tableIndex, address);

    public static FunctionSelector ByAddress(ulong address) =>
        new(null, Address: address);

    public bool HasCriteria => Name is not null || Table.HasValue || TableIndex.HasValue || Address.HasValue;

    public string ToDisplayString()
    {
        var parts = new List<string>();
        if (Name is { } name)
        {
            parts.Add($"name={name}");
        }

        if (Table is { } table)
        {
            parts.Add($"table={(table == ElfSymbolTableKind.Static ? "symtab" : "dynsym")}");
        }

        if (TableIndex is { } index)
        {
            parts.Add($"index={index}");
        }

        if (Address is { } address)
        {
            parts.Add($"address=0x{address:X}");
        }

        return parts.Count == 0 ? "<empty>" : string.Join(", ", parts);
    }
}

public sealed record FunctionSelectionResult(
    IReadOnlyList<ElfFunctionSymbol> Functions,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public static class FunctionSelectorResolver
{
    public static FunctionSelectionResult Resolve(
        ElfFile file,
        IReadOnlyList<FunctionSelector> selectors)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(selectors);
        var diagnostics = new DiagnosticBag();
        var functions = new List<ElfFunctionSymbol>();
        var seen = new HashSet<(ElfSymbolTableKind Table, uint Index)>();
        foreach (var selector in selectors)
        {
            if (!IsValid(selector, out var selectorError))
            {
                diagnostics.Error(DiagnosticCode.InvalidArgument, selectorError);
                continue;
            }

            var matches = file.FunctionSymbols
                .Where(function => Matches(function, selector))
                .ToArray();
            if (matches.Length == 0)
            {
                diagnostics.Error(
                    DiagnosticCode.FunctionNotFound,
                    DescribeMissing(selector));
                continue;
            }

            if (matches.Length > 1)
            {
                diagnostics.Error(
                    DiagnosticCode.FunctionSelectorAmbiguous,
                    $"Function selector '{Describe(selector)}' matches {matches.Length} symbol identities: "
                    + string.Join(", ", matches.Select(Describe)));
                continue;
            }

            var match = matches[0];
            if (seen.Add((match.Table, match.TableIndex)))
            {
                functions.Add(match);
            }
        }

        return new FunctionSelectionResult(functions, diagnostics.ToArray());
    }

    private static bool Matches(ElfFunctionSymbol function, FunctionSelector selector)
    {
        return (selector.Name is null || string.Equals(function.Name, selector.Name, StringComparison.Ordinal))
            && (!selector.Table.HasValue || function.Table == selector.Table.Value)
            && (!selector.TableIndex.HasValue || function.TableIndex == selector.TableIndex.Value)
            && (!selector.Address.HasValue || function.Value == selector.Address.Value);
    }

    private static bool IsValid(FunctionSelector selector, out string message)
    {
        if (!selector.HasCriteria)
        {
            message = "A function selector must specify an exact name, table/index identity, or address.";
            return false;
        }

        if (selector.Name is { Length: 0 })
        {
            message = "A function selector name must not be empty.";
            return false;
        }

        if (selector.TableIndex.HasValue && !selector.Table.HasValue)
        {
            message = "A function table index requires an explicit symtab or dynsym table.";
            return false;
        }

        message = string.Empty;
        return true;
    }

    private static string DescribeMissing(FunctionSelector selector) =>
        $"Function selector '{Describe(selector)}' did not match a unique STT_FUNC symbol.";

    private static string Describe(FunctionSelector selector)
    {
        var parts = new List<string>();
        if (selector.Name is { } name)
        {
            parts.Add($"name={name}");
        }

        if (selector.Table is { } table)
        {
            parts.Add($"table={Describe(table)}");
        }

        if (selector.TableIndex is { } index)
        {
            parts.Add($"index={index}");
        }

        if (selector.Address is { } address)
        {
            parts.Add($"address=0x{address:X}");
        }

        return parts.Count == 0 ? "<empty>" : string.Join(", ", parts);
    }

    private static string Describe(ElfSymbolTableKind table) =>
        table == ElfSymbolTableKind.Static ? "symtab" : "dynsym";

    private static string Describe(ElfFunctionSymbol function) =>
        $"{Describe(function.Table)}[{function.TableIndex}] {function.Name}@0x{function.Value:X}+0x{function.Size:X}";
}
