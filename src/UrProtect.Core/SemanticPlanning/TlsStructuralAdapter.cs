using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

public sealed record TlsStructuralProjectionResult<T>(T? Value, IReadOnlyList<Diagnostic> Diagnostics)
    where T : class
{
    public bool IsSuccess => Value is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Projects the one bounded StructuralElf TLS owner into the current typed semantic
/// model. Runtime-assigned module numbers remain unresolved and are never synthesized.
/// </summary>
public static class TlsStructuralAdapter
{
    public static TlsStructuralProjectionResult<TlsModuleIdentity> CreateImageModule(ElfFile file)
    {
        ArgumentNullException.ThrowIfNull(file);
        var diagnostics = new DiagnosticBag();
        if (file.TlsMetadata.Segments.Count != 1)
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                "An image-local TLS module identity requires exactly one validated PT_TLS segment.");
            return Failure<TlsModuleIdentity>(diagnostics);
        }

        var segment = file.TlsMetadata.Segments[0];
        var imageDigest = Convert.ToHexString(SHA256.HashData(file.Bytes.Span)).ToLowerInvariant();
        var templateDigest = Convert.ToHexString(SHA256.HashData(segment.InitializedTemplate.Span)).ToLowerInvariant();
        var template = new TlsTemplateContract(
            segment.TemplateFileOffset,
            segment.TemplateAddress,
            segment.FileSize,
            segment.MemorySize,
            segment.Alignment,
            segment.Permissions,
            segment.OwningLoadProgramHeaderIndex,
            templateDigest);
        return new TlsStructuralProjectionResult<TlsModuleIdentity>(
            new TlsModuleIdentity(
                TlsModuleIdentityKind.ImageLocal,
                $"image:{imageDigest}",
                file.DynamicMetadata.Soname,
                RuntimeModuleIndex: null,
                template),
            diagnostics.ToArray());
    }

    public static TlsSymbolIdentity? ProjectSymbol(TlsRelocationSymbolIdentity? symbol) => symbol is null
        ? null
        : new TlsSymbolIdentity(
            symbol.SymbolIndex,
            symbol.Name,
            symbol.Binding,
            symbol.Type,
            symbol.Visibility,
            symbol.SectionIndex,
            symbol.Value,
            symbol.Size,
            IsDefined: symbol.SectionIndex != 0);

    public static TlsStructuralProjectionResult<TlsGotEntryBinding> ProjectGotEntry(
        ElfFile file,
        TlsModuleIdentity module,
        TlsSymbolIdentity symbol,
        long addend)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(module);
        var diagnostics = new DiagnosticBag();
        var facts = file.TlsMetadata.StaticRelocations
            .Concat(file.TlsMetadata.Dynamic.Relocations)
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsTprel64
                && fact.Symbol is not null
                && fact.Symbol.SymbolIndex == symbol.SymbolIndex
                && string.Equals(fact.Symbol.Name, symbol.Name, StringComparison.Ordinal)
                && fact.Relocation.Addend == addend)
            .ToArray();
        if (facts.Length != 1)
        {
            diagnostics.Error(
                facts.Length == 0 ? DiagnosticCode.TlsBindingUnresolved : DiagnosticCode.TlsMetadataMalformed,
                facts.Length == 0
                    ? "The TLSIE MOVW sequence has no unique R_AARCH64_TLS_TPREL64 GOT entry for its symbol and addend."
                    : "The TLSIE MOVW sequence has duplicate or overlapping GOT ownership for its symbol and addend.",
                facts.Length == 0 ? null : facts[0].Relocation.Offset);
            return Failure<TlsGotEntryBinding>(diagnostics);
        }

        var fact = facts[0];
        if (fact.Relocation.IsPlt
            || fact.WriteSize != sizeof(ulong)
            || fact.Relocation.Offset % sizeof(ulong) != 0
            || !file.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(fact.Relocation.Offset),
                sizeof(ulong),
                out var fileOffset)
            || file.LoadMap.Segments.Count(segment => segment.ContainsVirtualAddress(fact.Relocation.Offset, sizeof(ulong))
                && segment.ContainsFileOffset(fileOffset.Value, sizeof(ulong))
                && (segment.Flags & ElfConstants.PfW) != 0) != 1)
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                "The TLSIE GOT entry is not one uniquely mapped, writable, file-backed 8-byte source range.",
                fact.Relocation.Offset);
            return Failure<TlsGotEntryBinding>(diagnostics);
        }

        var overlappingTlsFacts = file.TlsMetadata.StaticRelocations
            .Concat(file.TlsMetadata.Dynamic.Relocations)
            .Where(candidate => !ReferenceEquals(candidate, fact)
                && RangesOverlap(
                    candidate.Relocation.Offset,
                    candidate.WriteSize,
                    fact.Relocation.Offset,
                    fact.WriteSize))
            .ToArray();
        if (overlappingTlsFacts.Length != 0)
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                "The TLSIE GOT entry overlaps another retained TLS relocation target.",
                fact.Relocation.Offset);
            return Failure<TlsGotEntryBinding>(diagnostics);
        }

        var target = SemanticTarget.RuntimeResolved($"tls-got:{module.Identity}:{symbol.Name}");
        var relocation = RelocationBinding.FromRelocation(fact.Relocation, target, symbol.Name);
        var range = new SemanticSourceRange(
            fileOffset,
            new VirtualAddress(fact.Relocation.Offset),
            sizeof(ulong));
        return new TlsStructuralProjectionResult<TlsGotEntryBinding>(
            new TlsGotEntryBinding(
                SemanticEntityId.RelocationSite($"tls-got:{fact.Relocation.Offset:X}"),
                range,
                relocation,
                symbol,
                addend),
            diagnostics.ToArray());
    }

    public static TlsStructuralProjectionResult<TlsRelocationSite> ProjectRelocationSite(
        ElfFile file,
        TlsModuleIdentity module,
        TlsRelocationFacts fact,
        int pairOrdinal)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(fact);
        var diagnostics = new DiagnosticBag();
        var relocationType = fact.Relocation.Type;
        var family = TlsRelocationClassifier.GetFamily(relocationType);
        if (family is null)
        {
            diagnostics.Error(
                DiagnosticCode.TlsSemanticsUnsupported,
                $"AArch64 TLS relocation type {relocationType} has no typed semantic family.",
                fact.Relocation.SourceAddress);
            return Failure<TlsRelocationSite>(diagnostics);
        }

        if (pairOrdinal < 0 || fact.WriteSize == 0
            || fact.WriteSize != TlsRelocationClassifier.GetWriteSize(relocationType)
            || !file.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(fact.Relocation.Offset),
                fact.WriteSize,
                out var fileOffset))
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                "A TLS relocation target has no bounded typed source range.",
                fact.Relocation.Offset);
            return Failure<TlsRelocationSite>(diagnostics);
        }

        var symbol = ProjectSymbol(fact.Symbol);
        var runtimeBinding = symbol is not null
            ? $"tls-symbol:{module.Identity}:{symbol.Name}"
            : $"tls-module:{module.Identity}";
        var target = SemanticTarget.RuntimeResolved(runtimeBinding);
        var binding = RelocationBinding.FromRelocation(
            fact.Relocation,
            target,
            symbol?.Name);
        var range = new SemanticSourceRange(
            fileOffset,
            new VirtualAddress(fact.Relocation.Offset),
            fact.WriteSize);
        var isGotOwned = family is TlsRelocationFamily.GotTprel or TlsRelocationFamily.TlsDesc
            || (fact.IsDynamic && relocationType is
                ElfConstants.RArm64TlsDtpMod64
                or ElfConstants.RArm64TlsDtpRel64
                or ElfConstants.RArm64TlsTprel64
                or ElfConstants.RArm64TlsDesc);
        return new TlsStructuralProjectionResult<TlsRelocationSite>(
            new TlsRelocationSite(family.Value, range, binding, pairOrdinal, isGotOwned),
            diagnostics.ToArray());
    }

    private static TlsStructuralProjectionResult<T> Failure<T>(DiagnosticBag diagnostics)
        where T : class => new(null, diagnostics.ToArray());

    private static bool RangesOverlap(ulong leftStart, ulong leftSize, ulong rightStart, ulong rightSize) =>
        leftStart <= rightStart
            ? rightStart - leftStart < leftSize
            : leftStart - rightStart < rightSize;
}
