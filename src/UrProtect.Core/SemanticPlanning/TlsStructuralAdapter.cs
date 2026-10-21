using System.Buffers.Binary;
using System.Security.Cryptography;
using UrProtect.Core.Aarch64Semantics;
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
        if (segment.OwningLoadProgramHeaderIndex < 0)
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                "Managed TLS projection requires a PT_TLS template with an owning PT_LOAD.");
            return Failure<TlsModuleIdentity>(diagnostics);
        }

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
                && SymbolsMatch(fact.Symbol, symbol)
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

    /// <summary>
    /// Projects the loader-owned DTPMOD64 GOT owner without attaching it to the
    /// selected function's instruction-site list.
    /// </summary>
    public static TlsStructuralProjectionResult<TlsModuleOwnerBinding> ProjectModuleOwner(
        ElfFile file,
        TlsModuleIdentity module)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(module);
        var diagnostics = new DiagnosticBag();
        var facts = file.TlsMetadata.Dynamic.Relocations
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsDtpMod64)
            .ToArray();
        if (facts.Length != 1)
        {
            diagnostics.Error(
                facts.Length == 0 ? DiagnosticCode.TlsBindingUnresolved : DiagnosticCode.TlsMetadataMalformed,
                facts.Length == 0
                    ? "The local-dynamic TLS sequence has no unique loader-owned DTPMOD64 relocation."
                    : "The local-dynamic TLS sequence has duplicate DTPMOD64 module owners.",
                facts.Length == 0 ? null : facts[0].Relocation.Offset);
            return Failure<TlsModuleOwnerBinding>(diagnostics);
        }

        var fact = facts[0];
        if (fact.WriteSize != sizeof(ulong)
            || fact.Symbol is not null
            || fact.Relocation.SymbolIndex != 0
            || fact.Relocation.Addend != 0
            || !file.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(fact.Relocation.Offset),
                sizeof(ulong),
                out var fileOffset)
            || file.LoadMap.Segments.Count(segment =>
                segment.ContainsVirtualAddress(fact.Relocation.Offset, sizeof(ulong))
                && segment.ContainsFileOffset(fileOffset.Value, sizeof(ulong))
                && (segment.Flags & ElfConstants.PfW) != 0) != 1)
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                "The DTPMOD64 module owner is not one aligned, writable, file-backed loader-owned GOT range.",
                fact.Relocation.Offset);
            return Failure<TlsModuleOwnerBinding>(diagnostics);
        }

        var target = SemanticTarget.RuntimeResolved($"tls-module:{module.Identity}");
        var relocation = RelocationBinding.FromRelocation(fact.Relocation, target);
        var range = new SemanticSourceRange(
            fileOffset,
            new VirtualAddress(fact.Relocation.Offset),
            sizeof(ulong));
        return new TlsStructuralProjectionResult<TlsModuleOwnerBinding>(
            new TlsModuleOwnerBinding(
                SemanticEntityId.RelocationSite($"tls-module-owner:{fact.Relocation.Offset:X}"),
                range,
                relocation),
            diagnostics.ToArray());
    }

    /// <summary>
    /// Projects the two loader-owned TLSGD GOT words. The module and symbol
    /// owners must be adjacent, writable, file-backed DTPMOD64/DTPREL64 records
    /// for one dynamic TLS symbol.
    /// </summary>
    public static TlsStructuralProjectionResult<TlsGeneralDynamicOwnerBinding> ProjectGeneralDynamicOwners(
        ElfFile file,
        TlsModuleIdentity module,
        TlsSymbolIdentity symbol,
        long addend)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(symbol);
        var diagnostics = new DiagnosticBag();
        var dynamicFacts = file.TlsMetadata.Dynamic.Relocations;
        var moduleFacts = dynamicFacts
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsDtpMod64
                && string.Equals(fact.Symbol?.Name, symbol.Name, StringComparison.Ordinal)
                && fact.Relocation.Addend == 0)
            .ToArray();
        var dtpRelFacts = dynamicFacts
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsDtpRel64
                && string.Equals(fact.Symbol?.Name, symbol.Name, StringComparison.Ordinal)
                && fact.Relocation.Addend == addend)
            .ToArray();
        if (moduleFacts.Length != 1 || dtpRelFacts.Length != 1)
        {
            diagnostics.Error(
                moduleFacts.Length == 0 || dtpRelFacts.Length == 0
                    ? DiagnosticCode.TlsBindingUnresolved
                    : DiagnosticCode.TlsMetadataMalformed,
                "The TLSGD access does not have one matching loader-owned DTPMOD64/DTPREL64 owner pair.",
                moduleFacts.Length == 1
                    ? dtpRelFacts.Length == 1 ? dtpRelFacts[0].Relocation.Offset : moduleFacts[0].Relocation.Offset
                    : null);
            return Failure<TlsGeneralDynamicOwnerBinding>(diagnostics);
        }

        var moduleFact = moduleFacts[0];
        var dtpRelFact = dtpRelFacts[0];
        if (!IsWritableTlsOwner(file, moduleFact, out var moduleOffset)
            || !IsWritableTlsOwner(file, dtpRelFact, out var dtpRelOffset)
            || moduleFact.Relocation.Offset > ulong.MaxValue - sizeof(ulong)
            || moduleFact.Relocation.Offset + sizeof(ulong) != dtpRelFact.Relocation.Offset
            || moduleOffset.Value > ulong.MaxValue - sizeof(ulong)
            || moduleOffset.Value + sizeof(ulong) != dtpRelOffset.Value)
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                "The TLSGD DTPMOD64/DTPREL64 owner pair is not adjacent, aligned, writable, and file-backed.",
                moduleFact.Relocation.Offset);
            return Failure<TlsGeneralDynamicOwnerBinding>(diagnostics);
        }

        var moduleRelocation = RelocationBinding.FromRelocation(
            moduleFact.Relocation,
            SemanticTarget.RuntimeResolved($"tls-module:{module.Identity}:{symbol.Name}"),
            symbol.Name);
        var dtpRelocation = RelocationBinding.FromRelocation(
            dtpRelFact.Relocation,
            SemanticTarget.RuntimeResolved($"tls-symbol:{module.Identity}:{symbol.Name}"),
            symbol.Name);
        var moduleRange = new SemanticSourceRange(
            moduleOffset,
            new VirtualAddress(moduleFact.Relocation.Offset),
            sizeof(ulong));
        var dtpRelRange = new SemanticSourceRange(
            dtpRelOffset,
            new VirtualAddress(dtpRelFact.Relocation.Offset),
            sizeof(ulong));
        return new TlsStructuralProjectionResult<TlsGeneralDynamicOwnerBinding>(
            new TlsGeneralDynamicOwnerBinding(
                new TlsModuleOwnerBinding(
                    SemanticEntityId.RelocationSite($"tls-module-owner:{moduleFact.Relocation.Offset:X}"),
                    moduleRange,
                    moduleRelocation),
                new TlsDtpRelOwnerBinding(
                    SemanticEntityId.RelocationSite($"tls-dtprel-owner:{dtpRelFact.Relocation.Offset:X}"),
                    dtpRelRange,
                    dtpRelocation)),
            diagnostics.ToArray());
    }

    private static bool IsWritableTlsOwner(
        ElfFile file,
        TlsRelocationFacts fact,
        out FileOffset fileOffset)
    {
        fileOffset = default;
        if (!file.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(fact.Relocation.Offset),
                sizeof(ulong),
                out fileOffset))
        {
            return false;
        }

        var mappedFileOffset = fileOffset;
        var writableOwnerCount = file.LoadMap.Segments.Count(segment =>
            segment.ContainsVirtualAddress(fact.Relocation.Offset, sizeof(ulong))
            && segment.ContainsFileOffset(mappedFileOffset.Value, sizeof(ulong))
            && (segment.Flags & ElfConstants.PfW) != 0);
        return writableOwnerCount == 1;
    }

    /// <summary>One paired TLSGD loader-owner projection.</summary>
    public sealed record TlsGeneralDynamicOwnerBinding(
        TlsModuleOwnerBinding ModuleOwner,
        TlsDtpRelOwnerBinding DtpRelOwner);

    /// <summary>
    /// Projects the exact resolver call carrier for a linked image. The linked
    /// image retains the resolver as a JUMP_SLOT owner rather than a source
    /// CALL26 RELA, so the selected direct-call word is paired with that unique
    /// loader binding while retaining CALL26 semantic kind for rewriting.
    /// </summary>
    public static bool IsExactResolverCall(ElfFile file, SemanticSourceRange sourceRange) =>
        ProjectResolverCall(file, sourceRange).IsSuccess;

    public static TlsStructuralProjectionResult<TlsResolverCallBinding> ProjectResolverCall(
        ElfFile file,
        SemanticSourceRange sourceRange)
    {
        ArgumentNullException.ThrowIfNull(file);
        var diagnostics = new DiagnosticBag();
        var candidates = file.RelaRelocations
            .Where(relocation => relocation.IsPlt && relocation.Type == ElfConstants.RArm64JumpSlot)
            .Select(relocation => (relocation, Name: TryGetDynamicSymbolName(file, relocation.SymbolIndex)))
            .Where(item => string.Equals(item.Name, "__tls_get_addr", StringComparison.Ordinal))
            .ToArray();
        if (candidates.Length != 1
            || !sourceRange.IsInstructionRange
            || sourceRange.Size != sizeof(uint)
            || !file.LoadMap.TryVirtualAddressToFileOffset(
                sourceRange.VirtualAddress,
                sizeof(uint),
                out var sourceOffset)
            || sourceOffset != sourceRange.FileOffset
            || !TryReadWord(file, sourceOffset, out var sourceEncoding))
        {
            diagnostics.Error(
                candidates.Length == 0 ? DiagnosticCode.TlsBindingUnresolved : DiagnosticCode.TlsMetadataMalformed,
                candidates.Length == 0
                    ? "The dynamic TLS sequence has no unique loader-owned __tls_get_addr resolver binding."
                    : "The selected dynamic TLS call is not a bounded direct CALL26 with a decoded target.",
                sourceRange.FileOffset.Value);
            return Failure<TlsResolverCallBinding>(diagnostics);
        }

        var sourceDecode = new AsmStoneAdapter().Decode(sourceEncoding, sourceRange.VirtualAddress.Value);
        if (!sourceDecode.IsSuccess
            || sourceDecode.Instruction?.ControlFlow != Aarch64ControlFlowKind.DirectCall
            || sourceDecode.Instruction.DirectTarget is not { } resolverStubAddress)
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                "The selected dynamic TLS call is not a bounded direct CALL26 with a decoded target.",
                sourceRange.FileOffset.Value);
            return Failure<TlsResolverCallBinding>(diagnostics);
        }

        var jumpSlot = candidates[0].relocation;
        var writable = IsWritableFileBackedRange(file, jumpSlot.Offset, sizeof(ulong));
        var exactStub = IsExactAarch64PltStub(file, resolverStubAddress, jumpSlot.Offset);
        if (!writable || !exactStub)
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                "The dynamic TLS CALL26 target is not an executable AArch64 PLT stub owned by the __tls_get_addr JUMP_SLOT.",
                sourceRange.FileOffset.Value);
            return Failure<TlsResolverCallBinding>(diagnostics);
        }

        var target = SemanticTarget.RuntimeResolved("symbol:__tls_get_addr");
        var binding = new RelocationBinding(
            Aarch64RelocationKind.Call26,
            target,
            jumpSlot.Addend,
            jumpSlot.SymbolIndex,
            IsPlt: false,
            SymbolName: "__tls_get_addr",
            RelocationType: ElfConstants.RArm64Call26,
            RelocationAddress: sourceRange.VirtualAddress,
            RelocationTableAddress: new VirtualAddress(jumpSlot.SourceAddress));
        return new TlsStructuralProjectionResult<TlsResolverCallBinding>(
            new TlsResolverCallBinding(sourceRange, binding),
            diagnostics.ToArray());
    }

    private static bool IsExactAarch64PltStub(
        ElfFile file,
        ulong stubAddress,
        ulong jumpSlotAddress)
    {
        if ((stubAddress & 0xF) != 0
            || !IsExecutableFileBackedRange(file, stubAddress, 4 * sizeof(uint)))
        {
            return false;
        }

        var adapter = new AsmStoneAdapter();
        var instructions = new Aarch64DecodeResult[4];
        for (var index = 0; index < instructions.Length; index++)
        {
            if (!TryAdd(stubAddress, (ulong)index * sizeof(uint), out var address)
                || !file.LoadMap.TryVirtualAddressToFileOffset(
                    new VirtualAddress(address),
                    sizeof(uint),
                    out var offset)
                || offset.Value > int.MaxValue
                || offset.Value > (ulong)file.Bytes.Length
                || sizeof(uint) > (ulong)file.Bytes.Length - offset.Value)
            {
                return false;
            }

            var word = BinaryPrimitives.ReadUInt32LittleEndian(
                file.Bytes.Span.Slice(checked((int)offset.Value), sizeof(uint)));
            instructions[index] = adapter.Decode(word, address);
            if (!instructions[index].IsSuccess)
            {
                return false;
            }
        }

        var adrp = instructions[0].Instruction!;
        var load = instructions[1].Instruction!;
        var add = instructions[2].Instruction!;
        var branch = instructions[3].Instruction!;
        var gotPageTarget = adrp.DirectTarget.GetValueOrDefault();
        var memory = load.Operands
            .Where(operand => operand.Memory is not null)
            .Select(operand => operand.Memory)
            .FirstOrDefault();
        var addImmediate = add.Operands
            .Where(operand => operand.Immediate.HasValue)
            .Select(operand => operand.Immediate)
            .FirstOrDefault();
        var validShape = adrp.Properties.HasFlag(Aarch64InstructionProperties.PcRelative)
            && adrp.DirectTarget.HasValue
            && HasRegister(adrp, Aarch64OperandDirection.Output, 16)
            && load.Properties.HasFlag(Aarch64InstructionProperties.Load)
            && HasRegister(load, Aarch64OperandDirection.Output, 17)
            && memory is not null
            && memory.Base is { Class: Aarch64RegisterClass.General, Index: 16, Width: 64 }
            && memory.Index is null
            && memory.AccessSize == sizeof(ulong)
            && !memory.WritesBack
            && string.Equals(add.Mnemonic, "add", StringComparison.OrdinalIgnoreCase)
            && HasRegister(add, Aarch64OperandDirection.Input, 16)
            && HasRegister(add, Aarch64OperandDirection.Output, 16)
            && addImmediate.HasValue
            && addImmediate.Value >= 0
            && string.Equals(branch.Mnemonic, "br", StringComparison.OrdinalIgnoreCase)
            && branch.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
            && HasRegister(branch, Aarch64OperandDirection.Input, 17);
        if (!validShape)
        {
            return false;
        }

        var gotPage = gotPageTarget & ~0xFFFUL;
        var loaded = TryAddSigned(gotPage, memory!.Offset, out var loadedGotAddress);
        var added = TryAddSigned(gotPage, addImmediate!.Value, out var addedGotAddress);
        if (!loaded || !added || loadedGotAddress != jumpSlotAddress || addedGotAddress != jumpSlotAddress)
        {
            return false;
        }

        return true;
    }

    private static bool HasRegister(
        Aarch64Instruction instruction,
        Aarch64OperandDirection direction,
        byte index) => instruction.Operands.Any(operand =>
        (operand.Direction == direction
            || (direction == Aarch64OperandDirection.Input
                && operand.Direction == Aarch64OperandDirection.InputOutput)
            || (direction == Aarch64OperandDirection.Output
                && operand.Direction == Aarch64OperandDirection.InputOutput))
        && ((operand.Register is
            {
                Class: Aarch64RegisterClass.General,
                Role: Aarch64RegisterRole.None,
                Width: 64,
            } register
            && register.Index == index)
            || (operand.Memory?.Base is
                {
                    Class: Aarch64RegisterClass.General,
                    Role: Aarch64RegisterRole.None,
                    Width: 64,
                } memoryBase
                && memoryBase.Index == index)));

    private static bool IsWritableFileBackedRange(ElfFile file, ulong address, ulong size) =>
        file.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(address), size, out var fileOffset)
        && file.LoadMap.Segments.Count(segment =>
            segment.ContainsVirtualAddress(address, size)
            && segment.ContainsFileOffset(fileOffset.Value, size)
            && (segment.Flags & ElfConstants.PfW) != 0) == 1;

    private static bool IsExecutableFileBackedRange(ElfFile file, ulong address, ulong size) =>
        file.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(address), size, out var fileOffset)
        && file.LoadMap.Segments.Count(segment =>
            segment.ContainsVirtualAddress(address, size)
            && segment.ContainsFileOffset(fileOffset.Value, size)
            && (segment.Flags & ElfConstants.PfX) != 0) == 1;

    private static bool TryReadWord(ElfFile file, FileOffset fileOffset, out uint value)
    {
        value = 0;
        if (fileOffset.Value > int.MaxValue
            || fileOffset.Value > (ulong)file.Bytes.Length
            || sizeof(uint) > (ulong)file.Bytes.Length - fileOffset.Value)
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt32LittleEndian(
            file.Bytes.Span.Slice(checked((int)fileOffset.Value), sizeof(uint)));
        return true;
    }

    private static bool TryAdd(ulong value, ulong amount, out ulong result)
    {
        if (amount > ulong.MaxValue - value)
        {
            result = 0;
            return false;
        }

        result = value + amount;
        return true;
    }

    private static bool TryAddSigned(ulong value, long addend, out ulong result)
    {
        if (addend >= 0)
        {
            if ((ulong)addend > ulong.MaxValue - value)
            {
                result = 0;
                return false;
            }

            result = value + (ulong)addend;
            return true;
        }

        var magnitude = unchecked((ulong)(-(addend + 1))) + 1;
        if (magnitude > value)
        {
            result = 0;
            return false;
        }

        result = value - magnitude;
        return true;
    }

    /// <summary>
    /// Projects the one bounded per-symbol TLSDESC owner and the distinct
    /// resolver DT_TLSDESC_GOT slot. The descriptor relocation writes eight
    /// bytes, but its source/layout ownership is the complete sixteen-byte
    /// descriptor range.
    /// </summary>
    public static TlsStructuralProjectionResult<TlsDescriptorOwnerBinding> ProjectDescriptorOwner(
        ElfFile file,
        TlsModuleIdentity module,
        TlsSymbolIdentity symbol,
        long addend)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(symbol);
        var diagnostics = new DiagnosticBag();
        var candidates = file.TlsMetadata.Dynamic.Relocations
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsDesc)
            .Where(fact => fact.IsDynamic
                && fact.Relocation.IsPlt
                && fact.Symbol is not null
                && string.Equals(fact.Symbol.Name, symbol.Name, StringComparison.Ordinal)
                && fact.Relocation.Addend == addend)
            .ToArray();
        var allOwners = file.TlsMetadata.Dynamic.Relocations
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsDesc)
            .ToArray();
        if (allOwners.Length != 1 || candidates.Length != 1)
        {
            diagnostics.Error(
                allOwners.Length == 0 || candidates.Length == 0
                    ? DiagnosticCode.TlsBindingUnresolved
                    : DiagnosticCode.TlsMetadataMalformed,
                allOwners.Length == 0 || candidates.Length == 0
                    ? "The TLSDESC access has no unique loader-owned R_AARCH64_TLSDESC owner for its TLS symbol and addend."
                    : "The TLSDESC image has duplicate or mismatched loader-owned descriptor owners.",
                allOwners.Length == 0 ? null : allOwners[0].Relocation.Offset);
            return Failure<TlsDescriptorOwnerBinding>(diagnostics);
        }

        var fact = candidates[0];
        if (fact.Symbol is null
            || fact.Symbol.Type != ElfConstants.SttTls
            || fact.Symbol.SectionIndex == 0
            || fact.WriteSize != sizeof(ulong)
            || fact.Relocation.Addend != 0
            || addend != 0
            || !TryGetDynamicAddress(file, ElfConstants.DtTlsDescPlt, out var descriptorPlt)
            || !TryGetDynamicAddress(file, ElfConstants.DtTlsDescGot, out var descriptorGot)
            || !TryGetDynamicAddress(file, ElfConstants.DtPltGot, out var pltGot)
            || fact.Relocation.Offset > ulong.MaxValue - (2 * sizeof(ulong))
            || !file.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(fact.Relocation.Offset),
                2 * sizeof(ulong),
                out var descriptorFileOffset)
            || !IsWritableFileBackedRange(file, fact.Relocation.Offset, 2 * sizeof(ulong))
            || !IsWritableFileBackedRange(file, descriptorGot, sizeof(ulong))
            || !IsWritableFileBackedRange(file, pltGot, sizeof(ulong))
            || descriptorGot == fact.Relocation.Offset
            || RangesOverlap(descriptorGot, sizeof(ulong), fact.Relocation.Offset, 2 * sizeof(ulong))
            || !IsExecutableFileBackedRange(file, descriptorPlt, 6 * sizeof(uint))
            || !IsExactTlsDescResolverStub(file, descriptorPlt, descriptorGot, pltGot))
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                "The TLSDESC owner must be a defined TLS symbol with a writable file-backed 16-byte descriptor, paired tags, and the exact resolver PLT/GOT shape.",
                fact.Relocation.Offset);
            return Failure<TlsDescriptorOwnerBinding>(diagnostics);
        }

        var descriptorRange = new SemanticSourceRange(
            descriptorFileOffset,
            new VirtualAddress(fact.Relocation.Offset),
            2 * sizeof(ulong));
        var resolverPltFileOffset = file.LoadMap.TryVirtualAddressToFileOffset(
            descriptorPlt,
            6 * sizeof(uint),
            out var resolverPltOffset)
            ? resolverPltOffset
            : default;
        var resolverGotFileOffset = file.LoadMap.TryVirtualAddressToFileOffset(
            descriptorGot,
            sizeof(ulong),
            out var resolverGotOffset)
            ? resolverGotOffset
            : default;
        var resolverPltRange = new SemanticSourceRange(
            new FileOffset(resolverPltFileOffset),
            new VirtualAddress(descriptorPlt),
            6 * sizeof(uint));
        var resolverGotRange = new SemanticSourceRange(
            new FileOffset(resolverGotFileOffset),
            new VirtualAddress(descriptorGot),
            sizeof(ulong));
        var relocation = RelocationBinding.FromRelocation(
            fact.Relocation,
            SemanticTarget.RuntimeResolved($"tls-descriptor:{module.Identity}:{symbol.Name}"),
            symbol.Name);
        return new TlsStructuralProjectionResult<TlsDescriptorOwnerBinding>(
            new TlsDescriptorOwnerBinding(
                SemanticEntityId.RelocationSite($"tls-descriptor:{fact.Relocation.Offset:X}"),
                descriptorRange,
                relocation,
                symbol,
                addend,
                new VirtualAddress(descriptorPlt),
                new VirtualAddress(descriptorGot),
                new VirtualAddress(pltGot),
                resolverPltRange,
                resolverGotRange),
            diagnostics.ToArray());
    }

    private static bool TryGetDynamicAddress(ElfFile file, ulong tag, out ulong value)
    {
        var entries = file.DynamicEntries.Where(entry => entry.Tag == tag).ToArray();
        value = entries.Length == 1 ? entries[0].Value : 0;
        return entries.Length == 1 && value != 0;
    }

    private static bool IsExactTlsDescResolverStub(
        ElfFile file,
        ulong pltAddress,
        ulong resolverGotAddress,
        ulong pltGotAddress)
    {
        var adapter = new AsmStoneAdapter();
        var instructions = new Aarch64DecodeResult[6];
        for (var index = 0; index < instructions.Length; index++)
        {
            if (!TryAdd(pltAddress, (ulong)index * sizeof(uint), out var address)
                || !file.LoadMap.TryVirtualAddressToFileOffset(
                    new VirtualAddress(address),
                    sizeof(uint),
                    out var offset)
                || !TryReadWord(file, offset, out var word))
            {
                return false;
            }

            instructions[index] = adapter.Decode(word, address);
            if (!instructions[index].IsSuccess)
            {
                return false;
            }
        }

        var stp = instructions[0].Instruction!;
        var stpMemory = stp.Operands.Select(operand => operand.Memory).FirstOrDefault(memory => memory is not null);
        var stackFrameValid = string.Equals(stp.Mnemonic, "stp", StringComparison.OrdinalIgnoreCase)
            && stpMemory is { Base: { Role: Aarch64RegisterRole.StackPointer }, Offset: -16, WritesBack: true };

        var adrpResolver = instructions[1].Instruction!;
        var resolverLoad = instructions[2].Instruction!;
        var resolverAdd = instructions[3].Instruction!;
        var resolverBranch = instructions[4].Instruction!;
        var resolverLoadMemory = resolverLoad.Operands
            .Select(operand => operand.Memory)
            .FirstOrDefault(memory => memory is not null);
        var resolverPage = adrpResolver.DirectTarget;
        var resolverAddressValid = resolverPage.HasValue
            && resolverLoadMemory is not null
            && TryAddSigned(resolverPage.Value & ~0xFFFUL, resolverLoadMemory.Offset, out var resolvedGot)
            && resolvedGot == resolverGotAddress;

        var gnuStyle = stackFrameValid
            && HasRegister(stp, Aarch64OperandDirection.Input, 16)
            && HasRegister(stp, Aarch64OperandDirection.Input, 30)
            && string.Equals(adrpResolver.Mnemonic, "adrp", StringComparison.OrdinalIgnoreCase)
            && HasRegister(adrpResolver, Aarch64OperandDirection.Output, 16)
            && string.Equals(resolverLoad.Mnemonic, "ldr", StringComparison.OrdinalIgnoreCase)
            && HasRegister(resolverLoad, Aarch64OperandDirection.Output, 17)
            && resolverLoadMemory is
            {
                Base: { Class: Aarch64RegisterClass.General, Index: 16, Width: 64 },
                Index: null,
                AccessSize: 8,
                WritesBack: false,
            }
            && resolverAddressValid
            && string.Equals(resolverAdd.Mnemonic, "add", StringComparison.OrdinalIgnoreCase)
            && HasRegister(resolverAdd, Aarch64OperandDirection.Input, 16)
            && HasRegister(resolverAdd, Aarch64OperandDirection.Output, 16)
            && resolverAdd.Operands.Select(operand => operand.Immediate).Any(value => value is >= 0)
            && string.Equals(resolverBranch.Mnemonic, "br", StringComparison.OrdinalIgnoreCase)
            && resolverBranch.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
            && HasRegister(resolverBranch, Aarch64OperandDirection.Input, 17);

        var adrpPltGot = instructions[2].Instruction!;
        var load = instructions[3].Instruction!;
        var add = instructions[4].Instruction!;
        var branch = instructions[5].Instruction!;
        var loadMemory = load.Operands.Select(operand => operand.Memory).FirstOrDefault(memory => memory is not null);
        var addImmediate = add.Operands.Select(operand => operand.Immediate).FirstOrDefault(value => value.HasValue);
        var pltGotPage = adrpPltGot.DirectTarget;
        var pltGotAddressValid = pltGotPage.HasValue
            && addImmediate.HasValue
            && TryAddSigned(pltGotPage.Value & ~0xFFFUL, addImmediate.Value, out var resolvedPltGot)
            && (resolvedPltGot == pltGotAddress || resolvedPltGot == resolverGotAddress);
        var legacyResolverAddressValid = resolverPage.HasValue
            && loadMemory is not null
            && TryAddSigned(resolverPage.Value & ~0xFFFUL, loadMemory.Offset, out var legacyResolvedGot)
            && legacyResolvedGot == resolverGotAddress;
        var legacyStyle = stackFrameValid
            && HasRegister(stp, Aarch64OperandDirection.Input, 2)
            && HasRegister(stp, Aarch64OperandDirection.Input, 3)
            && string.Equals(adrpResolver.Mnemonic, "adrp", StringComparison.OrdinalIgnoreCase)
            && HasRegister(adrpResolver, Aarch64OperandDirection.Output, 2)
            && string.Equals(adrpPltGot.Mnemonic, "adrp", StringComparison.OrdinalIgnoreCase)
            && HasRegister(adrpPltGot, Aarch64OperandDirection.Output, 3)
            && string.Equals(load.Mnemonic, "ldr", StringComparison.OrdinalIgnoreCase)
            && HasRegister(load, Aarch64OperandDirection.Output, 2)
            && loadMemory is { Base: { Class: Aarch64RegisterClass.General, Index: 2, Width: 64 }, Index: null, AccessSize: 8, WritesBack: false }
            && legacyResolverAddressValid
            && string.Equals(add.Mnemonic, "add", StringComparison.OrdinalIgnoreCase)
            && HasRegister(add, Aarch64OperandDirection.Input, 3)
            && HasRegister(add, Aarch64OperandDirection.Output, 3)
            && addImmediate is { } immediate
            && immediate >= 0
            && pltGotAddressValid
            && string.Equals(branch.Mnemonic, "br", StringComparison.OrdinalIgnoreCase)
            && branch.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
            && HasRegister(branch, Aarch64OperandDirection.Input, 2);
        return gnuStyle || legacyStyle;
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

    private static string? TryGetDynamicSymbolName(ElfFile file, uint symbolIndex)
    {
        if (symbolIndex >= file.DynamicSymbols.Count)
        {
            return null;
        }

        var symbol = file.DynamicSymbols[(int)symbolIndex];
        return ElfParserUtilities.TryReadString(file.DynamicMetadata.StringTable, symbol.Name, out var name)
            ? name
            : null;
    }

    private static TlsStructuralProjectionResult<T> Failure<T>(DiagnosticBag diagnostics)
        where T : class => new(null, diagnostics.ToArray());

    private static bool RangesOverlap(ulong leftStart, ulong leftSize, ulong rightStart, ulong rightSize) =>
        leftStart <= rightStart
            ? rightStart - leftStart < leftSize
            : leftStart - rightStart < rightSize;

    /// <summary>Compares TLS symbol meaning across dynamic and regular symbol tables.</summary>
    public static bool SymbolsMatch(TlsRelocationSymbolIdentity left, TlsSymbolIdentity right) =>
        string.Equals(left.Name, right.Name, StringComparison.Ordinal)
        && left.Binding == right.Binding
        && left.Type == right.SymbolType
        && left.Visibility == right.Visibility
        && left.SectionIndex == right.SectionIndex
        && left.Value == right.Value
        && left.Size == right.Size
        && right.IsDefined == (left.SectionIndex != 0);

    public static bool SymbolsMatch(TlsSymbolIdentity left, TlsSymbolIdentity right) =>
        string.Equals(left.Name, right.Name, StringComparison.Ordinal)
        && left.Binding == right.Binding
        && left.SymbolType == right.SymbolType
        && left.Visibility == right.Visibility
        && left.SectionIndex == right.SectionIndex
        && left.Value == right.Value
        && left.Size == right.Size
        && left.IsDefined == right.IsDefined;
}
