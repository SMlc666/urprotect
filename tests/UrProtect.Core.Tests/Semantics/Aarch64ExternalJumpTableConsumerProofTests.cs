using System.Buffers.Binary;
using System.Text;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Semantics;

public sealed class Aarch64ExternalJumpTableConsumerProofTests
{
    private const ulong FunctionAddress = 0x1000;
    private const ulong GotPageAddress = 0x2000;
    private const ulong GotAddress = 0x2200;
    private const string ProviderSoname = "liburprotect-jump-table-provider.so.1";
    private const string TableSymbolName = "urp_external_jump_table";
    private static readonly string[] ExpectedTargetNames = { "case_0", "case_1", "case_2", "case_3" };

    [Theory]
    [InlineData("none")]
    [InlineData("sxtx-identity-target-add")]
    public void SelectedFunctionQueryProvesExactProviderBoundedConsumerWithoutAdmittingProductionAnalysis(string mutation)
    {
        var fixture = CreateFixture(mutation);
        var compare = fixture.Instructions[0].Decode.Instruction!;
        Assert.Equal("subs", compare.Mnemonic, ignoreCase: true);
        Assert.True(compare.Properties.HasFlag(Aarch64InstructionProperties.WritesNzcv));
        Assert.Contains(compare.Operands, operand =>
            operand.Kind == Aarch64OperandKind.Register
            && operand.Direction == Aarch64OperandDirection.Output
            && operand.Register is { Class: Aarch64RegisterClass.General, Width: 32, Role: Aarch64RegisterRole.Zero });
        var tableAdd = fixture.Instructions[5].Decode.Instruction!;
        if (mutation == "sxtx-identity-target-add")
        {
            var identityModifier = Assert.Single(tableAdd.Operands, operand =>
                operand.Kind == Aarch64OperandKind.EncodedField
                && operand.Codec == "arith_extendlsl64");
            Assert.Equal("Sxtx", identityModifier.RegisterModifierKind);
            Assert.Equal(0, identityModifier.RegisterModifierAmount);
        }
        else
        {
            var tableDisplacement = Assert.Single(tableAdd.Operands, operand =>
                operand.Direction == Aarch64OperandDirection.Input
                && operand.Register is { Class: Aarch64RegisterClass.General, Index: 2 });
            Assert.True(tableDisplacement.RegisterModifierKind is null
                || tableDisplacement.RegisterModifierKind == "Lsl" && tableDisplacement.RegisterModifierAmount == 0);
        }

        var success = Aarch64JumpTableResolver.TryProveExternalProviderTableConsumer(
            fixture.Instructions,
            branchIndex: 6,
            fixture.Function,
            fixture.File,
            CreateProviderFacts(),
            out var proof,
            out var failure);

        Assert.True(success, failure);
        var result = Assert.IsType<Aarch64ExternalJumpTableConsumerProof>(proof);
        Assert.Equal(fixture.Function, result.SelectedFunction);
        Assert.Equal(FunctionAddress, result.CompareAddress);
        Assert.Equal(FunctionAddress + 4, result.BoundsBranchAddress);
        Assert.Equal(FunctionAddress + (7 * sizeof(uint)), result.SafeDefaultAddress);
        Assert.Equal(new[]
        {
            FunctionAddress + (7 * sizeof(uint)),
            FunctionAddress + (8 * sizeof(uint)),
        }, result.SafeDefaultPathAddresses);
        Assert.Equal(new[]
        {
            FunctionAddress + (2 * sizeof(uint)),
            FunctionAddress + (3 * sizeof(uint)),
            FunctionAddress + (4 * sizeof(uint)),
            FunctionAddress + (5 * sizeof(uint)),
            FunctionAddress + (6 * sizeof(uint)),
        }, result.ProducerAddresses);
        Assert.Equal(GotAddress, result.GotSlotAddress.Value);
        Assert.Equal(GotAddress, result.GotSlotFileOffset.Value);
        Assert.Equal((byte)0, result.IndexRegister.Index);
        Assert.Equal((byte)32, result.IndexRegister.Width);
        Assert.Equal((byte)9, result.GotPointerRegister.Index);
        Assert.Equal((byte)2, result.LoadedDisplacementRegister.Index);
        Assert.Equal((byte)1, result.TargetRegister.Index);
        Assert.Equal(4, result.EntryWidth);
        Assert.True(result.IsSigned);
        Assert.Equal(2, result.IndexScaleShift);
        Assert.Equal(0, result.LowerBound);
        Assert.Equal(3, result.UpperBound);
        Assert.Equal(TableSymbolName, result.ImportOwner.SymbolName);
        Assert.Equal((uint)1, result.ImportOwner.SymbolIndex);
        Assert.Equal(ElfConstants.SttObject, result.ImportOwner.SymbolType);
        Assert.Equal(1, result.ImportOwner.SymbolBinding);
        Assert.Equal(ElfConstants.RArm64GlobDat, result.ImportOwner.Relocation.Type);
        Assert.False(result.ImportOwner.Relocation.IsPlt);
        Assert.Equal("provider-table-proof-4", result.ProviderFacts.TableIdentity);
        Assert.Equal(ProviderSoname, result.ProviderFacts.ProviderSoname);
        Assert.Equal("a1b2c3d4", result.ProviderFacts.ProviderBuildIdHex);
        Assert.Equal(new string('a', 64), result.ProviderFacts.ProviderSha256);
        Assert.Equal(new string('b', 64), result.ProviderFacts.TableBytesSha256);
        Assert.Equal(ExpectedTargetNames, result.ProviderFacts.TargetSymbols.Select(target => target.SymbolName));

        var productionAnalysis = new Aarch64FunctionAnalyzer().Analyze(fixture.File, fixture.Function);
        Assert.False(productionAnalysis.IsComplete);
        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, productionAnalysis.Status);
        Assert.Contains(productionAnalysis.Diagnostics, diagnostic =>
            diagnostic.Code is UrProtect.Core.Diagnostics.DiagnosticCode.IndirectTargetUnresolved
                or UrProtect.Core.Diagnostics.DiagnosticCode.IndirectTargetUnsupported);
    }

    [Fact]
    public void PinnedProviderReaderFactsBindTheConsumersDependencyAndImportedObjectIdentity()
    {
        var providerFixture = SemanticExternalJumpTableProviderReaderTests.ProviderElf.Create();
        var providerRead = SemanticExternalJumpTableProviderReader.Read(
            providerFixture.Bytes,
            SemanticExternalJumpTableProviderReaderTests.ProviderElf.Soname,
            SemanticExternalJumpTableProviderReaderTests.ProviderElf.BuildIdHex,
            SemanticExternalJumpTableProviderReaderTests.ProviderElf.Hash(providerFixture.Bytes),
            SemanticExternalJumpTableProviderReaderTests.ProviderElf.TableIdentity);
        Assert.True(providerRead.IsSuccess, string.Join(Environment.NewLine, providerRead.Diagnostics));
        var providerFacts = Assert.IsType<Aarch64ExternalJumpTableProviderFacts>(providerRead.CreateConsumerProofInput());
        var consumerFixture = CreateFixture(providerSoname: providerFacts.ProviderSoname);

        var success = Aarch64JumpTableResolver.TryProveExternalProviderTableConsumer(
            consumerFixture.Instructions,
            branchIndex: 6,
            consumerFixture.Function,
            consumerFixture.File,
            providerFacts,
            out var proof,
            out var failure);

        Assert.True(success, failure);
        var result = Assert.IsType<Aarch64ExternalJumpTableConsumerProof>(proof);
        Assert.Equal(providerFacts.ProviderSoname, Assert.Single(consumerFixture.File.DynamicMetadata.NeededLibraries));
        Assert.Equal(providerFacts.TableObjectName, result.ImportOwner.SymbolName);
        Assert.Equal(providerFacts.ProviderSha256, result.ProviderFacts.ProviderSha256);
        Assert.Equal(providerFacts.ProviderBuildIdHex, result.ProviderFacts.ProviderBuildIdHex);
    }

    [Fact]
    public void ProviderFactsRejectAnOverlongTargetEnumerableAfterOnlyRequiredCountPlusOneReads()
    {
        var observed = 0;

        IEnumerable<Aarch64ExternalProviderTargetIdentity> OverlongTargetSequence()
        {
            while (true)
            {
                var index = observed++;
                yield return new Aarch64ExternalProviderTargetIdentity(index, $"case_{index}");
            }
        }

        var exception = Assert.Throws<ArgumentException>(() => new Aarch64ExternalJumpTableProviderFacts(
            "provider-table-proof-4",
            ProviderSoname,
            "a1b2c3d4",
            new string('a', 64),
            TableSymbolName,
            Aarch64ExternalJumpTableProviderFacts.RequiredTableByteLength,
            new string('b', 64),
            OverlongTargetSequence()));

        Assert.Contains("Exactly 4 provider target identities are required.", exception.Message, StringComparison.Ordinal);
        Assert.Equal(Aarch64ExternalJumpTableProviderFacts.RequiredEntryCount + 1, observed);
    }

    [Theory]
    [InlineData("subs-index-clobber")]
    [InlineData("shifted-target-add")]
    [InlineData("uxtw-target-add")]
    [InlineData("sxtx-shifted-target-add")]
    public void SourceByteMutationsDoNotProduceAnExternalConsumerProof(string mutation)
    {
        var fixture = CreateFixture(mutation);
        if (mutation == "subs-index-clobber")
        {
            var compare = fixture.Instructions[0].Decode.Instruction!;
            Assert.Equal("subs", compare.Mnemonic, ignoreCase: true);
            Assert.Contains(compare.Operands, operand =>
                operand.Kind == Aarch64OperandKind.Register
                && operand.Direction == Aarch64OperandDirection.Output
                && operand.Register is { Class: Aarch64RegisterClass.General, Index: 0, Width: 32, Role: Aarch64RegisterRole.None });
        }
        else
        {
            var add = fixture.Instructions[5].Decode.Instruction!;
            Assert.Equal("add", add.Mnemonic, ignoreCase: true);
            if (mutation == "sxtx-shifted-target-add")
            {
                var modifier = Assert.Single(add.Operands, operand =>
                    operand.Kind == Aarch64OperandKind.EncodedField
                    && operand.Codec == "arith_extendlsl64");
                Assert.Equal("Sxtx", modifier.RegisterModifierKind);
                Assert.Equal(1, modifier.RegisterModifierAmount);
            }
            else
            {
                var expectedModifier = mutation switch
                {
                    "shifted-target-add" => (Kind: "Lsl", Amount: 1),
                    "uxtw-target-add" => (Kind: "Uxtw", Amount: 0),
                    _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
                };
                var displacement = Assert.Single(add.Operands, operand =>
                    operand.Direction == Aarch64OperandDirection.Input
                    && operand.Register is { Class: Aarch64RegisterClass.General, Index: 2 });
                Assert.Equal(expectedModifier.Kind, displacement.RegisterModifierKind);
                Assert.Equal(expectedModifier.Amount, displacement.RegisterModifierAmount);
            }
        }

        var proof = Aarch64JumpTableResolver.TryProveExternalProviderTableConsumer(
            fixture.Instructions,
            branchIndex: 6,
            fixture.Function,
            fixture.File,
            CreateProviderFacts(),
            out var result,
            out var failure);

        Assert.False(proof, mutation);
        Assert.Null(result);
        Assert.Equal(mutation == "subs-index-clobber"
            ? "The selected external-table index does not have one CMP/B.HI proof exactly bounded to the verified four-entry provider table."
            : "The selected BR does not have the exact ordered ADRP/GOT-LDR/indexed-LDRSW/table-base-ADD register-flow chain.", failure);
    }

    [Theory]
    [InlineData("missing-dynsym")]
    [InlineData("duplicate-dynsym")]
    [InlineData("wrong-dynsym-type")]
    [InlineData("missing-rela")]
    [InlineData("duplicate-rela")]
    [InlineData("wrong-rela-type")]
    [InlineData("duplicate-symbol-owner")]
    [InlineData("wrong-got-slot")]
    [InlineData("nonwritable-got")]
    [InlineData("non-file-backed-got")]
    [InlineData("duplicate-got-map")]
    [InlineData("missing-dependency")]
    [InlineData("duplicate-dependency")]
    [InlineData("extra-dependency")]
    [InlineData("provider-soname-mismatch")]
    [InlineData("provider-symbol-mismatch")]
    [InlineData("provider-identity-path")]
    [InlineData("version-tag")]
    [InlineData("rpath")]
    [InlineData("index-clobber")]
    [InlineData("base-clobber")]
    [InlineData("bad-load-width")]
    [InlineData("bad-load-scale")]
    [InlineData("out-of-range-bounds")]
    [InlineData("default-enters-dispatch")]
    [InlineData("default-branches-unsafely")]
    public void NearestExternalConsumerProofNegativesFailClosed(string mutation)
    {
        var fixture = CreateFixture(mutation);

        var success = Aarch64JumpTableResolver.TryProveExternalProviderTableConsumer(
            fixture.Instructions,
            branchIndex: 6,
            fixture.Function,
            fixture.File,
            CreateProviderFacts(mutation),
            out var proof,
            out var failure);

        Assert.False(success, mutation);
        Assert.Null(proof);
        Assert.False(string.IsNullOrWhiteSpace(failure));
        var expectedFailure = mutation switch
        {
            "duplicate-rela" => "The external provider GOT slot does not have one exact non-PLT R_AARCH64_GLOB_DAT owner.",
            "duplicate-symbol-owner" => "The imported provider table symbol has duplicate or ambiguous dynamic relocation owners.",
            _ => null,
        };
        if (expectedFailure is not null)
        {
            Assert.Equal(expectedFailure, failure);
        }
    }

    private static Aarch64ExternalJumpTableProviderFacts CreateProviderFacts(string mutation = "none") =>
        new(
            mutation == "provider-identity-path" ? "/operator/provider.so" : "provider-table-proof-4",
            mutation == "provider-soname-mismatch" ? "libwrong-provider.so.1" : ProviderSoname,
            "a1b2c3d4",
            new string('a', 64),
            mutation == "provider-symbol-mismatch" ? "wrong_provider_table" : TableSymbolName,
            Aarch64ExternalJumpTableProviderFacts.RequiredTableByteLength,
            new string('b', 64),
            Enumerable.Range(0, 4)
                .Select(index => new Aarch64ExternalProviderTargetIdentity(index, $"case_{index}")));

    private static ConsumerFixture CreateFixture(string mutation = "none", string? providerSoname = null)
    {
        var configuredProviderSoname = providerSoname ?? ProviderSoname;
        var encoder = new Aarch64InstructionEncoder();
        var words = new uint[9];
        words[0] = Create(encoder, new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.CompareImmediate,
            FunctionAddress,
            mutation == "out-of-range-bounds" ? 4UL : 3UL,
            BaseRegister: 0,
            DestinationWidth: 32));
        words[1] = Create(encoder, new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.ConditionalBranch19,
            FunctionAddress + sizeof(uint),
            mutation == "default-enters-dispatch"
                ? FunctionAddress + (4 * sizeof(uint))
                : FunctionAddress + (7 * sizeof(uint)),
            ConditionCode: 8));
        words[2] = Create(encoder, new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
            FunctionAddress + (2 * sizeof(uint)),
            GotPageAddress,
            DestinationRegister: mutation == "index-clobber" ? (byte)0 : (byte)9));
        words[3] = Create(encoder, new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate,
            FunctionAddress + (3 * sizeof(uint)),
            0x200,
            DestinationRegister: mutation == "index-clobber" ? (byte)0 : (byte)9,
            BaseRegister: mutation == "index-clobber" ? (byte)0 : (byte)9,
            DestinationWidth: 64,
            AccessWidth: 64));

        var indexedLoad = Permute(
            encoder,
            0xB8A05822u,
            FunctionAddress + (4 * sizeof(uint)),
            new Dictionary<byte, byte>
            {
                [1] = mutation switch
                {
                    "index-clobber" => 0,
                    "base-clobber" => 10,
                    _ => 9,
                },
            });
        if (mutation == "bad-load-width")
        {
            indexedLoad = Create(encoder, new Aarch64InstructionBuildRequest(
                Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate,
                FunctionAddress + (4 * sizeof(uint)),
                0,
                DestinationRegister: 2,
                BaseRegister: 9,
                DestinationWidth: 32,
                AccessWidth: 32));
        }
        else if (mutation == "bad-load-scale")
        {
            indexedLoad = FindValidInstructionMutation(
                indexedLoad,
                FunctionAddress + (4 * sizeof(uint)),
                decoder => decoder.Mnemonic.Equals("ldrsw", StringComparison.OrdinalIgnoreCase)
                    && decoder.Operands.Select(operand => operand.Memory).FirstOrDefault(memory => memory is not null)
                        is { IndexModifierKind: "Uxtw", IndexModifierAmount: not 2 });
        }

        words[4] = indexedLoad;
        words[5] = Permute(
            encoder,
            0x8B020061u,
            FunctionAddress + (5 * sizeof(uint)),
            new Dictionary<byte, byte> { [3] = 9 });
        words[6] = Permute(
            encoder,
            0xD61F0020u,
            FunctionAddress + (6 * sizeof(uint)),
            new Dictionary<byte, byte>());
        words[7] = Create(encoder, new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.MoveWideImmediate,
            FunctionAddress + (7 * sizeof(uint)),
            0,
            DestinationRegister: 0,
            DestinationWidth: 32));
        words[8] = Create(encoder, new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.Return,
            FunctionAddress + (8 * sizeof(uint)),
            0));

        if (mutation == "default-branches-unsafely")
        {
            words[7] = Create(encoder, new Aarch64InstructionBuildRequest(
                Aarch64InstructionEncodingFamily.Branch26,
                FunctionAddress + (7 * sizeof(uint)),
                FunctionAddress + (4 * sizeof(uint))));
        }

        if (mutation == "subs-index-clobber")
        {
            words[0] = (words[0] & ~0x1Fu) | 0u;
        }
        else if (mutation == "shifted-target-add")
        {
            words[5] = (words[5] & ~0xFC00u) | (1u << 10);
        }
        else if (mutation == "uxtw-target-add")
        {
            words[5] = (words[5] & ~(0x200000u | 0xE000u | 0x1C00u))
                | 0x200000u
                | (2u << 13);
        }
        else if (mutation is "sxtx-shifted-target-add" or "sxtx-identity-target-add")
        {
            words[5] = (words[5] & ~(0x200000u | 0xE000u | 0x1C00u))
                | 0x200000u
                | (7u << 13)
                | (mutation == "sxtx-shifted-target-add" ? 1u << 10 : 0u);
        }
        var providerBytes = Encoding.UTF8.GetBytes(configuredProviderSoname);
        var tableNameBytes = Encoding.UTF8.GetBytes(TableSymbolName);
        var entryNameBytes = Encoding.UTF8.GetBytes("urp_entry");
        var stringTable = new byte[1 + providerBytes.Length + 1 + tableNameBytes.Length + 1 + entryNameBytes.Length + 1];
        var providerNameOffset = 1;
        providerBytes.CopyTo(stringTable.AsSpan(providerNameOffset));
        var tableNameOffset = providerNameOffset + providerBytes.Length + 1;
        tableNameBytes.CopyTo(stringTable.AsSpan(tableNameOffset));
        var entryNameOffset = tableNameOffset + tableNameBytes.Length + 1;
        entryNameBytes.CopyTo(stringTable.AsSpan(entryNameOffset));

        var bytes = new byte[0x4000];
        for (var index = 0; index < words.Length; index++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(
                bytes.AsSpan(0x1000 + (index * sizeof(uint)), sizeof(uint)),
                words[index]);
        }

        var neededLibraries = mutation switch
        {
            "missing-dependency" => Array.Empty<string>(),
            "duplicate-dependency" => new[] { configuredProviderSoname, configuredProviderSoname },
            "extra-dependency" => new[] { configuredProviderSoname, "libc.so.6" },
            _ => new[] { configuredProviderSoname },
        };
        var declaredNonPltRelocationCount = mutation is "duplicate-rela" or "duplicate-symbol-owner"
            ? 2UL
            : 1UL;
        var dynamicEntries = new List<DynamicEntry>
        {
            new(ElfConstants.DtNeeded, checked((ulong)providerNameOffset)),
            new(ElfConstants.DtStrTab, 0x2300),
            new(ElfConstants.DtStrSz, checked((ulong)stringTable.Length)),
            new(ElfConstants.DtSymTab, 0x2400),
            new(ElfConstants.DtSymEnt, ElfConstants.SymbolEntrySize64),
            new(ElfConstants.DtRela, 0x2500),
            new(ElfConstants.DtRelaSz, checked(declaredNonPltRelocationCount * ElfConstants.RelaEntrySize64)),
            new(ElfConstants.DtRelaEnt, ElfConstants.RelaEntrySize64),
        };
        if (mutation == "missing-dependency")
        {
            dynamicEntries.RemoveAt(0);
        }
        else if (mutation == "duplicate-dependency")
        {
            dynamicEntries.Insert(1, new DynamicEntry(ElfConstants.DtNeeded, checked((ulong)providerNameOffset)));
        }
        else if (mutation == "extra-dependency")
        {
            dynamicEntries.Insert(1, new DynamicEntry(ElfConstants.DtNeeded, checked((ulong)providerNameOffset)));
        }
        else if (mutation == "version-tag")
        {
            dynamicEntries.Add(new DynamicEntry(ElfConstants.DtVersym, 0x2600));
        }
        else if (mutation == "rpath")
        {
            dynamicEntries.Add(new DynamicEntry(ElfConstants.DtRunPath, 0));
        }

        dynamicEntries.Add(new DynamicEntry(ElfConstants.DtNull, 0));
        stringTable.CopyTo(bytes.AsSpan(0x2300));

        var symbols = new List<DynamicSymbol>
        {
            default,
            new(
                checked((uint)tableNameOffset),
                (byte)((1 << 4) | ElfConstants.SttObject),
                0,
                0,
                0,
                0),
            new(
                checked((uint)entryNameOffset),
                (byte)((1 << 4) | ElfConstants.SttFunc),
                0,
                1,
                FunctionAddress,
                9 * sizeof(uint)),
        };
        if (mutation == "missing-dynsym")
        {
            symbols.RemoveAt(1);
        }
        else if (mutation == "duplicate-dynsym")
        {
            symbols.Add(symbols[1]);
        }
        else if (mutation == "wrong-dynsym-type")
        {
            symbols[1] = symbols[1] with { Info = (byte)((1 << 4) | ElfConstants.SttFunc) };
        }

        var gotOffset = mutation == "wrong-got-slot" ? GotAddress + sizeof(ulong) : GotAddress;
        var relocation = new RelaRelocation(
            gotOffset,
            (1UL << 32) | ElfConstants.RArm64GlobDat,
            0,
            0x2500,
            IsPlt: false);
        var relocations = mutation switch
        {
            "missing-rela" => Array.Empty<RelaRelocation>(),
            "duplicate-rela" => new[] { relocation, relocation },
            "wrong-rela-type" => new[] { relocation with { Info = (1UL << 32) | ElfConstants.RArm64JumpSlot } },
            "duplicate-symbol-owner" => new[]
            {
                relocation,
                relocation with { Offset = checked(gotOffset + sizeof(ulong)), SourceAddress = 0x2518 },
            },
            _ => new[] { relocation },
        };
        if (mutation == "wrong-got-slot")
        {
            gotOffset = GotAddress;
        }

        var rwFileSize = mutation == "non-file-backed-got" ? 0x200UL : 0x2000UL;
        var rwFlags = mutation == "nonwritable-got"
            ? ElfConstants.PfR
            : ElfConstants.PfR | ElfConstants.PfW;
        var programHeaders = new List<ProgramHeader>
        {
            new(ElfConstants.PtLoad, ElfConstants.PfR | ElfConstants.PfX,
                0x1000, 0x1000, 0, 0x1000, 0x1000, 0x1000),
            new(ElfConstants.PtLoad, rwFlags,
                0x2000, 0x2000, 0, rwFileSize, 0x2000, 0x1000),
            new(ElfConstants.PtDynamic, ElfConstants.PfR | ElfConstants.PfW,
                0x2080, 0x2080, 0, checked((ulong)dynamicEntries.Count * ElfConstants.DynamicEntrySize64),
                checked((ulong)dynamicEntries.Count * ElfConstants.DynamicEntrySize64), 8),
        };
        if (mutation == "duplicate-got-map")
        {
            programHeaders.Add(new ProgramHeader(
                ElfConstants.PtLoad,
                ElfConstants.PfR | ElfConstants.PfW,
                GotAddress,
                GotAddress,
                0,
                sizeof(ulong),
                sizeof(ulong),
                sizeof(ulong)));
        }

        var loadMap = LoadMap.Create(programHeaders);
        var function = new ElfFunctionSymbol(
            "urp_entry",
            ElfSymbolTableKind.Dynamic,
            2,
            1,
            0,
            1,
            FunctionAddress,
            9 * sizeof(uint));
        var dynamicMetadata = new ElfDynamicMetadata(
            neededLibraries,
            "libexternal-consumer.so",
            mutation == "rpath" ? "." : null,
            null,
            stringTable);
        var file = new ElfFile(
            bytes,
            new ElfHeader(
                ElfConstants.TypeDyn,
                ElfConstants.MachineAarch64,
                ElfConstants.HeaderVersionCurrent,
                0,
                64,
                0,
                0,
                ElfConstants.HeaderSize64,
                ElfConstants.ProgramHeaderSize64,
                checked((ushort)programHeaders.Count),
                ElfConstants.SectionHeaderSize64,
                0,
                0),
            Array.AsReadOnly(programHeaders.ToArray()),
            Array.Empty<SectionHeader>(),
            loadMap,
            Array.Empty<ElfNote>(),
            dynamicMetadata,
            ElfSymbolVersionMetadata.Empty,
            Array.AsReadOnly(dynamicEntries.ToArray()),
            Array.AsReadOnly(relocations),
            Array.Empty<ElfSectionRelocation>(),
            Array.Empty<RelrWord>(),
            Array.Empty<AndroidPackedRelocationTable>(),
            Array.AsReadOnly(symbols.ToArray()),
            new[] { function },
            ElfTlsMetadata.Empty);

        var decoder = new AsmStoneAdapter();
        var instructions = new List<Aarch64FunctionInstruction>(words.Length);
        for (var index = 0; index < words.Length; index++)
        {
            var address = checked(FunctionAddress + ((ulong)index * sizeof(uint)));
            var fileOffset = checked(0x1000UL + ((ulong)index * sizeof(uint)));
            var encoding = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(checked((int)fileOffset), sizeof(uint)));
            var decoded = decoder.Decode(encoding, address);
            Assert.True(decoded.IsSuccess, decoded.Diagnostic);
            instructions.Add(new Aarch64FunctionInstruction(fileOffset, address, encoding, decoded));
        }

        return new ConsumerFixture(file, function, Array.AsReadOnly(instructions.ToArray()));
    }

    private static uint Create(Aarch64InstructionEncoder encoder, Aarch64InstructionBuildRequest request)
    {
        var result = encoder.TryCreate(request);
        Assert.True(result.IsSuccess, result.Diagnostic);
        return result.Encoding;
    }

    private static uint Permute(
        Aarch64InstructionEncoder encoder,
        uint encoding,
        ulong address,
        IReadOnlyDictionary<byte, byte> mapping)
    {
        var result = encoder.TryPermuteGeneralRegisters(encoding, address, mapping);
        Assert.True(result.IsSuccess, result.Diagnostic);
        return result.Encoding;
    }

    private static uint FindValidInstructionMutation(
        uint sourceEncoding,
        ulong address,
        Func<Aarch64Instruction, bool> predicate)
    {
        var decoder = new AsmStoneAdapter();
        for (var bit = 0; bit < sizeof(uint) * 8; bit++)
        {
            var candidate = sourceEncoding ^ (1u << bit);
            var decoded = decoder.Decode(candidate, address);
            if (decoded.Instruction is { } instruction && predicate(instruction))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException("No one-bit decoded instruction mutation satisfied the requested negative boundary.");
    }

    private sealed record ConsumerFixture(
        ElfFile File,
        ElfFunctionSymbol Function,
        IReadOnlyList<Aarch64FunctionInstruction> Instructions);
}
