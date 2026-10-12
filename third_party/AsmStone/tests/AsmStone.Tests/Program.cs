using AsmStone;
using AsmStone.Decode;
using AsmStone.Encode;
using AsmStone.Encoding;
using AsmStone.Generated;
using AsmStone.Model;

AssertEqual("x0", A64Register.X(0).ToString());
AssertEqual("w7", A64Register.W(7).ToString());
AssertEqual("sp", A64Register.Sp().ToString());
AssertEqual("xzr", A64Register.Zr().ToString());

AssertEqual(0b101u, BitField.Read(0b101101u, 0, 3));
AssertEqual(0xAB00u, BitField.Insert(0, 0xAB, 8, 8));
AssertEqual(-1L, BitField.SignExtend(0x1Fu, 5));
AssertEqual(-2L, BitField.SignExtend(0x3FEu, 10));

AssertEncoded(Generated("NOP", "hint", [], 0, 0), 0, 0xD503201Fu);
AssertEncoded(
    Generated(
        "B",
        "b",
        [new TargetOperand(0x1010)],
        0,
        0x1000),
    0x1000,
    0x14000004u);
AssertEncoded(
    Generated(
        "BL",
        "bl",
        [new TargetOperand(0)],
        0,
        0x1000),
    0x1000,
    0x97FFFC00u);
AssertEncoded(
    Generated(
        "RET",
        "ret",
        [new RegisterOperand(A64Register.X(30))],
        0,
        0),
    0,
    0xD65F03C0u);
AssertEncoded(
    Generated(
        "ADDXri",
        "add",
        [
            new RegisterOperand(A64Register.X(0)),
            new RegisterOperand(A64Register.X(1)),
            new ImmediateOperand(0x2A),
        ],
        0,
        0),
    0,
    0x9100A820u);
AssertEncoded(
    Generated(
        "SUBWri",
        "sub",
            [
            new RegisterOperand(A64Register.Sp(32)),
            new RegisterOperand(A64Register.Sp(32)),
            new ImmediateOperand(0x1000),
        ],
        0,
        0),
    0,
    0x514007FFu);
AssertEncoded(
    Generated(
        "ADDSXri",
        "adds",
        [
            new RegisterOperand(A64Register.X(0)),
            new RegisterOperand(A64Register.Sp()),
            new ImmediateOperand(1),
        ],
        0,
        0),
    0,
    0xB10007E0u);
AssertEncoded(
    Generated(
        "ADDSXri",
        "adds",
        [
            new RegisterOperand(A64Register.Zr()),
            new RegisterOperand(A64Register.Sp()),
            new ImmediateOperand(1),
        ],
        0,
        0),
    0,
    0xB10007FFu);
AssertEncoded(
    Generated(
        "ADR",
        "adr",
        [new RegisterOperand(A64Register.X(3)), new TargetOperand(0x1010)],
        0,
        0x1000),
    0x1000,
    0x10000083u);
AssertEncoded(
    Generated(
        "ADRP",
        "adrp",
        [new RegisterOperand(A64Register.X(3)), new TargetOperand(0x5000)],
        0,
        0x1000),
    0x1000,
    0x90000023u);
AssertEncoded(
    Generated(
        "B",
        "b",
        [new TargetOperand(0xFFFFFFFFFFFFF010)],
        0,
        0xFFFFFFFFFFFFF000),
    0xFFFFFFFFFFFFF000,
    0x14000004u);

AssertEqual(A64InstructionId.Generated, Decode(0xD503201F, 0).Id);
if (!Decode(0x14000000, 0).Flags.HasFlag(A64InstructionFlags.IsTerminator)
    || !Decode(0xD65F03C0, 0).Flags.HasFlag(A64InstructionFlags.IsTerminator))
{
    throw new InvalidOperationException("Generated control-flow terminator flags are missing.");
}
AssertEqual(A64Register.Sp(), ((RegisterOperand)Decode(0xB10007E0, 0).Operands[1]).Register);
AssertEqual(A64Register.Zr(), ((RegisterOperand)Decode(0xB10007FF, 0).Operands[0]).Register);
AssertEqual(A64Register.Zr(), ((RegisterOperand)Decode(0x1000001F, 0).Operands[0]).Register);
AssertEqual(A64Register.Zr(), ((RegisterOperand)Decode(0xD61F03E0, 0).Operands[0]).Register);

AssertEqual(7484, A64InstructionCatalog.Count);
AssertEqual(456, A64InstructionCatalog.OperandTypeCount);
AssertEqual("87b1a2f7246bc0a4ed5335c45635bddb75847890", A64InstructionCatalog.SourceCommit);
AssertEqual("728f5eb9a7fb5d04f417e61e7f74181db7c17f1afebf512131c188be1066b82f", A64InstructionCatalog.TablegenInputSha256);
AssertEqual(8840, A64InstructionCatalog.SourceRecordCount);
AssertEqual(7484, A64InstructionCatalog.SourceCompleteEncodingCount);
AssertEqual(456, A64InstructionCatalog.SourceOperandTypeCount);
var generatedRecords = A64InstructionCatalog.Enumerate().ToArray();
AssertEqual(7484, generatedRecords.Length);
AssertEqual(7484, generatedRecords.Count(record => record.HasCompleteEncoding));

var generatedDescriptorCount = 0;
foreach (var descriptor in A64InstructionCatalog.EnumerateDescriptors())
{
    var descriptorIndex = generatedDescriptorCount++;
    AssertEqual(descriptorIndex, descriptor.Code.Value, $"descriptor code {descriptor.SourceName}");
    AssertEqual(generatedRecords[descriptorIndex].Name, descriptor.SourceName);
    if (!descriptor.HasCompleteEncoding)
    {
        continue;
    }

    foreach (var operand in descriptor.Operands)
    {
        if (operand.SourceType.Length == 0
            || operand.Codec.Name.Length == 0 && operand.Kind != A64OperandKind.EncodedField)
        {
            throw new InvalidOperationException(
                $"Typed descriptor is incomplete: {descriptor.SourceName}:{operand.Name}.");
        }

        if (operand.PcRelative.IsPresent
            && (operand.PcRelative.FieldWidth <= 0
                || operand.PcRelative.Alignment <= 0
                || operand.PcRelative.Relocation == A64RelocationKind.None))
        {
            throw new InvalidOperationException(
                $"PC-relative descriptor is incomplete: {descriptor.SourceName}:{operand.Name}.");
        }
    }
}
AssertEqual(generatedRecords.Length, generatedDescriptorCount);

if (!A64InstructionCatalog.TryGetDescriptor("ADRP", out var adrpDescriptor)
    || adrpDescriptor.Operands.First(operand => operand.Name == "label").PcRelative
        != new A64PcRelativeInfo(
            A64PcRelativeKind.Adrp21,
            21,
            12,
            4096,
            true,
            A64RelocationKind.AArch64AdrpPage21))
{
    throw new InvalidOperationException("ADRP typed PC-relative descriptor is incorrect.");
}

if (!A64InstructionCatalog.TryGetCode("B", out var branchCode)
    || !A64InstructionCatalog.TryGetDescriptor(branchCode, out var branchDescriptor)
    || branchDescriptor.Operands.First(operand => operand.Name == "addr").PcRelative.Kind
        != A64PcRelativeKind.Branch26)
{
    throw new InvalidOperationException("B typed instruction code/descriptor lookup failed.");
}

var codeConstructedMove = A64Instruction.Create(
    A64InstructionCatalog.TryGetCode("MOVZWi", out var moveCode)
        ? moveCode
        : throw new InvalidOperationException("MOVZWi code lookup failed."),
    [
        new RegisterOperand(A64Register.W(16)),
        new ImmediateOperand(0),
        new ImmediateOperand(0),
    ]);

if (!A64Encoder.TryEncode(codeConstructedMove, out var codeConstructedEncoding, out var codeConstructedDiagnostic)
    || codeConstructedEncoding != 0x52800010u
    || codeConstructedMove.SourceName != "MOVZWi"
    || codeConstructedMove.Code != moveCode)
{
    throw new InvalidOperationException($"Typed instruction construction failed: {codeConstructedDiagnostic}");
}
var rawFieldRoundTripCount = 0;
var rawFieldRepresentativeSkipCount = 0;
foreach (var record in generatedRecords.Where(record => record.HasCompleteEncoding))
{
    if (!A64InstructionCatalog.TryLookup(record.Value, A64FeatureSet.All, out _))
    {
        rawFieldRepresentativeSkipCount++;
        continue;
    }

    if (!A64InstructionCatalog.TryDecode(record.Value, A64FeatureSet.All, out var rawDecoded))
    {
        throw new InvalidOperationException($"Raw field decode failed for {record.Name}.");
    }

    var rawFields = rawDecoded.Fields.ToDictionary(field => field.Name, field => field.Value, StringComparer.Ordinal);
    if (!A64InstructionCatalog.TryEncodeFields(
            rawDecoded.Encoding.Name,
            rawFields,
            A64FeatureSet.All,
            out var rawRoundTrip,
            out var rawDiagnostic))
    {
        throw new InvalidOperationException($"Raw field encode failed for {record.Name}: {rawDiagnostic}");
    }

    AssertEqual(record.Value, rawRoundTrip, $"raw field {record.Name}");
    rawFieldRoundTripCount++;
}

AssertEqual(7484 - rawFieldRepresentativeSkipCount, rawFieldRoundTripCount);
AssertCatalog(0xD503201Fu, "NOP", "hint");
AssertCatalog(0x14000004u, "B", "b");
AssertCatalog(0x94000000u, "BL", "bl");
AssertCatalog(0xD65F03C0u, "RET", "ret");
AssertCatalog(0x9100A820u, "ADDXri", "add");
AssertCatalog(0xB9400000u, "LDRWui", "ldr");
AssertCatalog(0u, "UDF", "udf");
AssertCatalog(0xD500407Fu, "MSRpstateImm4", "msr");
AssertCatalog(0xD501401Fu, "MSRpstateImm1", "msr");
AssertCatalog(0xD50040DFu, "MSR", "msr");
var invalidAddSubShift = A64InstructionCatalog.TryLookup(0x51800000u, A64FeatureSet.All, out _);
var validAddSubShift = A64InstructionCatalog.TryLookup(0x51400000u, A64FeatureSet.All, out _);
var invalidMoveWideShift = A64InstructionCatalog.TryLookup(0x52C00000u, A64FeatureSet.All, out _);
var validMoveWideShift = A64InstructionCatalog.TryLookup(0x52A00000u, A64FeatureSet.All, out _);
var invalidMsrrPair = A64InstructionCatalog.TryLookup(0xD5400001u, A64FeatureSet.All, out _);
var invalidMsrrPair31 = A64InstructionCatalog.TryLookup(0xD540001Fu, A64FeatureSet.All, out _);
var validMsrrPair = A64InstructionCatalog.TryLookup(0xD5400000u, A64FeatureSet.All, out _);
if (invalidAddSubShift
    || !validAddSubShift
    || invalidMoveWideShift
    || !validMoveWideShift
    || invalidMsrrPair
    || invalidMsrrPair31
    || !validMsrrPair)
{
    throw new InvalidOperationException(
        $"Immediate/register-pair constraints are incorrect: "
        + $"add={invalidAddSubShift}/{validAddSubShift}, "
        + $"mov={invalidMoveWideShift}/{validMoveWideShift}, "
        + $"msrr={invalidMsrrPair}/{invalidMsrrPair31}/{validMsrrPair}.");
}
if (!A64InstructionCatalog.TryGetByName("DMB", out var dmbRecord)
    || !dmbRecord.Flags.HasFlag(A64InstructionFlags.HasSideEffects))
{
    throw new InvalidOperationException("Generated DMB side-effect flag is missing.");
}

if (!A64InstructionCatalog.TryGetByName("B", out var branchRecord)
    || !branchRecord.Flags.HasFlag(A64InstructionFlags.IsBarrier)
    || !branchRecord.Flags.HasFlag(A64InstructionFlags.IsTerminator))
{
    throw new InvalidOperationException("Generated branch control-flow flags are missing.");
}

if (!A64InstructionCatalog.TryGetByName("ADCSWr", out var adcsRecord)
    || !adcsRecord.Flags.HasFlag(A64InstructionFlags.ReadsNzcv)
    || !adcsRecord.Flags.HasFlag(A64InstructionFlags.WritesNzcv)
    || !A64InstructionCatalog.TryGetByName("FCMPDrr", out var fcmpRecord)
    || !fcmpRecord.Flags.HasFlag(A64InstructionFlags.ReadsFpcr)
    || !fcmpRecord.Flags.HasFlag(A64InstructionFlags.MayRaiseFpException)
    || !A64InstructionCatalog.TryGetByName("WRFFR", out var wrffrRecord)
    || !wrffrRecord.Flags.HasFlag(A64InstructionFlags.WritesFfr))
{
    throw new InvalidOperationException("Generated instruction effect flags are incomplete.");
}

if (!A64InstructionCatalog.TryGetByName("SUBSWri", out var compareRecord)
    || !compareRecord.Flags.HasFlag(A64InstructionFlags.IsCompare))
{
    throw new InvalidOperationException("Generated compare flag is missing.");
}

if (A64InstructionCatalog.TryLookup(0x4EA28420u, A64FeatureSet.Base, out _))
{
    throw new InvalidOperationException("NEON encoding must be gated out of Base.");
}

if (A64Decoder.TryDecode(0x4EA28420u, 0, A64FeatureSet.Base, out _, out var unsupportedNeonDiagnostic)
    || unsupportedNeonDiagnostic.Code != A64DiagnosticCode.UnsupportedFeature)
{
    throw new InvalidOperationException("Strict decode must distinguish an unsupported feature from an unknown encoding.");
}

if (!A64InstructionCatalog.TryLookup(0x4EA28420u, A64FeatureSet.From(A64Feature.Neon), out var neonInfo))
{
    throw new InvalidOperationException("NEON encoding must be enabled by the NEON profile.");
}

AssertEqual("ADDv4i32", neonInfo.Name);
if (!A64FeatureSet.From(A64Feature.Sme).Supports("HasSVE_or_SME"))
{
    throw new InvalidOperationException("SME must satisfy the LLVM SVE-or-SME predicate.");
}

if (!A64FeatureSet.FromPredicates(["HasSVE2p1"]).Supports("HasSVE2p1_or_StreamingSME2"))
{
    throw new InvalidOperationException("Explicit predicate profiles must support LLVM compound predicates.");
}
var cryptoProfile = A64FeatureSet.From(A64Feature.Crypto);
if (!cryptoProfile.Supports("HasNEON") || !cryptoProfile.Supports("HasFPARMv8"))
{
    throw new InvalidOperationException("Crypto profile must include its base floating/vector dependencies.");
}
if (!A64FeatureSet.From(A64Feature.FullFp16).Supports("HasFullFP16")
    || !A64FeatureSet.From(A64Feature.I8mm).Supports("HasMatMulInt8")
    || !A64FeatureSet.From(A64Feature.Sve2p2).Supports("HasSVE2p2")
    || !A64FeatureSet.From(A64Feature.Mte2).Supports("HasMTE2"))
{
    throw new InvalidOperationException("Extended AArch64 feature profiles are incomplete.");
}
if (!A64FeatureSet.From(A64Feature.Rcpc).Supports("HasRCPC_IMMO")
    || !A64FeatureSet.From(A64Feature.Ras).Supports("HasRASv2"))
{
    throw new InvalidOperationException("RCPC and RAS feature aliases are incomplete.");
}
if (A64InstructionCatalog.TryLookup(0x1EE02008u, A64FeatureSet.From(A64Feature.FloatingPoint), out _)
    || !A64InstructionCatalog.TryLookup(0x1EE02008u, A64FeatureSet.From(A64Feature.FullFp16), out var fp16Record)
    || fp16Record.Name != "FCMPHri")
{
    throw new InvalidOperationException("FP16 feature gating did not select the expected FCMPH record.");
}

var smeProfile = A64FeatureSet.From(A64Feature.Sme);
if (!smeProfile.Supports("HasSME2") || !smeProfile.Supports("HasSME2p3"))
{
    throw new InvalidOperationException("SME profile must include the current SME generation predicates.");
}
if (!A64FeatureSet.From(A64Feature.Sme, A64ExecutionMode.NonStreaming).Supports("HasSMEandIsNonStreamingSafe")
    || A64FeatureSet.From(A64Feature.Sme, A64ExecutionMode.NonStreaming).Supports("HasSMEandIsStreamingSafe")
    || !A64FeatureSet.From(A64Feature.Sme, A64ExecutionMode.Streaming).Supports("HasSMEandIsStreamingSafe"))
{
    throw new InvalidOperationException("SME execution mode predicates were not evaluated correctly.");
}
if (!A64FeatureSet.From(A64Feature.Sme, A64ExecutionMode.Streaming).Supports("HasSVE2p1_or_StreamingSME2")
    || A64FeatureSet.From(A64Feature.Sme, A64ExecutionMode.NonStreaming).Supports("HasSVE2p1_or_StreamingSME2")
    || !A64FeatureSet.From(A64Feature.Sve, A64ExecutionMode.NonStreaming).Supports("HasNonStreamingSVE_or_SME2"))
{
    throw new InvalidOperationException("Streaming and non-streaming compound predicates were not evaluated correctly.");
}
if (!A64FeatureSet.From(A64Feature.Neon | A64Feature.FloatingPoint, A64ExecutionMode.Streaming)
        .Supports("HasNEONandIsFPRCVTStreamingSafe")
    || A64FeatureSet.From(A64Feature.Neon | A64Feature.FloatingPoint, A64ExecutionMode.NonStreaming)
        .Supports("HasNEONandIsFPRCVTStreamingSafe"))
{
    throw new InvalidOperationException("Capability-qualified streaming predicates were not evaluated correctly.");
}
if (A64InstructionCatalog.TryLookup(0xC0080000u, A64FeatureSet.From(A64Feature.Sme), out _)
    || !A64InstructionCatalog.TryLookup(
        0xC0080000u,
        A64FeatureSet.From(A64Feature.Sme, A64ExecutionMode.NonStreaming),
        out var nonStreamingSmeRecord)
    || nonStreamingSmeRecord.Name != "ZERO_M")
{
    throw new InvalidOperationException("SME contextual gating did not select ZERO_M correctly.");
}
if (!A64Decoder.TryDecode(
        0xC0080000u,
        0,
        A64FeatureSet.From(A64Feature.Sme, A64ExecutionMode.NonStreaming),
        out var generatedZeroM,
        out var zeroMDiagnostic))
{
    throw new InvalidOperationException($"Generated ZERO_M decode failed: {zeroMDiagnostic}");
}

AssertEqual(0, ((MatrixTileMaskOperand)generatedZeroM.Operands[0]).Mask);
AssertGeneratedRoundTrip(generatedZeroM, 0xC0080000u);

if (!A64Decoder.TryDecode(
        0xE1000023u,
        0,
        A64FeatureSet.From(A64Feature.Sme, A64ExecutionMode.NonStreaming),
        out var generatedSmeSpill,
        out var smeSpillDiagnostic))
{
    throw new InvalidOperationException($"Generated SME spill/fill decode failed: {smeSpillDiagnostic}");
}

AssertEqual("LDR_ZA", generatedSmeSpill.SourceName);
var smeSpillMemory = (MemoryOperand)generatedSmeSpill.Operands[1];
AssertEqual(A64Register.X(1), smeSpillMemory.Base);
AssertEqual(3L, smeSpillMemory.Offset);
var smeSpillSemantics = generatedSmeSpill.GetOperandSemantics();
var smeSpillOffset = smeSpillSemantics.First(operand => operand.Name == "offset");
AssertEqual("imm4", smeSpillOffset.TiedTo);
AssertEqual(3L, ((ImmediateOperand)smeSpillOffset.Operand!).Value);
AssertGeneratedRoundTrip(generatedSmeSpill, 0xE1000023u);
AssertEqual(0xFF000000u, GetByName("ADDXri").Mask);
AssertEqual(0x91000000u, GetByName("ADDXri").Value);
AssertEqual("$dst = $Rd", GetByName("PACIZA").Constraints);

var decodedBarrier = Decode(0xD503309Fu, 0);
AssertEqual(0L, ((EnumImmediateOperand)decodedBarrier.Operands[0]).Value);
AssertEqual(A64EnumKind.Barrier, ((EnumImmediateOperand)decodedBarrier.Operands[0]).EnumKind);
AssertGeneratedRoundTrip(decodedBarrier, 0xD503309Fu);

var decodedNonShareableBarrier = Decode(
    0xD503323Fu,
    0);
// DSB nXS stores the architectural #16/#20/#24/#28 value in a sparse field.
AssertEqual(16L, ((EnumImmediateOperand)decodedNonShareableBarrier.Operands[0]).Value);
AssertEqual(A64EnumKind.Barrier, ((EnumImmediateOperand)decodedNonShareableBarrier.Operands[0]).EnumKind);
AssertGeneratedRoundTrip(decodedNonShareableBarrier, 0xD503323Fu);
AssertEncoded(
    Generated(
        "DSBnXS",
        "dsb",
        [new EnumImmediateOperand(20, A64EnumKind.Barrier)],
        0,
        0),
    0,
    0xD503363Fu);

var decodedCondition = Decode(0x54000000u, 0);
AssertEqual(0L, ((EnumImmediateOperand)decodedCondition.Operands[0]).Value);
AssertEqual(A64EnumKind.ConditionCode, ((EnumImmediateOperand)decodedCondition.Operands[0]).EnumKind);
AssertGeneratedRoundTrip(decodedCondition, 0x54000000u);

var decodedRangePrefetch = Decode(0xF8A14858u, 0);
AssertEqual(0L, ((EnumImmediateOperand)decodedRangePrefetch.Operands[0]).Value);
AssertEqual(A64EnumKind.Prefetch, ((EnumImmediateOperand)decodedRangePrefetch.Operands[0]).EnumKind);
AssertGeneratedRoundTrip(decodedRangePrefetch, 0xF8A14858u);
AssertEncoded(
    Generated(
        "RPRFM",
        "rprfm",
        [
            new EnumImmediateOperand(0, A64EnumKind.Prefetch),
            new RegisterOperand(A64Register.X(1)),
            new RegisterOperand(A64Register.X(2)),
        ],
        0,
        0),
    0,
    0xF8A14858u);

var decodedNumericSvePattern = Decode(0x0420E1C0u, 0);
AssertEqual("CNTB_XPiI", decodedNumericSvePattern.SourceName);
AssertEqual(14L, ((EnumImmediateOperand)decodedNumericSvePattern.Operands[1]).Value);
AssertEqual(
    A64EnumKind.SvePredicatePattern,
    ((EnumImmediateOperand)decodedNumericSvePattern.Operands[1]).EnumKind);
AssertGeneratedRoundTrip(decodedNumericSvePattern, 0x0420E1C0u);

var decodedNumericSvePrefetch = Decode(0x8400E00Eu, 0);
AssertEqual("PRFB_S_PZI", decodedNumericSvePrefetch.SourceName);
AssertEqual(14L, ((EnumImmediateOperand)decodedNumericSvePrefetch.Operands[0]).Value);
AssertEqual(
    A64EnumKind.SvePrefetch,
    ((EnumImmediateOperand)decodedNumericSvePrefetch.Operands[0]).EnumKind);
AssertGeneratedRoundTrip(decodedNumericSvePrefetch, 0x8400E00Eu);

AssertFails(
    Generated(
        "Bcc",
        "b.eq",
        [
            new EnumImmediateOperand(0, A64EnumKind.Barrier),
            new TargetOperand(0),
        ],
        0,
        0),
    "enum domain");

if (!A64InstructionCatalog.TryDecode(0x14000004u, out var generatedBranch))
{
    throw new InvalidOperationException("Generated branch lookup failed.");
}

AssertEqual(0x4u, generatedBranch.Fields.Single(field => field.Name == "addr").Value);

if (!A64Decoder.TryDecode(0xD5002000u, 0, A64FeatureSet.All, out var generatedHinte, out var hinteDiagnostic)
    || generatedHinte.SourceName != "HINTE"
    || ((ImmediateOperand)generatedHinte.Operands[0]).Value != 0
    || ((ImmediateOperand)generatedHinte.Operands[0]).SemanticKind != A64ImmediateSemanticKind.HinteImmediate)
{
    throw new InvalidOperationException($"Generated HINTE decode failed: {hinteDiagnostic}");
}

AssertGeneratedRoundTrip(generatedHinte, 0xD5002000u);
AssertFails(
    Generated("HINTE", "hinte", [new ImmediateOperand(12319)], 0, 0),
    "valid HINTE immediate");

if (!A64Decoder.TryDecode(0x4E010C20u, 0, A64FeatureSet.From(A64Feature.Neon), out var generatedDup, out var dupDiagnostic))
{
    throw new InvalidOperationException($"Generated DUP decode failed: {dupDiagnostic}");
}

AssertEqual(A64Register.Vector(0), ((RegisterOperand)generatedDup.Operands[0]).Register);
AssertEqual(A64Register.W(1), ((RegisterOperand)generatedDup.Operands[1]).Register);
AssertGeneratedRoundTrip(generatedDup, 0x4E010C20u);

if (!A64Decoder.TryDecode(0x05212000u, 0, A64FeatureSet.From(A64Feature.Sve), out var generatedSveDuplicate, out var sveDuplicateDiagnostic))
{
    throw new InvalidOperationException($"Generated SVE duplicate-index decode failed: {sveDuplicateDiagnostic}");
}

var sveDuplicateIndex = (LaneIndexOperand)generatedSveDuplicate.Operands[2];
AssertEqual(0L, sveDuplicateIndex.Value);
AssertEqual(8, sveDuplicateIndex.ElementWidth);
AssertEqual(64, sveDuplicateIndex.LaneCount);
AssertGeneratedRoundTrip(generatedSveDuplicate, 0x05212000u);

if (!A64Decoder.TryDecode(0x2578E020u, 0, A64FeatureSet.From(A64Feature.Sve), out var generatedSveOptionalShift, out var sveOptionalShiftDiagnostic))
{
    throw new InvalidOperationException($"Generated SVE optional-shift decode failed: {sveOptionalShiftDiagnostic}");
}

var sveOptionalShift = (ImmediateOperand)generatedSveOptionalShift.Operands[1];
AssertEqual(256L, sveOptionalShift.Value);
AssertEqual(8, sveOptionalShift.ShiftAmount);
AssertEqual(A64ImmediateSemanticKind.SveOptionalShift, sveOptionalShift.SemanticKind);
AssertGeneratedRoundTrip(generatedSveOptionalShift, 0x2578E020u);

var generatedSveOptionalShiftConstruction = Generated(
    "DUP_ZI_H",
    "dup",
    [
        new RegisterOperand(A64Register.SveVector(0, 16)),
        new ImmediateOperand(256) { ShiftAmount = 8 },
    ],
    0,
    0);
AssertEncoded(generatedSveOptionalShiftConstruction, 0, 0x2578E020u);

if (!A64Decoder.TryDecode(0x1E602008u, 0, A64FeatureSet.From(A64Feature.FloatingPoint), out var generatedCompareZero, out var compareZeroDiagnostic))
{
    throw new InvalidOperationException($"Generated FCMP zero decode failed: {compareZeroDiagnostic}");
}

AssertEqual(A64Register.FloatingPoint(0, 64), ((RegisterOperand)generatedCompareZero.Operands[0]).Register);
AssertGeneratedRoundTrip(generatedCompareZero, 0x1E602008u);

if (!A64Decoder.TryDecode(0x6E062420u, 0, A64FeatureSet.From(A64Feature.Neon), out var generatedInsert, out var insertDiagnostic))
{
    throw new InvalidOperationException($"Generated INS decode failed: {insertDiagnostic}");
}

AssertEqual(1L, ((ImmediateOperand)generatedInsert.Operands[1]).Value);
AssertEqual(2L, ((ImmediateOperand)generatedInsert.Operands[3]).Value);
AssertGeneratedRoundTrip(generatedInsert, 0x6E062420u);

if (!A64InstructionCatalog.TryGetOperand("uimm12s4", out var loadOffsetOperand))
{
    throw new InvalidOperationException("Generated load offset operand lookup failed.");
}

AssertEqual("OPERAND_IMMEDIATE", loadOffsetOperand.OperandType);
AssertEqual("getLdStUImm12OpValue<AArch64::fixup_aarch64_ldst_imm12_scale4>", loadOffsetOperand.EncoderMethod);

if (!AsmStoneApi.TryEncodeFields(
        "ADDWrs",
        new Dictionary<string, uint>
        {
            ["Rd"] = 0,
            ["Rn"] = 1,
            ["Rm"] = 2,
            ["shift"] = 3,
        },
        A64FeatureSet.Base,
        out var rawAddEncoding,
        out var rawAddDiagnostic))
{
    throw new InvalidOperationException($"Raw ADDWrs encoding failed: {rawAddDiagnostic}");
}

AssertEqual(0x0B020C20u, rawAddEncoding);
if (!AsmStoneApi.TryEncodeFields(
        "ADDWrs",
        new Dictionary<string, uint> { ["Rd"] = 0, ["Rn"] = 1, ["Rm"] = 2, ["shift"] = 3 },
        out var defaultRawEncoding,
        out var defaultRawDiagnostic)
    || defaultRawEncoding != 0x0B020C20u)
{
    throw new InvalidOperationException($"Default raw-field encoding failed: {defaultRawDiagnostic}");
}

var rawBytes = new byte[4];
if (!AsmStoneApi.TryEncodeFields(
        "ADDWrs",
        new Dictionary<string, uint> { ["Rd"] = 0, ["Rn"] = 1, ["Rm"] = 2, ["shift"] = 3 },
        rawBytes,
        A64FeatureSet.Base,
        out var rawBytesDiagnostic))
{
    throw new InvalidOperationException($"Raw byte encoding failed: {rawBytesDiagnostic}");
}

if (!AsmStoneApi.TryDecode(rawBytes, 0, A64FeatureSet.Base, out var rawBytesInstruction, out rawBytesDiagnostic))
{
    throw new InvalidOperationException($"Raw byte decoding failed: {rawBytesDiagnostic}");
}

AssertEqual("add", rawBytesInstruction.Mnemonic);
AssertGeneratedRoundTrip(rawBytesInstruction, 0x0B020C20u);
var defaultRawBytes = new byte[4];
if (!AsmStoneApi.TryEncodeFields(
        "ADDWrs",
        new Dictionary<string, uint> { ["Rd"] = 0, ["Rn"] = 1, ["Rm"] = 2, ["shift"] = 3 },
        defaultRawBytes,
        out var defaultRawBytesDiagnostic))
{
    throw new InvalidOperationException($"Default raw byte encoding failed: {defaultRawBytesDiagnostic}");
}

AssertEqual(rawBytes[0], defaultRawBytes[0]);
AssertEqual(rawBytes[1], defaultRawBytes[1]);
AssertEqual(rawBytes[2], defaultRawBytes[2]);
AssertEqual(rawBytes[3], defaultRawBytes[3]);

if (!AsmStoneApi.TryEncodeFields(
        "ST4B",
        new Dictionary<string, uint>
        {
            ["Zt"] = 16,
            ["Pg"] = 4,
            ["Rn"] = 25,
            ["Rm"] = 31,
        },
        A64FeatureSet.FromPredicates(["HasSVE"]),
        out var rawSveEncoding,
        out var rawSveDiagnostic))
{
    throw new InvalidOperationException($"Raw ST4B encoding failed: {rawSveDiagnostic}");
}

AssertEqual(0xE47F7330u, rawSveEncoding);
var sveProfile = A64FeatureSet.FromPredicates(["HasSVE"]);
AssertRawFieldsFail("ST4B", new Dictionary<string, uint> { ["Zt"] = 16 }, "requires encoded field", sveProfile);
AssertRawFieldsFail("ST4B", new Dictionary<string, uint> { ["Zt"] = 16, ["Pg"] = 4, ["Rn"] = 25, ["Rm"] = 31, ["bad"] = 0 }, "no encoded field", sveProfile);
AssertRawFieldsFail(
    "ST4B",
    new Dictionary<string, uint> { ["Zt"] = 16, ["Pg"] = 4, ["Rn"] = 25, ["Rm"] = 31 },
    "requires predicates");

var mopsProfile = A64FeatureSet.From(A64Feature.Mops);
if (!A64Decoder.TryDecode(0x19010440u, 0, mopsProfile, out var generatedMopsCopy, out var mopsCopyDiagnostic))
{
    throw new InvalidOperationException($"Generated MOPS copy decode failed: {mopsCopyDiagnostic}");
}

AssertEqual("CPYFP", generatedMopsCopy.SourceName);
AssertEqual(3, generatedMopsCopy.Operands.Count);
AssertEqual(true, generatedMopsCopy.Flags.HasFlag(A64InstructionFlags.WritesBack));
AssertGeneratedRoundTrip(generatedMopsCopy, 0x19010440u);

if (!A64Decoder.TryDecode(0x19C20420u, 0, mopsProfile, out var generatedMopsSet, out var mopsSetDiagnostic))
{
    throw new InvalidOperationException($"Generated MOPS set decode failed: {mopsSetDiagnostic}");
}

AssertEqual("SETP", generatedMopsSet.SourceName);
AssertGeneratedRoundTrip(generatedMopsSet, 0x19C20420u);

if (!A64Decoder.TryDecode(0x4EA28420u, 0, A64FeatureSet.From(A64Feature.Neon), out var generatedNeon, out var neonDiagnostic))
{
    throw new InvalidOperationException($"Generated NEON decode failed: {neonDiagnostic}");
}

if (!generatedNeon.IsGenerated)
{
    throw new InvalidOperationException("NEON decode must produce generated IR.");
}

AssertEqual(
    A64Register.Vector(0),
    ((RegisterOperand)generatedNeon.Operands.First()).Register);

if (!A64Decoder.TryDecode(0xB4000080u, 0, A64FeatureSet.Base, out var generatedCbz, out var cbzDiagnostic))
{
    throw new InvalidOperationException($"Generated CBZ decode failed: {cbzDiagnostic}");
}

AssertEqual(A64InstructionId.Generated, generatedCbz.Id);
AssertEqual(A64Register.X(0), ((RegisterOperand)generatedCbz.Operands[0]).Register);
AssertEqual(0x10UL, ((TargetOperand)generatedCbz.Operands[1]).Address);

if (!A64Decoder.TryDecode(0xB9401020u, 4, A64FeatureSet.Base, out var generatedLoad, out var loadDiagnostic))
{
    throw new InvalidOperationException($"Generated LDR decode failed: {loadDiagnostic}");
}

AssertEqual(A64Register.W(0), ((RegisterOperand)generatedLoad.Operands[0]).Register);
var generatedLoadMemory = (MemoryOperand)generatedLoad.Operands[1];
AssertEqual(A64Register.X(1), generatedLoadMemory.Base);
AssertEqual(16L, generatedLoadMemory.Offset);
var loadSemantics = generatedLoad.GetOperandSemantics();
AssertEqual(3, loadSemantics.Count);
AssertEqual(A64OperandDirection.Output, loadSemantics[0].Direction);
AssertEqual("Rt", loadSemantics[0].Name);
AssertEqual(A64OperandDirection.Input, loadSemantics[1].Direction);
AssertEqual("Rn", loadSemantics[1].Name);
AssertEqual(true, loadSemantics[2].IsImplicit);
AssertEqual("offset", loadSemantics[2].Name);
AssertEqual(A64OperandKind.Immediate, loadSemantics[2].Kind);
AssertEqual(4, loadSemantics[2].Scale);
AssertEqual(12, loadSemantics[2].FieldWidth);
AssertGeneratedRoundTrip(generatedCbz, 0xB4000080u);
AssertGeneratedRoundTrip(generatedLoad, 0xB9401020u);
AssertGeneratedRoundTrip(generatedNeon, 0x4EA28420u);
AssertFails(
    generatedLoad with
    {
        Operands =
        [
            new RegisterOperand(A64Register.W(0)),
            new MemoryOperand(A64Register.Zr(), 16),
        ],
    },
    "register role");

AssertGeneratedMemoryRoundTrip(0xB9401020u, 4, A64MemoryAddressingMode.Offset);

if (!A64Decoder.TryDecode(
        0xDAC123E0u,
        0,
        A64FeatureSet.From(A64Feature.PointerAuthentication),
        out var generatedTiedRegister,
        out var tiedRegisterDiagnostic))
{
    throw new InvalidOperationException($"Generated tied-register decode failed: {tiedRegisterDiagnostic}");
}

var tiedRegisterSemantics = generatedTiedRegister.GetOperandSemantics();
var tiedDestination = tiedRegisterSemantics.First(operand => operand.Name == "dst");
AssertEqual("Rd", tiedDestination.TiedTo);
AssertEqual(true, tiedDestination.IsImplicit);
AssertEqual(A64OperandDirection.Output, tiedDestination.Direction);
AssertEqual(A64OperandKind.Register, tiedDestination.Kind);
AssertEqual(generatedTiedRegister.Operands[0], tiedDestination.Operand);
AssertGeneratedRoundTrip(generatedTiedRegister, 0xDAC123E0u);

if (!A64Decoder.TryDecode(
        0x0DC04000u,
        0,
        A64FeatureSet.From(A64Feature.Neon),
        out var generatedTiedLoad,
        out var tiedLoadDiagnostic))
{
    throw new InvalidOperationException($"Generated tied-load decode failed: {tiedLoadDiagnostic}");
}

var tiedLoadSemantics = generatedTiedLoad.GetOperandSemantics();
var tiedWriteback = tiedLoadSemantics.First(operand => operand.Name == "wback");
var tiedLoadDestination = tiedLoadSemantics.First(operand => operand.Name == "dst");
AssertEqual("Rn", tiedWriteback.TiedTo);
AssertEqual("Vt", tiedLoadDestination.TiedTo);
AssertEqual(true, tiedWriteback.IsImplicit);
AssertEqual(true, tiedLoadDestination.IsImplicit);
AssertEqual(A64OperandKind.VectorRegisterList, tiedLoadDestination.Kind);
AssertEqual(A64OperandKind.Memory, tiedWriteback.Operand is MemoryOperand
    ? A64OperandKind.Memory
    : A64OperandKind.EncodedField);
AssertGeneratedRoundTrip(generatedTiedLoad, 0x0DC04000u);

if (!A64Decoder.TryDecode(0xB8408062u, 0, A64FeatureSet.Base, out var generatedUnscaled, out var unscaledDiagnostic))
{
    throw new InvalidOperationException($"Generated unscaled load decode failed: {unscaledDiagnostic}");
}

AssertEqual(A64MemoryAddressingMode.Offset, ((MemoryOperand)generatedUnscaled.Operands[1]).Mode);
AssertGeneratedRoundTrip(generatedUnscaled, 0xB8408062u);

if (!A64Decoder.TryDecode(0xA9007BFDu, 0x1000, A64FeatureSet.Base, out var generatedPair, out var pairDiagnostic))
{
    throw new InvalidOperationException($"Generated pair store decode failed: {pairDiagnostic}");
}

AssertEqual(A64MemoryAddressingMode.Offset, ((MemoryOperand)generatedPair.Operands[2]).Mode);
AssertGeneratedRoundTrip(generatedPair, 0xA9007BFDu);

if (!A64Decoder.TryDecode(0xB8408C20u, 0, A64FeatureSet.Base, out var generatedPre, out var preDiagnostic))
{
    throw new InvalidOperationException($"Generated pre-index load decode failed: {preDiagnostic}");
}

AssertEqual(A64MemoryAddressingMode.PreIndexed, ((MemoryOperand)generatedPre.Operands[1]).Mode);
AssertGeneratedRoundTrip(generatedPre, 0xB8408C20u);

if (!A64Decoder.TryDecode(0xB8408420u, 0, A64FeatureSet.Base, out var generatedPost, out var postDiagnostic))
{
    throw new InvalidOperationException($"Generated post-index load decode failed: {postDiagnostic}");
}

AssertEqual(A64MemoryAddressingMode.PostIndexed, ((MemoryOperand)generatedPost.Operands[1]).Mode);
AssertGeneratedRoundTrip(generatedPost, 0xB8408420u);

if (!A64Decoder.TryDecode(0x99800800u, 0, A64FeatureSet.From(A64Feature.Rcpc), out var generatedFixedPre, out var fixedPreDiagnostic))
{
    throw new InvalidOperationException($"Generated fixed-offset pre-index decode failed: {fixedPreDiagnostic}");
}

var fixedPreMemory = (MemoryOperand)generatedFixedPre.Operands[1];
AssertEqual(-4L, fixedPreMemory.Offset);
AssertEqual(A64MemoryAddressingMode.PreIndexed, fixedPreMemory.Mode);
AssertGeneratedRoundTrip(generatedFixedPre, 0x99800800u);

if (!A64Decoder.TryDecode(0x885F7C20u, 0, A64FeatureSet.Base, out var generatedExclusive, out var exclusiveDiagnostic))
{
    throw new InvalidOperationException($"Generated exclusive load decode failed: {exclusiveDiagnostic}");
}

AssertEqual(A64MemoryAddressingMode.Offset, ((MemoryOperand)generatedExclusive.Operands[1]).Mode);
AssertEqual(true, generatedExclusive.Flags.HasFlag(A64InstructionFlags.IsAtomic));
AssertGeneratedRoundTrip(generatedExclusive, 0x885F7C20u);

if (A64Decoder.TryDecode(0x88A07C22u, 0, A64FeatureSet.Base, out _, out _))
{
    throw new InvalidOperationException("LSE CAS must be gated out of Base.");
}

if (!A64Decoder.TryDecode(
        0x88A07C22u,
        0,
        A64FeatureSet.From(A64Feature.Lse),
        out var generatedCas,
        out var casDiagnostic))
{
    throw new InvalidOperationException($"Generated CAS decode failed: {casDiagnostic}");
}

AssertEqual(A64InstructionId.Generated, generatedCas.Id);
AssertEqual(A64MemoryAddressingMode.Offset, ((MemoryOperand)generatedCas.Operands[2]).Mode);
AssertEqual(true, generatedCas.Flags.HasFlag(A64InstructionFlags.IsAtomic));
AssertGeneratedRoundTrip(generatedCas, 0x88A07C22u);

if (!A64Decoder.TryDecode(
        0x3CE26820u,
        0,
        A64FeatureSet.From(A64Feature.FloatingPoint),
        out var generatedRegisterOffset,
        out var registerOffsetDiagnostic))
{
    throw new InvalidOperationException($"Generated register-offset load decode failed: {registerOffsetDiagnostic}");
}

var registerOffsetMemory = (MemoryOperand)generatedRegisterOffset.Operands[1];
AssertEqual(A64MemoryAddressingMode.RegisterOffset, registerOffsetMemory.Mode);
AssertEqual(A64Register.X(1), registerOffsetMemory.Base);
AssertEqual(A64Register.X(2), registerOffsetMemory.Index);
AssertEqual(0u, registerOffsetMemory.IndexModifier);
AssertGeneratedRoundTrip(generatedRegisterOffset, 0x3CE26820u);

if (!A64Decoder.TryDecode(0x3CE2C820u, 0, A64FeatureSet.From(A64Feature.FloatingPoint), out var generatedExtendedMemory, out var extendedMemoryDiagnostic))
{
    throw new InvalidOperationException($"Generated extended memory decode failed: {extendedMemoryDiagnostic}");
}

var extendedMemory = (MemoryOperand)generatedExtendedMemory.Operands[1];
AssertEqual(A64Register.W(2), extendedMemory.Index);
AssertEqual(2u, extendedMemory.IndexModifier);
AssertEqual(A64RegisterModifierKind.Sxtw, extendedMemory.IndexModifierSemantics!.Value.Kind);
AssertEqual(16, extendedMemory.AccessSize);
AssertGeneratedRoundTrip(generatedExtendedMemory, 0x3CE2C820u);

var acquireDiagnostic = A64Diagnostic.None;
var releaseDiagnostic = A64Diagnostic.None;
if (!A64Decoder.TryDecode(0x88DFFC00u, 0, A64FeatureSet.Base, out var generatedAcquire, out acquireDiagnostic)
    || !A64Decoder.TryDecode(0x889FFC00u, 0, A64FeatureSet.Base, out var generatedRelease, out releaseDiagnostic))
{
    throw new InvalidOperationException($"Generated ordering decode failed: {acquireDiagnostic}; {releaseDiagnostic}");
}

AssertEqual(A64MemoryOrdering.Acquire, ((MemoryOperand)generatedAcquire.Operands[1]).Ordering);
AssertEqual(true, generatedAcquire.Flags.HasFlag(A64InstructionFlags.IsAcquire));
AssertEqual(A64MemoryOrdering.Release, ((MemoryOperand)generatedRelease.Operands[1]).Ordering);
AssertEqual(true, generatedRelease.Flags.HasFlag(A64InstructionFlags.IsRelease));
AssertGeneratedRoundTrip(generatedAcquire, 0x88DFFC00u);
AssertGeneratedRoundTrip(generatedRelease, 0x889FFC00u);

if (!A64Decoder.TryDecode(0xF8201420u, 0, A64FeatureSet.From(A64Feature.PointerAuthentication), out var generatedAuthLoad, out var authLoadDiagnostic))
{
    throw new InvalidOperationException($"Generated authenticated load decode failed: {authLoadDiagnostic}");
}

var authMemory = (MemoryOperand)generatedAuthLoad.Operands[1];
AssertEqual(8L, authMemory.Offset);
AssertEqual(A64MemoryAddressingMode.Offset, authMemory.Mode);
AssertGeneratedRoundTrip(generatedAuthLoad, 0xF8201420u);

if (!A64Decoder.TryDecode(0xF8201C20u, 0, A64FeatureSet.From(A64Feature.PointerAuthentication), out var generatedAuthWriteback, out var authWritebackDiagnostic))
{
    throw new InvalidOperationException($"Generated authenticated writeback load decode failed: {authWritebackDiagnostic}");
}

AssertEqual(true, generatedAuthWriteback.Flags.HasFlag(A64InstructionFlags.WritesBack));
AssertEqual(A64MemoryAddressingMode.PreIndexed, ((MemoryOperand)generatedAuthWriteback.Operands[1]).Mode);
AssertGeneratedRoundTrip(generatedAuthWriteback, 0xF8201C20u);

if (!A64Decoder.TryDecode(0x36180080u, 0, A64FeatureSet.Base, out var generatedTbz, out var tbzDiagnostic))
{
    throw new InvalidOperationException($"Generated TBZ decode failed: {tbzDiagnostic}");
}

AssertEqual(A64Register.W(0), ((RegisterOperand)generatedTbz.Operands[0]).Register);
AssertEqual(3L, ((ImmediateOperand)generatedTbz.Operands[1]).Value);
AssertEqual(0x10UL, ((TargetOperand)generatedTbz.Operands[2]).Address);
AssertEqual(true, generatedTbz.Flags.HasFlag(A64InstructionFlags.IsTerminator));
AssertGeneratedRoundTrip(generatedTbz, 0x36180080u);

if (!A64Decoder.TryDecode(0xB7080001u, 4, A64FeatureSet.Base, out var generatedTbnz, out var tbnzDiagnostic))
{
    throw new InvalidOperationException($"Generated TBNZ decode failed: {tbnzDiagnostic}");
}

AssertEqual(A64Register.X(1), ((RegisterOperand)generatedTbnz.Operands[0]).Register);
AssertEqual(33L, ((ImmediateOperand)generatedTbnz.Operands[1]).Value);
AssertEqual(4UL, ((TargetOperand)generatedTbnz.Operands[2]).Address);
AssertGeneratedRoundTrip(generatedTbnz, 0xB7080001u);

if (!A64Decoder.TryDecode(0x8B020C20u, 0, A64FeatureSet.Base, out var generatedShiftedAdd, out var shiftedAddDiagnostic))
{
    throw new InvalidOperationException($"Generated shifted-register add decode failed: {shiftedAddDiagnostic}");
}

var shiftedAddOperand = (ModifiedRegisterOperand)generatedShiftedAdd.Operands[2];
AssertEqual(A64Register.X(2), shiftedAddOperand.Register);
AssertEqual(3u, shiftedAddOperand.Modifier);
if (!shiftedAddOperand.TryGetModifier(out var shiftedModifier)
    || shiftedModifier.Kind != A64RegisterModifierKind.Lsl
    || shiftedModifier.Amount != 3)
{
    throw new InvalidOperationException("Shifted-register modifier semantics were not materialized.");
}
AssertGeneratedRoundTrip(generatedShiftedAdd, 0x8B020C20u);
AssertFails(
    Generated(
        "ADDWrs",
        "add",
        [
            new RegisterOperand(A64Register.W(0)),
            new RegisterOperand(A64Register.W(1)),
            new ModifiedRegisterOperand(A64Register.W(2), 0x20u, "arith_shifted_reg32"),
        ],
        0,
        0),
    "valid register modifier");

if (!A64Decoder.TryDecode(0x8B22C820u, 0, A64FeatureSet.Base, out var generatedExtendedAdd, out var extendedAddDiagnostic))
{
    throw new InvalidOperationException($"Generated extended-register add decode failed: {extendedAddDiagnostic}");
}

var extendedAddOperand = (ModifiedRegisterOperand)generatedExtendedAdd.Operands[2];
AssertEqual(A64Register.W(2), extendedAddOperand.Register);
AssertEqual(0x32u, extendedAddOperand.Modifier);
if (!extendedAddOperand.TryGetModifier(out var extendedModifier)
    || extendedModifier.Kind != A64RegisterModifierKind.Sxtw
    || extendedModifier.Amount != 2)
{
    throw new InvalidOperationException("Extended-register modifier semantics were not materialized.");
}
AssertGeneratedRoundTrip(generatedExtendedAdd, 0x8B22C820u);
if (!ModifiedRegisterOperand.TryCreate(
        A64Register.X(2),
        "arith_shifted_reg64",
        A64RegisterModifierKind.Lsr,
        4,
        out var constructedShiftedOperand))
{
    throw new InvalidOperationException("Semantic shifted-register construction failed.");
}

var constructedShifted = generatedShiftedAdd with
{
    Operands = [generatedShiftedAdd.Operands[0], generatedShiftedAdd.Operands[1], constructedShiftedOperand],
};
AssertGeneratedRoundTrip(constructedShifted, 0x8B421020u);

if (!ModifiedRegisterOperand.TryCreate(
        A64Register.W(2),
        "arith_extended_reg32to64_i64",
        A64RegisterModifierKind.Uxtw,
        0,
        out var constructedExtendedOperand))
{
    throw new InvalidOperationException("Semantic extended-register construction failed.");
}

var constructedExtended = generatedExtendedAdd with
{
    Operands = [generatedExtendedAdd.Operands[0], generatedExtendedAdd.Operands[1], constructedExtendedOperand],
};
AssertGeneratedRoundTrip(constructedExtended, 0x8B224020u);

if (!A64Decoder.TryDecode(0x8B226C20u, 0, A64FeatureSet.Base, out var generatedExtendedLsl, out var extendedLslDiagnostic))
{
    throw new InvalidOperationException($"Generated UXTX modifier decode failed: {extendedLslDiagnostic}");
}

var extendedLslModifier = (RegisterModifierOperand)generatedExtendedLsl.Operands[3];
AssertEqual(A64RegisterModifierKind.Uxtx, extendedLslModifier.Modifier.Kind);
AssertEqual(3, extendedLslModifier.Modifier.Amount);
AssertEqual(3u, extendedLslModifier.Modifier.RawEncoding);
AssertGeneratedRoundTrip(generatedExtendedLsl, 0x8B226C20u);

var constructedExtendedLslModifier = new RegisterModifierOperand(
    new A64RegisterModifier(A64RegisterModifierKind.Sxtx, 4, 0),
    "arith_extendlsl64");
var constructedExtendedLsl = generatedExtendedLsl with
{
    Operands =
    [
        generatedExtendedLsl.Operands[0],
        generatedExtendedLsl.Operands[1],
        generatedExtendedLsl.Operands[2],
        constructedExtendedLslModifier,
    ],
};
AssertGeneratedRoundTrip(constructedExtendedLsl, 0x8B22F020u);

if (!A64Decoder.TryDecode(0x8B22F020u, 0, A64FeatureSet.Base, out var generatedSignedExtendedLsl, out var signedExtendedLslDiagnostic)
    || ((RegisterModifierOperand)generatedSignedExtendedLsl.Operands[3]).Modifier.Kind != A64RegisterModifierKind.Sxtx)
{
    throw new InvalidOperationException($"Generated SXTX modifier decode failed: {signedExtendedLslDiagnostic}");
}

if (!ModifiedRegisterOperand.TryCreate(
        A64Register.W(2),
        "arith_shifted_reg64",
        A64RegisterModifierKind.Lsl,
        0,
        out var wrongWidthModifier))
{
    throw new InvalidOperationException("Modifier construction setup failed.");
}

AssertFails(
    generatedShiftedAdd with
    {
        Operands = [generatedShiftedAdd.Operands[0], generatedShiftedAdd.Operands[1], wrongWidthModifier],
    },
    "class and width");

if (!A64Decoder.TryDecode(
        0x4C407820u,
        0,
        A64FeatureSet.From(A64Feature.Neon),
        out var generatedVectorLoad,
        out var vectorLoadDiagnostic))
{
    throw new InvalidOperationException($"Generated vector-list load decode failed: {vectorLoadDiagnostic}");
}

var vectorList = (VectorRegisterListOperand)generatedVectorLoad.Operands[0];
AssertEqual(1, vectorList.Registers.Count);
AssertEqual(A64Register.Vector(0), vectorList.Registers[0]);
AssertEqual(32, vectorList.ElementWidth);
AssertEqual(A64Register.X(1), ((MemoryOperand)generatedVectorLoad.Operands[^1]).Base);
AssertGeneratedRoundTrip(generatedVectorLoad, 0x4C407820u);

if (!A64Decoder.TryDecode(
        0x0C40A03Fu,
        0,
        A64FeatureSet.From(A64Feature.Neon),
        out var generatedWrappedVectorLoad,
        out var wrappedVectorDiagnostic))
{
    throw new InvalidOperationException($"Generated wrapped vector-list load decode failed: {wrappedVectorDiagnostic}");
}

var wrappedList = (VectorRegisterListOperand)generatedWrappedVectorLoad.Operands[0];
AssertEqual(2, wrappedList.Registers.Count);
AssertEqual(A64Register.Vector(31), wrappedList.Registers[0]);
AssertEqual(A64Register.Vector(0), wrappedList.Registers[1]);
AssertGeneratedRoundTrip(generatedWrappedVectorLoad, 0x0C40A03Fu);

if (!A64Decoder.TryDecode(0xD53BD040u, 0, out var generatedMrs, out var mrsDiagnostic))
{
    throw new InvalidOperationException($"Generated MRS decode failed: {mrsDiagnostic}");
}

AssertEqual(A64Register.X(0), ((RegisterOperand)generatedMrs.Operands[0]).Register);
AssertEqual(0xDE82u, ((SystemRegisterOperand)generatedMrs.Operands[1]).Encoding);
AssertGeneratedRoundTrip(generatedMrs, 0xD53BD040u);

if (!A64Decoder.TryDecode(0xD51BD040u, 0, out var generatedMsr, out var msrDiagnostic))
{
    throw new InvalidOperationException($"Generated MSR decode failed: {msrDiagnostic}");
}

AssertEqual(0xDE82u, ((SystemRegisterOperand)generatedMsr.Operands[0]).Encoding);
AssertEqual(A64Register.X(0), ((RegisterOperand)generatedMsr.Operands[1]).Register);
if (!generatedMrs.Flags.HasFlag(A64InstructionFlags.IsSystem)
    || !generatedMsr.Flags.HasFlag(A64InstructionFlags.IsSystem))
{
    throw new InvalidOperationException("Generated system-register effect flags are missing.");
}
AssertGeneratedRoundTrip(generatedMsr, 0xD51BD040u);

if (!A64Decoder.TryDecode(0x92401C20u, 0, out var generatedAnd, out var andDiagnostic))
{
    throw new InvalidOperationException($"Generated logical-immediate decode failed: {andDiagnostic}");
}

AssertEqual(255L, ((ImmediateOperand)generatedAnd.Operands[2]).Value);
AssertGeneratedRoundTrip(generatedAnd, 0x92401C20u);
AssertGeneratedRoundTrip(
    generatedAnd with
    {
        Operands =
        [
            generatedAnd.Operands[0],
            generatedAnd.Operands[1],
            new ImmediateOperand(0xFFFF),
        ],
    },
    0x92403C20u);

if (!A64Decoder.TryDecode(0x12001CA4u, 0, out var generatedAnd32, out var and32Diagnostic))
{
    throw new InvalidOperationException($"Generated 32-bit logical-immediate decode failed: {and32Diagnostic}");
}

AssertEqual(255L, ((ImmediateOperand)generatedAnd32.Operands[2]).Value);
AssertGeneratedRoundTrip(generatedAnd32, 0x12001CA4u);

if (!A64Decoder.TryDecode(0x0F0B5420u, 0, A64FeatureSet.From(A64Feature.Neon), out var generatedVectorShift, out var vectorShiftDiagnostic))
{
    throw new InvalidOperationException($"Generated vector-shift decode failed: {vectorShiftDiagnostic}");
}

AssertEqual(3L, ((ImmediateOperand)generatedVectorShift.Operands[2]).Value);
AssertGeneratedRoundTrip(generatedVectorShift, 0x0F0B5420u);

if (!A64Decoder.TryDecode(0x4F3F04A4u, 0, A64FeatureSet.From(A64Feature.Neon), out var generatedVectorRightShift, out var vectorRightShiftDiagnostic))
{
    throw new InvalidOperationException($"Generated vector-right-shift decode failed: {vectorRightShiftDiagnostic}");
}

AssertEqual(1L, ((ImmediateOperand)generatedVectorRightShift.Operands[2]).Value);
AssertGeneratedRoundTrip(generatedVectorRightShift, 0x4F3F04A4u);

if (!A64Decoder.TryDecode(0x0F0D84E6u, 0, A64FeatureSet.From(A64Feature.Neon), out var generatedNarrowShift, out var narrowShiftDiagnostic))
{
    throw new InvalidOperationException($"Generated narrow vector-shift decode failed: {narrowShiftDiagnostic}");
}

AssertEqual(3L, ((ImmediateOperand)generatedNarrowShift.Operands[2]).Value);
AssertGeneratedRoundTrip(generatedNarrowShift, 0x0F0D84E6u);

if (!A64Decoder.TryDecode(0xA520E040u, 0, A64FeatureSet.From(A64Feature.Sve), out var generatedSveLoad, out var sveLoadDiagnostic))
{
    throw new InvalidOperationException($"Generated SVE group load decode failed: {sveLoadDiagnostic}");
}

var sveGroup = (RegisterGroupOperand)generatedSveLoad.Operands[0];
AssertEqual(2, sveGroup.Registers.Count);
AssertEqual(A64Register.SveVector(0, 32), sveGroup.Registers[0]);
AssertEqual(A64Register.SveVector(1, 32), sveGroup.Registers[1]);
AssertEqual(32, sveGroup.ElementWidth);
AssertEqual(A64Register.X(2), ((MemoryOperand)generatedSveLoad.Operands[^1]).Base);
AssertGeneratedRoundTrip(generatedSveLoad, 0xA520E040u);

if (!A64Decoder.TryDecode(0x042FE3E2u, 0, A64FeatureSet.From(A64Feature.Sve), out var generatedCnt, out var cntDiagnostic))
{
    throw new InvalidOperationException($"Generated SVE CNT decode failed: {cntDiagnostic}");
}

AssertEqual(16L, ((ImmediateOperand)generatedCnt.Operands[^1]).Value);
AssertGeneratedRoundTrip(generatedCnt, 0x042FE3E2u);

if (!A64Decoder.TryDecode(0x2598E3E0u, 0, A64FeatureSet.From(A64Feature.Sve), out var generatedPtrue, out var ptrueDiagnostic))
{
    throw new InvalidOperationException($"Generated SVE predicate decode failed: {ptrueDiagnostic}");
}

AssertEqual(A64RegisterClass.Predicate, ((RegisterOperand)generatedPtrue.Operands[0]).Register.Class);
AssertEqual(31L, ((ImmediateOperand)generatedPtrue.Operands[1]).Value);
AssertEqual(32, ((RegisterOperand)generatedPtrue.Operands[0]).ElementWidth);
AssertEqual(
    A64EnumKind.SvePredicatePattern,
    ((ImmediateOperand)generatedPtrue.Operands[1]).EnumKind);
if (!A64Decoder.TryDecode(0x8400C000u, 0, A64FeatureSet.From(A64Feature.Sve), out var generatedSvePrefetch, out var svePrefetchDiagnostic))
{
    throw new InvalidOperationException($"Generated SVE prefetch decode failed: {svePrefetchDiagnostic}");
}

AssertEqual(A64EnumKind.SvePrefetch, ((ImmediateOperand)generatedSvePrefetch.Operands[0]).EnumKind);
AssertGeneratedRoundTrip(generatedSvePrefetch, 0x8400C000u);

if (!A64Decoder.TryDecode(0x25208200u, 0, A64FeatureSet.From(A64Feature.Sve2p1), out var generatedVectorLength, out var vectorLengthDiagnostic))
{
    throw new InvalidOperationException($"Generated SVE vector-length decode failed: {vectorLengthDiagnostic}");
}

AssertEqual(A64EnumKind.SveVectorLength, ((ImmediateOperand)generatedVectorLength.Operands[2]).EnumKind);
AssertGeneratedRoundTrip(generatedVectorLength, 0x25208200u);

if (!A64Decoder.TryDecode(0xD503427Fu, 0, A64FeatureSet.All, out var generatedSvcr, out var svcrDiagnostic))
{
    throw new InvalidOperationException($"Generated SVCR decode failed: {svcrDiagnostic}");
}

AssertEqual(A64EnumKind.Svcr, ((ImmediateOperand)generatedSvcr.Operands[0]).EnumKind);
AssertGeneratedRoundTrip(generatedSvcr, 0xD503427Fu);

if (!A64Decoder.TryDecode(0xD4E00000u, 0, A64FeatureSet.All, out var generatedTenter, out var tenterDiagnostic))
{
    throw new InvalidOperationException($"Generated TENTER decode failed: {tenterDiagnostic}");
}

AssertEqual(1L, ((ImmediateOperand)generatedTenter.Operands[1]).Value);
AssertEqual(A64EnumKind.TIndexHint, ((ImmediateOperand)generatedTenter.Operands[1]).EnumKind);
AssertGeneratedRoundTrip(generatedTenter, 0xD4E00000u);
if (!A64Decoder.TryDecode(0xC0480001u, 0, A64FeatureSet.All, out var generatedZeroT, out var zeroTDiagnostic))
{
    throw new InvalidOperationException($"Generated ZERO_T decode failed: {zeroTDiagnostic}");
}

var zeroTSemantics = generatedZeroT.GetOperandSemantics();
AssertEqual(1, zeroTSemantics.Count);
AssertEqual("ZT", zeroTSemantics[0].Name);
AssertEqual(true, zeroTSemantics[0].IsImplicit);
AssertEqual(A64MatrixRegisterKind.Zt, ((MatrixRegisterOperand)zeroTSemantics[0].Operand!).Kind);
AssertGeneratedRoundTrip(generatedZeroT, 0xC0480001u);

if (!A64Decoder.TryDecode(0xD5400000u, 0, A64FeatureSet.All, out var generatedMsrr, out var msrrDiagnostic))
{
    throw new InvalidOperationException($"Generated MSRR decode failed: {msrrDiagnostic}");
}

var msrrPair = (RegisterPairOperand)generatedMsrr.Operands[1];
AssertEqual(A64Register.X(0), msrrPair.First);
AssertEqual(A64Register.X(1), msrrPair.Second);
AssertGeneratedRoundTrip(generatedMsrr, 0xD5400000u);

if (!A64Decoder.TryDecode(0x80600008u, 0, A64FeatureSet.All, out var generatedTile, out var tileDiagnostic))
{
    throw new InvalidOperationException($"Generated SME tile decode failed: {tileDiagnostic}");
}

var tileAccumulator = (MatrixRegisterOperand)generatedTile.Operands[0];
AssertEqual(A64MatrixRegisterKind.Tile, tileAccumulator.Kind);
var tileK = (MatrixRegisterOperand)generatedTile.Operands[3];
AssertEqual(A64MatrixRegisterKind.Zk, tileK.Kind);
AssertEqual(20, tileK.Index);
var tileSemantics = generatedTile.GetOperandSemantics();
var tiedTile = tileSemantics.First(operand => operand.Name == "_ZAda");
var tileOutputSemantic = tileSemantics.First(operand => operand.Name == "ZAda");
AssertEqual("ZAda", tiedTile.TiedTo);
AssertEqual(true, tiedTile.IsImplicit);
AssertEqual(A64OperandDirection.Input, tiedTile.Direction);
AssertEqual(A64OperandKind.MatrixRegister, tiedTile.Kind);
AssertEqual(A64MatrixRegisterKind.Tile, tiedTile.MatrixRegisterKind);
AssertEqual(16, tiedTile.ElementWidth);
AssertEqual(tileOutputSemantic.Operand, tiedTile.Operand);
AssertEqual(A64OperandDirection.Output, tileOutputSemantic.Direction);
AssertEqual(A64OperandKind.MatrixRegister, tileOutputSemantic.Kind);
AssertGeneratedRoundTrip(generatedTile, 0x80600008u);
AssertFails(
    generatedTile with
    {
        Operands =
        [
            generatedTile.Operands[0],
            generatedTile.Operands[1],
            generatedTile.Operands[2],
            tileK with { EncodedValue = 1 },
        ],
    },
    "matching semantic and raw matrix register indices");
AssertGeneratedRoundTrip(generatedPtrue, 0x2598E3E0u);

if (!A64Decoder.TryDecode(0x1E2E1000u, 0, A64FeatureSet.From(A64Feature.FloatingPoint), out var generatedFpSingle, out var fpSingleDiagnostic))
{
    throw new InvalidOperationException($"Generated FP32 immediate decode failed: {fpSingleDiagnostic}");
}

AssertEqual(1.0, ((FloatingImmediateOperand)generatedFpSingle.Operands[1]).Value);
AssertGeneratedRoundTrip(generatedFpSingle, 0x1E2E1000u);

if (!A64Decoder.TryDecode(0x1E028000u, 0, A64FeatureSet.From(A64Feature.FloatingPoint), out var generatedFixedPoint, out var fixedPointDiagnostic))
{
    throw new InvalidOperationException($"Generated fixed-point decode failed: {fixedPointDiagnostic}");
}

AssertEqual(32L, ((FixedPointOperand)generatedFixedPoint.Operands[2]).Value);
AssertEqual(32, ((FixedPointOperand)generatedFixedPoint.Operands[2]).FractionalBits);
AssertGeneratedRoundTrip(generatedFixedPoint, 0x1E028000u);

if (!A64Decoder.TryDecode(0x44002400u, 0, A64FeatureSet.From(A64Feature.Sve2), out var generatedComplex, out var complexDiagnostic))
{
    throw new InvalidOperationException($"Generated complex-rotation decode failed: {complexDiagnostic}");
}

AssertEqual(90L, ((ComplexRotationOperand)generatedComplex.Operands[3]).Value);
AssertGeneratedRoundTrip(generatedComplex, 0x44002400u);

if (!A64Decoder.TryDecode(0x65808000u, 0, A64FeatureSet.From(A64Feature.Sve), out var generatedPredicated, out var predicatedDiagnostic))
{
    throw new InvalidOperationException($"Generated predicated SVE decode failed: {predicatedDiagnostic}");
}

var mergePredicate = (RegisterOperand)generatedPredicated.Operands[1];
AssertEqual(A64PredicateMode.Merge, mergePredicate.PredicateMode);
AssertEqual(32, mergePredicate.ElementWidth);
AssertGeneratedRoundTrip(generatedPredicated, 0x65808000u);

if (!A64Decoder.TryDecode(0x65588000u, 0, A64FeatureSet.From(A64Feature.Sve), out var generatedSveFloatImmediate, out var sveFloatImmediateDiagnostic))
{
    throw new InvalidOperationException($"Generated SVE exact FP immediate decode failed: {sveFloatImmediateDiagnostic}");
}

var sveFloatImmediate = (FloatingImmediateOperand)generatedSveFloatImmediate.Operands[2];
AssertEqual(0.5, sveFloatImmediate.Value);
AssertEqual(A64ImmediateSemanticKind.FloatingImmediate, sveFloatImmediate.SemanticKind);
AssertGeneratedRoundTrip(generatedSveFloatImmediate, 0x65588000u);

if (!A64Decoder.TryDecode(0x85004000u, 0, A64FeatureSet.From(A64Feature.Sve), out var generatedZeroing, out var zeroingDiagnostic))
{
    throw new InvalidOperationException($"Generated zeroing SVE decode failed: {zeroingDiagnostic}");
}

var zeroPredicate = generatedZeroing.Operands
    .OfType<RegisterOperand>()
    .First(operand => operand.Register.Class == A64RegisterClass.Predicate);
AssertEqual(A64PredicateMode.Zero, zeroPredicate.PredicateMode);
AssertGeneratedRoundTrip(generatedZeroing, 0x85004000u);

if (!A64Decoder.TryDecode(0x25205010u, 0, A64FeatureSet.From(A64Feature.Sve2p1), out var generatedPredicatePair, out var predicatePairDiagnostic))
{
    throw new InvalidOperationException($"Generated predicate-pair decode failed: {predicatePairDiagnostic}");
}

var predicatePair = (RegisterGroupOperand)generatedPredicatePair.Operands[0];
AssertEqual(2, predicatePair.Registers.Count);
AssertEqual(A64RegisterClass.Predicate, predicatePair.Registers[0].Class);
AssertEqual(0, predicatePair.Registers[0].Index);
AssertEqual(1, predicatePair.Registers[1].Index);
AssertEqual(8, predicatePair.ElementWidth);
var predicatePairSemantics = generatedPredicatePair.GetOperandSemantics();
AssertEqual(A64OperandKind.RegisterGroup, predicatePairSemantics[0].Kind);
AssertEqual(A64OperandDirection.Output, predicatePairSemantics[0].Direction);
AssertEqual(2, predicatePairSemantics[0].ShapeCount);
AssertEqual(8, predicatePairSemantics[0].ElementWidth);
AssertGeneratedRoundTrip(generatedPredicatePair, 0x25205010u);

if (!A64Decoder.TryDecode(0x1E701001u, 0, A64FeatureSet.From(A64Feature.FloatingPoint), out var generatedFpDouble, out var fpDoubleDiagnostic))
{
    throw new InvalidOperationException($"Generated FP64 immediate decode failed: {fpDoubleDiagnostic}");
}

AssertEqual(-2.0, ((FloatingImmediateOperand)generatedFpDouble.Operands[1]).Value);
AssertGeneratedRoundTrip(generatedFpDouble, 0x1E701001u);

if (!A64Decoder.TryDecode(0xD2A24680u, 0, A64FeatureSet.Base, out var generatedMovz, out var movzDiagnostic))
{
    throw new InvalidOperationException($"Generated MOVZ decode failed: {movzDiagnostic}");
}

AssertEqual(0x1234L, ((ImmediateOperand)generatedMovz.Operands[1]).Value);
AssertEqual(16L, ((ImmediateOperand)generatedMovz.Operands[2]).Value);
AssertEqual(A64ImmediateSemanticKind.MoveWideImmediate, ((ImmediateOperand)generatedMovz.Operands[1]).SemanticKind);
AssertEqual(A64ImmediateSemanticKind.Shift, ((ImmediateOperand)generatedMovz.Operands[2]).SemanticKind);
AssertGeneratedRoundTrip(generatedMovz, 0xD2A24680u);

if (!A64Decoder.TryDecode(0x12A00021u, 0, A64FeatureSet.Base, out var generatedMovn, out var movnDiagnostic))
{
    throw new InvalidOperationException($"Generated MOVN decode failed: {movnDiagnostic}");
}

AssertEqual(1L, ((ImmediateOperand)generatedMovn.Operands[1]).Value);
AssertEqual(16L, ((ImmediateOperand)generatedMovn.Operands[2]).Value);
AssertGeneratedRoundTrip(generatedMovn, 0x12A00021u);

if (!A64Decoder.TryDecode(0xF2F579A2u, 0, A64FeatureSet.Base, out var generatedMovk, out var movkDiagnostic))
{
    throw new InvalidOperationException($"Generated MOVK decode failed: {movkDiagnostic}");
}

AssertEqual(0xABCDL, ((ImmediateOperand)generatedMovk.Operands[1]).Value);
AssertEqual(48L, ((ImmediateOperand)generatedMovk.Operands[2]).Value);
AssertGeneratedRoundTrip(generatedMovk, 0xF2F579A2u);

if (!A64Decoder.TryDecode(0x2F05E540u, 0, A64FeatureSet.From(A64Feature.Neon), out var generatedSimdImmediate, out var simdImmediateDiagnostic))
{
    throw new InvalidOperationException($"Generated AdvSIMD immediate decode failed: {simdImmediateDiagnostic}");
}

AssertEqual(unchecked((long)0xFF00FF00FF00FF00UL), ((ImmediateOperand)generatedSimdImmediate.Operands[1]).Value);
AssertEqual(A64ImmediateSemanticKind.SimdImmediate, ((ImmediateOperand)generatedSimdImmediate.Operands[1]).SemanticKind);
AssertGeneratedRoundTrip(generatedSimdImmediate, 0x2F05E540u);

if (!A64Decoder.TryDecode(0x92000000u, 0, A64FeatureSet.Base, out var generatedLogicalImmediate, out var logicalImmediateDiagnostic))
{
    throw new InvalidOperationException($"Generated logical immediate decode failed: {logicalImmediateDiagnostic}");
}

AssertEqual(
    A64ImmediateSemanticKind.LogicalImmediate,
    ((ImmediateOperand)generatedLogicalImmediate.Operands[2]).SemanticKind);
AssertGeneratedRoundTrip(generatedLogicalImmediate, 0x92000000u);

AssertGeneratedRoundTrip(
    generatedSimdImmediate with
    {
        Operands =
        [
            generatedSimdImmediate.Operands[0],
            new ImmediateOperand(unchecked((long)0x00FF00FF00FF00FFUL)),
        ],
    },
    0x2F02E6A0u);

if (!A64Decoder.TryDecode(0x4F002640u, 0, A64FeatureSet.From(A64Feature.Neon), out var generatedModifiedShift, out var modifiedShiftDiagnostic))
{
    throw new InvalidOperationException($"Generated modified vector-shift decode failed: {modifiedShiftDiagnostic}");
}

AssertEqual(0x12L, ((ImmediateOperand)generatedModifiedShift.Operands[1]).Value);
AssertEqual(8L, ((ImmediateOperand)generatedModifiedShift.Operands[2]).Value);
AssertGeneratedRoundTrip(generatedModifiedShift, 0x4F002640u);
AssertFails(
    new A64Instruction(
        A64InstructionId.Generated,
        "orr",
        [
            new RegisterOperand(A64Register.Vector(0, 64)),
            new ImmediateOperand(1),
            new ImmediateOperand(16),
        ],
        0,
        0)
    {
        SourceName = "ORRv4i16",
    },
    "valid AdvSIMD vector shift");

var encodedBytes = new byte[4];
if (!AsmStoneApi.TryEncode(generatedLoad, encodedBytes, out var byteEncodeDiagnostic))
{
    throw new InvalidOperationException($"Span encode failed: {byteEncodeDiagnostic}");
}

AssertEqual(0x20, encodedBytes[0]);
AssertEqual(0x10, encodedBytes[1]);
AssertEqual(0x40, encodedBytes[2]);
AssertEqual(0xB9, encodedBytes[3]);
if (!generatedLoad.Flags.HasFlag(A64InstructionFlags.IsLoad)
    || !generatedCas.Flags.HasFlag(A64InstructionFlags.IsLoad)
    || !generatedCas.Flags.HasFlag(A64InstructionFlags.IsStore))
{
    throw new InvalidOperationException("Generated memory flags were not preserved.");
}

if (A64Encoder.TryEncode(generatedCas, A64FeatureSet.Base, out _, out var restrictedCasDiagnostic)
    || restrictedCasDiagnostic.Code != A64DiagnosticCode.UnsupportedFeature)
{
    throw new InvalidOperationException("Feature-aware generated encoding must reject LSE in Base.");
}

var allRoundTripFailures = new List<string>();
foreach (var record in generatedRecords.Where(record => record.HasCompleteEncoding))
{
    if (!A64InstructionCatalog.TryLookup(record.Value, A64FeatureSet.All, out _))
    {
        continue;
    }

    if (!A64Decoder.TryDecode(record.Value, 0x1000, A64FeatureSet.All, out var roundTripInstruction, out var roundTripDiagnostic)
        || !A64Encoder.TryEncode(roundTripInstruction, A64FeatureSet.All, out var roundTripEncoding, out roundTripDiagnostic)
        || roundTripEncoding != record.Value)
    {
        allRoundTripFailures.Add($"{record.Name}: {roundTripDiagnostic}");
    }
}

if (allRoundTripFailures.Count != 0)
{
    throw new InvalidOperationException(
        $"Generated complete-record round-trip failures: {allRoundTripFailures.Count}; "
        + string.Join("; ", allRoundTripFailures.Take(8)));
}

var generatedFallbackOperands = new List<string>();
foreach (var record in generatedRecords.Where(record => record.HasCompleteEncoding))
{
    if (!A64Decoder.TryDecode(record.Value, 0x1000, A64FeatureSet.All, out var decodedRecord, out _)
        || !string.Equals(decodedRecord.SourceName, record.Name, StringComparison.Ordinal))
    {
        continue;
    }

    for (var operandIndex = 0; operandIndex < decodedRecord.Operands.Count; operandIndex++)
    {
        if (decodedRecord.Operands[operandIndex] is EncodedFieldOperand encodedField)
        {
            generatedFallbackOperands.Add(
                $"{record.Name}:{encodedField.Name}:{encodedField.Codec}");
        }
    }
}

if (generatedFallbackOperands.Count != 0)
{
    throw new InvalidOperationException(
        $"Generated complete-record decoding still uses opaque operands: {generatedFallbackOperands.Count}; "
        + string.Join("; ", generatedFallbackOperands.Take(8)));
}

var generatedViewFallbacks = new List<string>();
var generatedViewBuffer = new A64OperandView[32];
foreach (var record in generatedRecords.Where(record => record.HasCompleteEncoding))
{
    if (!AsmStoneApi.TryDecodeView(
            record.Value,
            0x1000,
            A64FeatureSet.All,
            generatedViewBuffer,
            out var decodedView,
            out _)
        || !string.Equals(decodedView.SourceName, record.Name, StringComparison.Ordinal))
    {
        continue;
    }

    for (var operandIndex = 0; operandIndex < decodedView.OperandCount; operandIndex++)
    {
        if (decodedView.Operands[operandIndex].Kind == A64OperandKind.EncodedField)
        {
            generatedViewFallbacks.Add(
                $"{record.Name}:{decodedView.Operands[operandIndex].Name}");
        }
    }
}

if (generatedViewFallbacks.Count != 0)
{
    throw new InvalidOperationException(
        $"Generated view decoding still uses opaque operands: {generatedViewFallbacks.Count}; "
        + string.Join("; ", generatedViewFallbacks.Take(8)));
}

var generatedMissingSemantics = new List<string>();
foreach (var record in generatedRecords.Where(record => record.HasCompleteEncoding))
{
    if (!A64Decoder.TryDecode(record.Value, 0x1000, A64FeatureSet.All, out var decodedRecord, out _)
        || !string.Equals(decodedRecord.SourceName, record.Name, StringComparison.Ordinal))
    {
        continue;
    }

    foreach (var semantic in decodedRecord.GetOperandSemantics())
    {
        if (semantic.Operand is null)
        {
            generatedMissingSemantics.Add($"{record.Name}:{semantic.Name}");
        }
    }
}

if (generatedMissingSemantics.Count != 0)
{
    throw new InvalidOperationException(
        $"Generated complete-record semantics are missing operands: {generatedMissingSemantics.Count}; "
        + string.Join("; ", generatedMissingSemantics.Take(8)));
}

var generatedSemanticFallbacks = new List<string>();
foreach (var record in generatedRecords.Where(record => record.HasCompleteEncoding))
{
    if (!A64Decoder.TryDecode(record.Value, 0x1000, A64FeatureSet.All, out var decodedRecord, out _)
        || !string.Equals(decodedRecord.SourceName, record.Name, StringComparison.Ordinal))
    {
        continue;
    }

    foreach (var semantic in decodedRecord.GetOperandSemantics())
    {
        if (semantic.Kind == A64OperandKind.EncodedField)
        {
            generatedSemanticFallbacks.Add($"{record.Name}:{semantic.Name}:{semantic.Codec}");
        }
    }
}

if (generatedSemanticFallbacks.Count != 0)
{
    throw new InvalidOperationException(
        $"Generated complete-record semantics still use opaque kinds: {generatedSemanticFallbacks.Count}; "
        + string.Join("; ", generatedSemanticFallbacks.Take(8)));
}

var sampledGeneratedRecords = A64InstructionCatalog.Enumerate()
    .Where(record => record.HasCompleteEncoding)
    .Where(record => A64InstructionCatalog.TryLookup(record.Value, A64FeatureSet.All, out _))
    .Where((_, index) => index % 37 == 0)
    .Take(200)
    .ToArray();
foreach (var record in sampledGeneratedRecords)
{
    if (!A64Decoder.TryDecode(record.Value, 0x1000, A64FeatureSet.All, out var sampledInstruction, out var sampledDiagnostic))
    {
        throw new InvalidOperationException($"Generated sample decode failed for {record.Name}: {sampledDiagnostic}");
    }

    if (!A64Encoder.TryEncode(sampledInstruction, A64FeatureSet.All, out var sampledEncoding, out sampledDiagnostic))
    {
        throw new InvalidOperationException($"Generated sample encode failed for {record.Name}: {sampledDiagnostic}");
    }

    AssertEqual(record.Value, sampledEncoding, $"generated sample {record.Name}");
}

var random = new Random(0xA64);
var randomRoundTripCount = 0;
var randomRoundTripFailures = new List<string>();
for (var sample = 0; sample < 10000; sample++)
{
    var record = generatedRecords[random.Next(generatedRecords.Length)];
    if (!record.HasCompleteEncoding)
    {
        continue;
    }

    var word = record.Value;
    for (var bit = 0; bit < 32; bit++)
    {
        if ((record.Mask & (1u << bit)) == 0 && random.Next(2) == 1)
        {
            word |= 1u << bit;
        }
    }

    if (!A64Decoder.TryDecode(word, 0x1000, A64FeatureSet.All, out var randomInstruction, out var randomDiagnostic))
    {
        continue;
    }

    randomRoundTripCount++;
    var randomEncoded = A64Encoder.TryEncode(
        randomInstruction,
        A64FeatureSet.All,
        out var randomEncoding,
        out randomDiagnostic);
    if (!randomEncoded || randomEncoding != word)
    {
        randomRoundTripFailures.Add(
            $"{record.Name}->{randomInstruction.SourceName}/0x{word:X8}->0x{randomEncoding:X8}: {randomDiagnostic}; "
            + string.Join(",", randomInstruction.Operands.Select(operand => operand.ToString())));
    }
}

if (randomRoundTripFailures.Count != 0)
{
    throw new InvalidOperationException(
        $"Generated random round-trip failures: {randomRoundTripFailures.Count}; "
        + string.Join("; ", randomRoundTripFailures.Take(8)));
}

if (randomRoundTripCount < 5000)
{
    throw new InvalidOperationException($"Generated random sample hit too few records: {randomRoundTripCount}.");
}

AssertFails(
    Generated(
        "ADDSXri",
        "adds",
        [
            new RegisterOperand(A64Register.X(0)),
            new RegisterOperand(A64Register.Zr()),
            new ImmediateOperand(1),
        ],
        0,
        0),
    "register role");
AssertFails(
    Generated(
        "ADDXri",
        "add",
        [
            new RegisterOperand(A64Register.Zr()),
            new RegisterOperand(A64Register.X(0)),
            new ImmediateOperand(1),
        ],
        0,
        0),
    "register role");

if (!A64Decoder.TryDecode(0, 0, out var undefinedInstruction, out var unknownDiagnostic))
{
    throw new InvalidOperationException($"Base decoder must resolve UDF: {unknownDiagnostic}");
}

AssertEqual(A64InstructionId.Generated, undefinedInstruction.Id);
AssertEqual("UDF", undefinedInstruction.SourceName);
AssertEqual(A64InstructionId.Generated, DecodeGenerated(0, 0).Id);

var rawAllocationStart = GC.GetAllocatedBytesForCurrentThread();
for (var rawSample = 0; rawSample < 1000; rawSample++)
{
    if (!AsmStoneApi.TryDecodeRaw(0xB9401020u, 4, A64FeatureSet.Base, out var rawInstruction, out var rawDiagnostic)
        || rawInstruction.SourceName != "LDRWui"
        || !rawInstruction.TryGetField("Rt", out var rawRt)
        || rawRt.Value != 0)
    {
        throw new InvalidOperationException($"Zero-allocation raw decode failed: {rawDiagnostic}");
    }
}

if (GC.GetAllocatedBytesForCurrentThread() != rawAllocationStart)
{
    throw new InvalidOperationException("Raw generated decode allocated on the hot path.");
}

var viewOperands = new A64OperandView[8];
var viewAllocationStart = GC.GetAllocatedBytesForCurrentThread();
for (var viewSample = 0; viewSample < 1000; viewSample++)
{
    if (!AsmStoneApi.TryDecodeView(
            0xB9401020u,
            4,
            A64FeatureSet.Base,
            viewOperands,
            out var viewInstruction,
            out var viewDiagnostic)
        || viewInstruction.SourceName != "LDRWui"
        || viewInstruction.OperandCount != 2
        || viewInstruction.Operands[0].Kind != A64OperandKind.Register
        || viewInstruction.Operands[0].Direction != A64OperandDirection.Output
        || viewInstruction.Operands[0].RegisterWidth != 32
        || viewInstruction.Operands[0].FieldWidth != 5
        || !viewInstruction.Operands[0].AllowsZeroRegister
        || viewInstruction.Operands[0].SemanticDomain != "GPR32z"
        || viewInstruction.Operands[1].Kind != A64OperandKind.Memory
        || viewInstruction.Operands[1].Direction != A64OperandDirection.Input
        || viewInstruction.Operands[1].RegisterWidth != 64
        || !viewInstruction.Operands[1].AllowsStackPointer
        || viewInstruction.Operands[1].BaseRegister != A64Register.X(1))
    {
        throw new InvalidOperationException($"Zero-allocation view decode failed: {viewDiagnostic}");
    }
}

if (GC.GetAllocatedBytesForCurrentThread() != viewAllocationStart)
{
    throw new InvalidOperationException("Semantic view decode allocated on the hot path.");
}

if (!AsmStoneApi.TryDecodeView(
        0x80600008u,
        0,
        A64FeatureSet.All,
        viewOperands,
        out var tileView,
        out var tileViewDiagnostic)
    || tileView.Operands[0].Kind != A64OperandKind.MatrixRegister
    || tileView.Operands[3].MatrixRegisterKind != A64MatrixRegisterKind.Zk
    || tileView.Operands[3].MatrixRegisterIndex != 20)
{
    throw new InvalidOperationException($"Typed matrix view decode failed: {tileViewDiagnostic}");
}

if (!AsmStoneApi.TryDecodeView(
        0x65808000u,
        0,
        A64FeatureSet.From(A64Feature.Sve),
        viewOperands,
        out var predicatedView,
        out var predicatedViewDiagnostic)
    || predicatedView.Operands[1].PredicateMode != A64PredicateMode.Merge
    || predicatedView.Operands[1].ElementWidth != 32
    || predicatedView.Operands[1].RegisterConstraint != new A64RegisterConstraint(0, 7)
    || predicatedView.Operands[1].SemanticDomain != "PPR3bAny")
{
    throw new InvalidOperationException($"Typed predicate view decode failed: {predicatedViewDiagnostic}");
}

if (!AsmStoneApi.TryDecodeView(
        0x14000004u,
        0,
        A64FeatureSet.Base,
        viewOperands,
        out var branchView,
        out var branchViewDiagnostic)
    || !branchView.Flags.HasFlag(A64InstructionFlags.IsPcRelative)
    || branchView.Operands[0].Kind != A64OperandKind.Target)
{
    throw new InvalidOperationException($"PC-relative view metadata failed: {branchViewDiagnostic}");
}

if (!AsmStoneApi.TryDecodeView(
        0x8B226C20u,
        0,
        A64FeatureSet.Base,
        viewOperands,
        out var modifierView,
        out var modifierViewDiagnostic)
    || modifierView.OperandCount != 4
    || modifierView.Operands[3].Kind != A64OperandKind.RegisterModifier
    || modifierView.Operands[3].ModifierKind != A64RegisterModifierKind.Uxtx
    || modifierView.Operands[3].ModifierAmount != 3)
{
    throw new InvalidOperationException($"Register modifier view metadata failed: {modifierViewDiagnostic}");
}

if (!AsmStoneApi.TryDecodeView(
        0x8B020C20u,
        0,
        A64FeatureSet.Base,
        viewOperands,
        out var shiftedRegisterView,
        out var shiftedRegisterViewDiagnostic)
    || shiftedRegisterView.Operands[2].Kind != A64OperandKind.ModifiedRegister
    || shiftedRegisterView.Operands[2].ModifierKind != A64RegisterModifierKind.Lsl
    || shiftedRegisterView.Operands[2].ModifierAmount != 3)
{
    throw new InvalidOperationException($"Modified-register view metadata failed: {shiftedRegisterViewDiagnostic}");
}

var zeroAllocationEncodeInstruction = Generated(
    "ADDXri",
    "add",
    [
        new RegisterOperand(A64Register.X(0)),
        new RegisterOperand(A64Register.X(1)),
        new ImmediateOperand(42),
    ],
    0,
    0);
var encodeAllocationStart = GC.GetAllocatedBytesForCurrentThread();
for (var encodeSample = 0; encodeSample < 1000; encodeSample++)
{
    if (!A64Encoder.TryEncode(zeroAllocationEncodeInstruction, A64FeatureSet.Base, out var encoded, out var encodeDiagnostic)
        || encoded != 0x9100A820u)
    {
        throw new InvalidOperationException($"Zero-allocation generated encode failed: {encodeDiagnostic}");
    }
}

if (GC.GetAllocatedBytesForCurrentThread() != encodeAllocationStart)
{
    throw new InvalidOperationException("Generated encode allocated on the hot path.");
}

var memoryEncodeAllocationStart = GC.GetAllocatedBytesForCurrentThread();
for (var memoryEncodeSample = 0; memoryEncodeSample < 1000; memoryEncodeSample++)
{
    if (!A64Encoder.TryEncode(generatedLoad, A64FeatureSet.Base, out var memoryEncoding, out var memoryEncodeDiagnostic)
        || memoryEncoding != 0xB9401020u)
    {
        throw new InvalidOperationException($"Zero-allocation generated memory encode failed: {memoryEncodeDiagnostic}");
    }
}

if (GC.GetAllocatedBytesForCurrentThread() != memoryEncodeAllocationStart)
{
    throw new InvalidOperationException("Generated memory encode allocated on the hot path.");
}

var rawFieldValues = new A64FieldValue[]
{
    new("Rd", 0),
    new("Rn", 1),
    new("imm", 42),
};
var rawFieldAllocationStart = GC.GetAllocatedBytesForCurrentThread();
for (var rawFieldSample = 0; rawFieldSample < 1000; rawFieldSample++)
{
    if (!AsmStoneApi.TryEncodeFields(
            "ADDXri",
            rawFieldValues,
            A64FeatureSet.Base,
            out var rawFieldEncoding,
            out var rawFieldDiagnostic)
        || rawFieldEncoding != 0x9100A820u)
    {
        throw new InvalidOperationException($"Zero-allocation raw field encode failed: {rawFieldDiagnostic}");
    }
}

if (GC.GetAllocatedBytesForCurrentThread() != rawFieldAllocationStart)
{
    throw new InvalidOperationException("Raw field span encoding allocated on the hot path.");
}

if (AsmStoneApi.TryDecodeRaw(0xFFFFFFFFu, 0, A64FeatureSet.All, out _, out var rawUnknownDiagnostic)
    || rawUnknownDiagnostic.Code != A64DiagnosticCode.UnknownEncoding)
{
    throw new InvalidOperationException("Raw decode must reject an unknown encoding.");
}

Console.WriteLine("AsmStone.Tests: PASS");

static A64Instruction Decode(uint encoding, ulong address)
{
    if (!A64Decoder.TryDecode(encoding, address, out var instruction, out var diagnostic))
    {
        throw new InvalidOperationException($"Decode 0x{encoding:X8} failed: {diagnostic}");
    }

    return instruction;
}

static A64Instruction DecodeGenerated(uint encoding, ulong address)
{
    if (!A64Decoder.TryDecode(encoding, address, A64FeatureSet.Base, out var instruction, out var diagnostic))
    {
        throw new InvalidOperationException($"Generated decode 0x{encoding:X8} failed: {diagnostic}");
    }

    return instruction;
}

static A64Instruction Generated(
    string sourceName,
    string mnemonic,
    IReadOnlyList<A64Operand> operands,
    uint encoding,
    ulong address)
{
    return new A64Instruction(
        A64InstructionId.Generated,
        mnemonic,
        operands,
        encoding,
        address)
    {
        SourceName = sourceName,
    };
}

static void AssertEncoded(A64Instruction instruction, ulong address, uint expected)
{
    if (!A64Encoder.TryEncode(instruction with { Address = address }, out var actual, out var diagnostic))
    {
        throw new InvalidOperationException($"Encode {instruction.Mnemonic} failed: {diagnostic}");
    }

    AssertEqual(expected, actual, instruction.Mnemonic);
}

static A64EncodingInfo GetByName(string name)
{
    if (!A64InstructionCatalog.TryGetByName(name, out var info))
    {
        throw new InvalidOperationException($"Catalog name lookup failed for {name}.");
    }

    return info;
}

static void AssertCatalog(uint encoding, string expectedName, string expectedMnemonic)
{
    if (!A64InstructionCatalog.TryLookup(encoding, out var info))
    {
        throw new InvalidOperationException($"Catalog lookup failed for 0x{encoding:X8}.");
    }

    AssertEqual(expectedName, info.Name, $"catalog 0x{encoding:X8}");
    AssertEqual(expectedMnemonic, info.Mnemonic, $"catalog 0x{encoding:X8}");
}

static void AssertFails(A64Instruction instruction, string expectedMessage)
{
    if (A64Encoder.TryEncode(instruction, out _, out var diagnostic)
        || !diagnostic.Message.Contains(expectedMessage, StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"Expected {instruction.Mnemonic} to fail with '{expectedMessage}', got {diagnostic}.");
    }
}

static void AssertRawFieldsFail(
    string name,
    IReadOnlyDictionary<string, uint> fields,
    string expectedMessage,
    A64FeatureSet? features = null)
{
    if (AsmStoneApi.TryEncodeFields(name, fields, features ?? A64FeatureSet.Base, out _, out var diagnostic)
        || !diagnostic.Message.Contains(expectedMessage, StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"Expected raw {name} encoding to fail with '{expectedMessage}', got {diagnostic}.");
    }
}

static void AssertGeneratedRoundTrip(A64Instruction instruction, uint expected)
{
    if (!A64Encoder.TryEncode(instruction, out var actual, out var diagnostic))
    {
        throw new InvalidOperationException($"Generated encode {instruction.SourceName} failed: {diagnostic}");
    }

    AssertEqual(expected, actual, $"generated {instruction.SourceName}");
}

static void AssertGeneratedMemoryRoundTrip(uint encoding, ulong address, A64MemoryAddressingMode mode)
{
    if (!A64Decoder.TryDecode(encoding, address, A64FeatureSet.Base, out var instruction, out var diagnostic))
    {
        throw new InvalidOperationException($"Generated memory decode failed: {diagnostic}");
    }

    AssertEqual(mode, ((MemoryOperand)instruction.Operands.Last()).Mode);
    AssertGeneratedRoundTrip(instruction, encoding);
}

static void AssertEqual<T>(T expected, T actual, string? context = null)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException(
            $"Assertion failed{(context is null ? string.Empty : $" ({context})")}: expected {expected}, got {actual}.");
    }
}
