using A64FeatureSet = global::AsmStone.Model.A64FeatureSet;
using A64InstructionModel = global::AsmStone.Model.A64Instruction;
using A64InstructionId = global::AsmStone.Model.A64InstructionId;
using A64Operand = global::AsmStone.Model.A64Operand;
using A64Register = global::AsmStone.Model.A64Register;
using A64RegisterOperand = global::AsmStone.Model.RegisterOperand;
using A64ImmediateOperand = global::AsmStone.Model.ImmediateOperand;
using A64EnumImmediateOperand = global::AsmStone.Model.EnumImmediateOperand;
using A64EnumKind = global::AsmStone.Model.A64EnumKind;
using A64MemoryOperand = global::AsmStone.Model.MemoryOperand;
using A64TargetOperand = global::AsmStone.Model.TargetOperand;
using A64ModifiedRegisterOperand = global::AsmStone.Model.ModifiedRegisterOperand;
using A64OperandDirection = global::AsmStone.Model.A64OperandDirection;

namespace UrProtect.Core.Aarch64Semantics;

public enum Aarch64InstructionEncodingFamily
{
    Branch26,
    Call26,
    ConditionalBranch19,
    TestBranch14,
    AdrPrelLo21,
    AdrPrelPgHi21,
    Literal19,
    AddImmediate,
    LoadStoreUnsignedImmediate,
    MoveWideImmediate,
    MoveRegister,
    CompareImmediate,
    Return,
}

public enum Aarch64InstructionEncodeDiagnosticCode
{
    None,
    InvalidRequest,
    SourceDecodeFailed,
    TemplateDecodeFailed,
    UnsupportedInstructionFamily,
    OperandMissing,
    OperandWidthMismatch,
    InvalidOperand,
    TargetMisaligned,
    TargetOutOfRange,
    BackendEncodeFailed,
    RoundTripDecodeFailed,
    RoundTripMismatch,
}

public readonly record struct Aarch64InstructionEncodeRequest(
    uint SourceEncoding,
    ulong SourceAddress,
    ulong OutputAddress,
    Aarch64InstructionEncodingFamily Family,
    ulong TargetOrImmediate,
    int AccessWidth = 0,
    uint? OutputTemplateEncoding = null,
    bool PreserveSourceImmediate = false,
    int RegisterWidth = 0);

public readonly record struct Aarch64InstructionBuildRequest(
    Aarch64InstructionEncodingFamily Family,
    ulong Address,
    ulong TargetOrImmediate,
    byte DestinationRegister = 0,
    byte BaseRegister = 1,
    int DestinationWidth = 64,
    int AccessWidth = 0,
    bool IsStore = false,
    bool ShiftedImmediate = false,
    int ImmediateShift = 0,
    byte? SourceRegister = null,
    int ConditionCode = 0);

public readonly record struct Aarch64InstructionEncodeResult(
    bool IsSuccess,
    uint Encoding,
    Aarch64Instruction? Instruction,
    Aarch64InstructionEncodeDiagnosticCode DiagnosticCode,
    string Diagnostic)
{
    public static Aarch64InstructionEncodeResult Failure(
        Aarch64InstructionEncodeDiagnosticCode code,
        string diagnostic) =>
        new(false, 0, null, code, diagnostic);

    public static Aarch64InstructionEncodeResult Success(
        uint encoding,
        Aarch64Instruction instruction) =>
        new(true, encoding, instruction, Aarch64InstructionEncodeDiagnosticCode.None, string.Empty);
}

public interface IAarch64InstructionEncoder
{
    Aarch64InstructionEncodeResult TryEncode(Aarch64InstructionEncodeRequest request);

    Aarch64InstructionEncodeResult TryCreate(Aarch64InstructionBuildRequest request);

    Aarch64EncodeResult TryPermuteGeneralRegisters(
        uint encoding,
        ulong address,
        IReadOnlyDictionary<byte, byte> mapping);
}

/// <summary>
/// The project-owned AsmStone boundary for final generated or re-encoded words.
/// </summary>
/// <remarks>
/// UrProtect supplies the instruction family, mapped addresses, relocation result,
/// and expected access width. AsmStone owns instruction operand encoding and
/// legality. Every returned word is decoded again through AsmStone.
/// </remarks>
public sealed class Aarch64InstructionEncoder : IAarch64InstructionEncoder
{
    private const string MovzWSourceName = "MOVZWi";
    private const string MovnWSourceName = "MOVNWi";
    private const string MovkWSourceName = "MOVKWi";
    private const string MovzXSourceName = "MOVZXi";
    private const string MovnXSourceName = "MOVNXi";
    private const string MovkXSourceName = "MOVKXi";
    private const string OrrWSourceName = "ORRWrs";
    private const string OrrXSourceName = "ORRXrs";
    private const string LogicalShiftedRegister32Codec = "logical_shifted_reg32";
    private const string LogicalShiftedRegister64Codec = "logical_shifted_reg64";
    private static readonly string[] ConditionalBranchDomains = { "am_brcond", "am_brcmpcond" };
    private static readonly string[] TestBranchDomains = { "am_tbrcond" };
    private static readonly string[] LiteralDomains = { "am_ldrlit" };
    private readonly A64FeatureSet features;
    private readonly AsmStoneAdapter decoder;

    public Aarch64InstructionEncoder()
        : this(A64FeatureSet.All)
    {
    }

    internal Aarch64InstructionEncoder(A64FeatureSet features)
    {
        this.features = features ?? throw new ArgumentNullException(nameof(features));
        decoder = new AsmStoneAdapter(features);
    }

    public Aarch64InstructionEncodeResult TryEncode(Aarch64InstructionEncodeRequest request)
    {
        if (request.SourceAddress % sizeof(uint) != 0
            || request.OutputAddress % sizeof(uint) != 0)
        {
            return Failure(
                Aarch64InstructionEncodeDiagnosticCode.InvalidRequest,
                "AArch64 source and output instruction addresses must be four-byte aligned.");
        }

        if (!global::AsmStone.AsmStoneApi.TryDecode(
                request.SourceEncoding,
                request.SourceAddress,
                features,
                out var sourceInstruction,
                out var decodeDiagnostic))
        {
            return Failure(
                Aarch64InstructionEncodeDiagnosticCode.SourceDecodeFailed,
                $"AsmStone could not decode the source instruction: {decodeDiagnostic}");
        }

        if (!TryValidateFamily(sourceInstruction, request.Family, request.AccessWidth, request.RegisterWidth, out var familyError))
        {
            return Failure(
                familyError.Code,
                familyError.Message);
        }

        var templateInstruction = sourceInstruction;
        if (request.OutputTemplateEncoding is { } outputTemplateEncoding)
        {
            if (!global::AsmStone.AsmStoneApi.TryDecode(
                    outputTemplateEncoding,
                    request.OutputAddress,
                    features,
                    out var decodedTemplate,
                    out var templateDiagnostic))
            {
                return Failure(
                    Aarch64InstructionEncodeDiagnosticCode.TemplateDecodeFailed,
                    $"AsmStone could not decode the output instruction template: {templateDiagnostic}");
            }

            if (!TryValidateFamily(decodedTemplate, request.Family, request.AccessWidth, request.RegisterWidth, out var templateFamilyError)
                || !string.Equals(
                    decodedTemplate.SourceName,
                    sourceInstruction.SourceName,
                    StringComparison.Ordinal))
            {
                return Failure(
                    templateFamilyError.Code == Aarch64InstructionEncodeDiagnosticCode.None
                        ? Aarch64InstructionEncodeDiagnosticCode.InvalidOperand
                        : templateFamilyError.Code,
                    string.IsNullOrEmpty(templateFamilyError.Message)
                        ? "The output instruction template does not preserve the source instruction family."
                        : templateFamilyError.Message);
            }

            templateInstruction = decodedTemplate;
        }

        var operands = templateInstruction.Operands.ToArray();
        var expectedValue = request.TargetOrImmediate;
        switch (request.Family)
        {
            case Aarch64InstructionEncodingFamily.Branch26:
            case Aarch64InstructionEncodingFamily.Call26:
            case Aarch64InstructionEncodingFamily.ConditionalBranch19:
            case Aarch64InstructionEncodingFamily.TestBranch14:
            case Aarch64InstructionEncodingFamily.AdrPrelLo21:
            case Aarch64InstructionEncodingFamily.AdrPrelPgHi21:
            case Aarch64InstructionEncodingFamily.Literal19:
                ReplaceTarget(operands, request.TargetOrImmediate);
                break;
            case Aarch64InstructionEncodingFamily.MoveWideImmediate:
                if (request.PreserveSourceImmediate)
                {
                    if (!TryGetSourceImmediate(
                            sourceInstruction,
                            request.Family,
                            out var sourceImmediate)
                        || sourceImmediate < 0)
                    {
                        return Failure(
                            Aarch64InstructionEncodeDiagnosticCode.InvalidOperand,
                            "The source move-wide instruction does not expose a non-negative immediate.");
                    }

                    expectedValue = checked((ulong)sourceImmediate);
                }

                if (expectedValue > ushort.MaxValue)
                {
                    return Failure(
                        Aarch64InstructionEncodeDiagnosticCode.InvalidOperand,
                        "Move-wide immediate must fit the 16-bit halfword domain.");
                }

                ReplaceImmediate(operands, (long)expectedValue);
                break;
            case Aarch64InstructionEncodingFamily.MoveRegister:
            case Aarch64InstructionEncodingFamily.Return:
                break;
            case Aarch64InstructionEncodingFamily.CompareImmediate:
            case Aarch64InstructionEncodingFamily.AddImmediate:
            case Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate:
                if (request.PreserveSourceImmediate)
                {
                    if (!TryGetSourceImmediate(
                            sourceInstruction,
                            request.Family,
                            out var sourceImmediate)
                        || sourceImmediate < 0)
                    {
                        return Failure(
                            Aarch64InstructionEncodeDiagnosticCode.InvalidOperand,
                            "The source instruction does not expose a non-negative relocation immediate.");
                    }

                    expectedValue = checked((ulong)sourceImmediate);
                }

                if (expectedValue > long.MaxValue)
                {
                    return Failure(
                        Aarch64InstructionEncodeDiagnosticCode.InvalidOperand,
                        "The immediate value exceeds the signed operand domain.");
                }

                if (request.Family == Aarch64InstructionEncodingFamily.AddImmediate)
                {
                    ReplaceImmediate(
                        operands,
                        (long)expectedValue,
                        request.PreserveSourceImmediate
                            ? sourceInstruction.Operands.OfType<A64ImmediateOperand>().SingleOrDefault()?.EncodedValue
                            : null);
                }
                else if (request.Family == Aarch64InstructionEncodingFamily.CompareImmediate)
                {
                    ReplaceImmediate(
                        operands,
                        (long)expectedValue,
                        request.PreserveSourceImmediate
                            ? sourceInstruction.Operands.OfType<A64ImmediateOperand>().SingleOrDefault()?.EncodedValue
                            : null);
                }
                else
                {
                    ReplaceMemoryOffset(operands, (long)expectedValue);
                }
                break;
            default:
                return Failure(
                    Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily,
                    $"The project encoder does not own instruction family '{request.Family}'.");
        }

        var outputInstruction = templateInstruction with
        {
            Address = request.OutputAddress,
            Operands = operands,
        };
        return EncodeAndRoundTrip(outputInstruction, request.Family, expectedValue, request.RegisterWidth);
    }

    public Aarch64InstructionEncodeResult TryCreate(Aarch64InstructionBuildRequest request)
    {
        if (request.Address % sizeof(uint) != 0)
        {
            return Failure(
                Aarch64InstructionEncodeDiagnosticCode.InvalidRequest,
                "AArch64 instruction addresses must be four-byte aligned.");
        }

        if (!TryBuildInstruction(request, out var instruction, out var error))
        {
            return Failure(error.Code, error.Message);
        }

        var expectedValue = request.Family == Aarch64InstructionEncodingFamily.MoveRegister
            || request.Family == Aarch64InstructionEncodingFamily.Return
            ? 0UL
            : request.TargetOrImmediate;
        var expectedRegisterWidth = request.Family switch
        {
            Aarch64InstructionEncodingFamily.MoveWideImmediate
            or Aarch64InstructionEncodingFamily.MoveRegister
            or Aarch64InstructionEncodingFamily.CompareImmediate => request.DestinationWidth,
            Aarch64InstructionEncodingFamily.Return => 64,
            _ => 0,
        };
        return EncodeAndRoundTrip(instruction!, request.Family, expectedValue, expectedRegisterWidth);
    }

    public Aarch64EncodeResult TryPermuteGeneralRegisters(
        uint encoding,
        ulong address,
        IReadOnlyDictionary<byte, byte> mapping)
    {
        ArgumentNullException.ThrowIfNull(mapping);
        if (!global::AsmStone.AsmStoneApi.TryDecode(
                encoding,
                address,
                features,
                out var instruction,
                out var decodeDiagnostic))
        {
            return new Aarch64EncodeResult(false, 0, decodeDiagnostic.ToString());
        }

        var mappedOperands = instruction.Operands
            .Select(operand => MapGeneralRegisters(operand, mapping))
            .ToArray();
        var mappedInstruction = instruction with { Operands = mappedOperands };
        if (!global::AsmStone.AsmStoneApi.TryEncode(
                mappedInstruction,
                features,
                out var mappedEncoding,
                out var encodeDiagnostic))
        {
            return new Aarch64EncodeResult(false, 0, encodeDiagnostic.ToString());
        }

        if (!global::AsmStone.AsmStoneApi.TryDecode(
                mappedEncoding,
                address,
                features,
                out var roundTrip,
                out var roundTripDiagnostic)
            || !string.Equals(
                roundTrip.Mnemonic,
                instruction.Mnemonic,
                StringComparison.OrdinalIgnoreCase))
        {
            return new Aarch64EncodeResult(
                false,
                0,
                $"AsmStone register permutation did not round-trip: {roundTripDiagnostic}");
        }

        var projectRoundTrip = decoder.Decode(mappedEncoding, address);
        if (!projectRoundTrip.IsSuccess)
        {
            return new Aarch64EncodeResult(
                false,
                0,
                $"The project decoder rejected the AsmStone register permutation: {projectRoundTrip.Diagnostic}");
        }

        return new Aarch64EncodeResult(true, mappedEncoding, encodeDiagnostic.Message);
    }

    private Aarch64InstructionEncodeResult EncodeAndRoundTrip(
        A64InstructionModel instruction,
        Aarch64InstructionEncodingFamily family,
        ulong expectedValue,
        int expectedRegisterWidth = 0)
    {
        if (!global::AsmStone.AsmStoneApi.TryEncode(
                instruction,
                features,
                out var encoding,
                out var encodeDiagnostic))
        {
            return Failure(
                MapBackendDiagnostic(encodeDiagnostic.Code, family),
                $"AsmStone rejected the {family} operands: {encodeDiagnostic}");
        }

        if (!global::AsmStone.AsmStoneApi.TryDecode(
                encoding,
                instruction.Address,
                features,
                out var decoded,
                out var decodeDiagnostic))
        {
            return Failure(
                Aarch64InstructionEncodeDiagnosticCode.RoundTripDecodeFailed,
                $"AsmStone could not decode its encoded {family} word: {decodeDiagnostic}");
        }

        var familyMatches = TryValidateFamily(
            decoded,
            family,
            GetExpectedAccessWidth(instruction, family),
            expectedRegisterWidth,
            out var familyError);
        var valueMatches = familyMatches && MatchesExpectedValue(decoded, instruction, family, expectedValue);
        if (!familyMatches || !valueMatches)
        {
            var familyMessage = familyError.Message ?? string.Empty;
            var actualTarget = decoded.Operands.OfType<A64TargetOperand>().SingleOrDefault()?.Address;
            var actualImmediate = decoded.Operands.OfType<A64ImmediateOperand>().SingleOrDefault()?.Value;
            return Failure(
                Aarch64InstructionEncodeDiagnosticCode.RoundTripMismatch,
                string.IsNullOrEmpty(familyMessage)
                    ? $"AsmStone {family} encoding did not round-trip its requested operand (expected=0x{expectedValue:X}, target={(actualTarget is { } target ? $"0x{target:X}" : "<none>")}, immediate={(actualImmediate is { } immediate ? Convert.ToString(immediate, System.Globalization.CultureInfo.InvariantCulture) : "<none>")})."
                    : familyMessage);
        }

        var projectInstruction = decoder.Decode(encoding, instruction.Address);
        if (!projectInstruction.IsSuccess || projectInstruction.Instruction is null)
        {
            return Failure(
                Aarch64InstructionEncodeDiagnosticCode.RoundTripDecodeFailed,
                $"The project decoder rejected the AsmStone round-trip word: {projectInstruction.Diagnostic}");
        }

        return Aarch64InstructionEncodeResult.Success(encoding, projectInstruction.Instruction);
    }

    private static bool TryBuildInstruction(
        Aarch64InstructionBuildRequest request,
        out A64InstructionModel? instruction,
        out (Aarch64InstructionEncodeDiagnosticCode Code, string Message) error)
    {
        instruction = null;
        error = default;
        if (request.DestinationRegister > 30 || request.BaseRegister > 30)
        {
            error = (Aarch64InstructionEncodeDiagnosticCode.InvalidRequest,
                "Project instruction builders accept general-register indices from 0 through 30.");
            return false;
        }

        string sourceName;
        string mnemonic;
        A64Operand[] operands;
        switch (request.Family)
        {
            case Aarch64InstructionEncodingFamily.Branch26:
                sourceName = "B";
                mnemonic = "b";
                operands = new A64Operand[] { new A64TargetOperand(request.TargetOrImmediate) };
                break;
            case Aarch64InstructionEncodingFamily.Call26:
                sourceName = "BL";
                mnemonic = "bl";
                operands = new A64Operand[] { new A64TargetOperand(request.TargetOrImmediate) };
                break;
            case Aarch64InstructionEncodingFamily.ConditionalBranch19:
                if ((uint)request.ConditionCode > 15)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.InvalidOperand,
                        "Conditional branches require a condition code from 0 through 15.");
                    return false;
                }

                sourceName = "Bcc";
                mnemonic = "b.cond";
                operands = new A64Operand[]
                {
                    new A64EnumImmediateOperand(request.ConditionCode, A64EnumKind.ConditionCode),
                    new A64TargetOperand(request.TargetOrImmediate),
                };
                break;
            case Aarch64InstructionEncodingFamily.AdrPrelLo21:
            case Aarch64InstructionEncodingFamily.AdrPrelPgHi21:
                sourceName = request.Family == Aarch64InstructionEncodingFamily.AdrPrelLo21 ? "ADR" : "ADRP";
                mnemonic = request.Family == Aarch64InstructionEncodingFamily.AdrPrelLo21 ? "adr" : "adrp";
                operands = new A64Operand[]
                {
                    new A64RegisterOperand(A64Register.X(request.DestinationRegister)),
                    new A64TargetOperand(request.TargetOrImmediate),
                };
                break;
            case Aarch64InstructionEncodingFamily.Literal19 when request.DestinationWidth is 32 or 64:
                sourceName = request.DestinationWidth == 32 ? "LDRWl" : "LDRXl";
                mnemonic = "ldr";
                operands = new A64Operand[]
                {
                    new A64RegisterOperand(request.DestinationWidth == 32
                        ? A64Register.W(request.DestinationRegister)
                        : A64Register.X(request.DestinationRegister)),
                    new A64TargetOperand(request.TargetOrImmediate),
                };
                break;
            case Aarch64InstructionEncodingFamily.MoveWideImmediate:
                if (request.DestinationWidth is not (32 or 64)
                    || request.TargetOrImmediate > ushort.MaxValue
                    || !IsValidMoveWideShift(request.DestinationWidth, request.ImmediateShift))
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.InvalidOperand,
                        "Move-wide construction requires a 16-bit immediate and a valid halfword shift for its register width.");
                    return false;
                }

                sourceName = request.DestinationWidth == 32 ? MovzWSourceName : MovzXSourceName;
                mnemonic = "movz";
                operands = new A64Operand[]
                {
                    new A64RegisterOperand(request.DestinationWidth == 32
                        ? A64Register.W(request.DestinationRegister)
                        : A64Register.X(request.DestinationRegister)),
                    new A64ImmediateOperand((long)request.TargetOrImmediate),
                    new A64ImmediateOperand(request.ImmediateShift),
                };
                break;
            case Aarch64InstructionEncodingFamily.MoveRegister:
                if (request.DestinationWidth is not (32 or 64)
                    || request.SourceRegister is not { } sourceRegister
                    || sourceRegister > 30)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.InvalidRequest,
                        "Register moves require 32- or 64-bit general registers from x0/w0 through x30/w30.");
                    return false;
                }

                sourceName = request.DestinationWidth == 32 ? OrrWSourceName : OrrXSourceName;
                mnemonic = "orr";
                var moveSource = request.DestinationWidth == 32
                    ? A64Register.W(sourceRegister)
                    : A64Register.X(sourceRegister);
                var moveZero = request.DestinationWidth == 32
                    ? A64Register.Zr(32)
                    : A64Register.Zr(64);
                operands = new A64Operand[]
                {
                    new A64RegisterOperand(request.DestinationWidth == 32
                        ? A64Register.W(request.DestinationRegister)
                        : A64Register.X(request.DestinationRegister)),
                    new A64RegisterOperand(moveZero),
                    new A64ModifiedRegisterOperand(
                        moveSource,
                        0,
                        request.DestinationWidth == 32
                            ? LogicalShiftedRegister32Codec
                            : LogicalShiftedRegister64Codec),
                };
                break;
            case Aarch64InstructionEncodingFamily.CompareImmediate:
                if (request.DestinationWidth is not (32 or 64)
                    || !IsValidAddSubImmediate(request.TargetOrImmediate))
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.InvalidOperand,
                        "Compare-immediate construction requires a valid ADD/SUB immediate domain.");
                    return false;
                }

                sourceName = request.DestinationWidth == 32 ? "SUBSWri" : "SUBSXri";
                mnemonic = "subs";
                operands = new A64Operand[]
                {
                    new A64RegisterOperand(request.DestinationWidth == 32
                        ? A64Register.Zr(32)
                        : A64Register.Zr(64)),
                    new A64RegisterOperand(request.DestinationWidth == 32
                        ? A64Register.W(request.BaseRegister)
                        : A64Register.X(request.BaseRegister)),
                    new A64ImmediateOperand((long)request.TargetOrImmediate),
                };
                break;
            case Aarch64InstructionEncodingFamily.Return:
                var returnRegister = request.SourceRegister ?? 30;
                if (returnRegister > 30)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.InvalidRequest,
                        "Return construction requires a general register from x0 through x30.");
                    return false;
                }

                sourceName = "RET";
                mnemonic = "ret";
                operands = new A64Operand[] { new A64RegisterOperand(A64Register.X(returnRegister)) };
                break;
            case Aarch64InstructionEncodingFamily.AddImmediate:
                if (request.TargetOrImmediate > 0xFFF000
                    || (!request.ShiftedImmediate && request.TargetOrImmediate > 0xFFF)
                    || (request.ShiftedImmediate
                        && request.TargetOrImmediate > 0xFFF
                        && (request.TargetOrImmediate & 0xFFF) != 0))
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.InvalidOperand,
                        "ADD immediate must fit the unshifted or 12-bit shifted AArch64 immediate domain.");
                    return false;
                }

                sourceName = request.DestinationWidth == 32 ? "ADDWri" : "ADDXri";
                mnemonic = "add";
                var addRegister = request.DestinationWidth == 32
                    ? A64Register.W(request.DestinationRegister)
                    : A64Register.X(request.DestinationRegister);
                var addBase = request.DestinationWidth == 32
                    ? A64Register.W(request.BaseRegister)
                    : A64Register.X(request.BaseRegister);
                var encodedImmediate = request.ShiftedImmediate
                    ? (uint)((request.TargetOrImmediate & 0xFFF) | 0x1000)
                    : (uint)request.TargetOrImmediate;
                operands = new A64Operand[]
                {
                    new A64RegisterOperand(addRegister),
                    new A64RegisterOperand(addBase),
                    new A64ImmediateOperand((long)request.TargetOrImmediate, encodedImmediate),
                };
                break;
            case Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate:
                if (request.AccessWidth is not (8 or 16 or 32 or 64))
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.InvalidRequest,
                        "Unsigned load/store access width must be 8, 16, 32, or 64 bits.");
                    return false;
                }

                if (request.TargetOrImmediate > long.MaxValue)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.InvalidOperand,
                        "The load/store offset exceeds the signed operand domain.");
                    return false;
                }

                sourceName = GetUnsignedLoadStoreSourceName(request.AccessWidth, request.IsStore);
                mnemonic = request.IsStore ? "str" : "ldr";
                var register = request.AccessWidth == 64
                    ? A64Register.X(request.DestinationRegister)
                    : A64Register.W(request.DestinationRegister);
                operands = new A64Operand[]
                {
                    new A64RegisterOperand(register),
                    new A64MemoryOperand(A64Register.X(request.BaseRegister),
                        (long)request.TargetOrImmediate),
                };
                break;
            default:
                error = (Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily,
                    $"The project instruction builder does not own family '{request.Family}'.");
                return false;
        }

        instruction = new A64InstructionModel(
            A64InstructionId.Generated,
            mnemonic,
            operands,
            0,
            request.Address)
        {
            SourceName = sourceName,
        };
        return true;
    }

    private static bool TryValidateFamily(
        A64InstructionModel instruction,
        Aarch64InstructionEncodingFamily family,
        int expectedAccessWidth,
        int expectedRegisterWidth,
        out (Aarch64InstructionEncodeDiagnosticCode Code, string Message) error)
    {
        error = default;
        var targets = instruction.OperandSemantics
            .Where(operand => operand.Operand is A64TargetOperand)
            .ToArray();
        switch (family)
        {
            case Aarch64InstructionEncodingFamily.Branch26:
                return MatchTarget(instruction.SourceName == "B", targets, 26, false, null, out error);
            case Aarch64InstructionEncodingFamily.Call26:
                return MatchTarget(instruction.SourceName == "BL", targets, 26, false, null, out error);
            case Aarch64InstructionEncodingFamily.ConditionalBranch19:
                return MatchTarget(
                    instruction.Flags.HasFlag(global::AsmStone.Model.A64InstructionFlags.IsBranch),
                    targets,
                    19,
                    false,
                    ConditionalBranchDomains,
                    out error);
            case Aarch64InstructionEncodingFamily.TestBranch14:
                return MatchTarget(
                    instruction.SourceName is "TBZW" or "TBNZW" or "TBZX" or "TBNZX",
                    targets,
                    14,
                    false,
                    TestBranchDomains,
                    out error);
            case Aarch64InstructionEncodingFamily.AdrPrelLo21:
                return MatchTarget(instruction.SourceName == "ADR", targets, 21, false, null, out error);
            case Aarch64InstructionEncodingFamily.AdrPrelPgHi21:
                return MatchTarget(instruction.SourceName == "ADRP", targets, 21, true, null, out error);
            case Aarch64InstructionEncodingFamily.Literal19:
                return MatchTarget(
                    instruction.SourceName is "LDRWl" or "LDRSl" or "LDRXl" or "LDRDl",
                    targets,
                    19,
                    false,
                    LiteralDomains,
                    out error);
            case Aarch64InstructionEncodingFamily.MoveWideImmediate:
                if (!IsMoveWideSourceName(instruction.SourceName)
                    || !TryGetOutputRegisterWidth(instruction, out var moveWideWidth)
                    || !IsMoveWideWidthConsistent(instruction.SourceName, moveWideWidth)
                    || instruction.Operands.OfType<A64ImmediateOperand>().Count() != 2)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily,
                        "The source instruction is not a valid MOVZ/MOVN/MOVK immediate form.");
                    return false;
                }

                if (expectedRegisterWidth != 0 && moveWideWidth != expectedRegisterWidth)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.OperandWidthMismatch,
                        "The move-wide register width does not match the requested width.");
                    return false;
                }

                return true;
            case Aarch64InstructionEncodingFamily.MoveRegister:
                if (!IsCanonicalMoveRegister(instruction)
                    || !TryGetOutputRegisterWidth(instruction, out var moveWidth))
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily,
                        "The source instruction is not a canonical ORR register-move alias.");
                    return false;
                }

                if (expectedRegisterWidth != 0 && moveWidth != expectedRegisterWidth)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.OperandWidthMismatch,
                        "The register-move width does not match the requested width.");
                    return false;
                }

                return true;
            case Aarch64InstructionEncodingFamily.CompareImmediate:
                if (!IsCanonicalCompareImmediate(instruction, out var compareWidth)
                    || !instruction.Flags.HasFlag(global::AsmStone.Model.A64InstructionFlags.IsCompare)
                    || instruction.Operands.OfType<A64ImmediateOperand>().Count() != 1)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily,
                        "The source instruction is not a canonical CMP/SUBS-immediate compare form.");
                    return false;
                }

                if (expectedRegisterWidth != 0 && compareWidth != expectedRegisterWidth)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.OperandWidthMismatch,
                        "The compare register width does not match the requested width.");
                    return false;
                }

                return true;
            case Aarch64InstructionEncodingFamily.Return:
                if (instruction.SourceName != "RET"
                    || !instruction.Flags.HasFlag(global::AsmStone.Model.A64InstructionFlags.IsReturn)
                    || instruction.Operands.OfType<A64RegisterOperand>().Count() != 1
                    || instruction.Operands.OfType<A64RegisterOperand>().Single().Register.Width != 64)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily,
                        "The source instruction is not the canonical RET form.");
                    return false;
                }

                return true;
            case Aarch64InstructionEncodingFamily.AddImmediate:
                if (!string.Equals(instruction.Mnemonic, "add", StringComparison.OrdinalIgnoreCase)
                    || instruction.Operands.OfType<A64ImmediateOperand>().Count() != 1)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily,
                        "The source instruction is not an ADD-immediate form with one immediate operand.");
                    return false;
                }

                return true;
            case Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate:
                var memory = instruction.Operands.OfType<A64MemoryOperand>().SingleOrDefault();
                if (memory is null
                    || memory.Index is not null
                    || memory.Mode != global::AsmStone.Model.A64MemoryAddressingMode.Offset
                    || !string.Equals(instruction.Mnemonic, "ldr", StringComparison.OrdinalIgnoreCase)
                        && !string.Equals(instruction.Mnemonic, "str", StringComparison.OrdinalIgnoreCase))
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily,
                        "The source instruction is not an unsigned-immediate LDR/STR form.");
                    return false;
                }

                if (expectedAccessWidth != 0 && memory.AccessSize != 0
                    && checked(memory.AccessSize * 8) != expectedAccessWidth)
                {
                    error = (Aarch64InstructionEncodeDiagnosticCode.OperandWidthMismatch,
                        "The requested access width does not match the AsmStone-decoded load/store width.");
                    return false;
                }

                return true;
            default:
                error = (Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily,
                    $"The project encoder does not own instruction family '{family}'.");
                return false;
        }
    }

    private static bool MatchTarget(
        bool instructionMatches,
        IReadOnlyList<global::AsmStone.Model.A64InstructionOperand> targets,
        int width,
        bool pageRelative,
        IReadOnlyList<string>? semanticDomains,
        out (Aarch64InstructionEncodeDiagnosticCode Code, string Message) error)
    {
        if (instructionMatches
            && targets.Count == 1
            && targets[0].FieldWidth == width
            && targets[0].IsPageRelative == pageRelative
            && (semanticDomains is null || semanticDomains.Contains(targets[0].SemanticDomain, StringComparer.Ordinal)))
        {
            error = default;
            return true;
        }

        error = (Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily,
            "The AsmStone-decoded instruction does not match the requested operand family and width.");
        return false;
    }

    private static bool TryGetSourceImmediate(
        A64InstructionModel instruction,
        Aarch64InstructionEncodingFamily family,
        out long value)
    {
        value = default;
        if (family == Aarch64InstructionEncodingFamily.MoveWideImmediate)
        {
            var immediate = instruction.Operands.OfType<A64ImmediateOperand>().FirstOrDefault();
            if (immediate is null)
            {
                return false;
            }

            value = immediate.Value;
            return true;
        }

        if (family is Aarch64InstructionEncodingFamily.AddImmediate
            or Aarch64InstructionEncodingFamily.CompareImmediate)
        {
            var immediate = instruction.Operands.OfType<A64ImmediateOperand>().SingleOrDefault();
            if (immediate is null)
            {
                return false;
            }

            value = immediate.Value;
            return true;
        }

        if (family == Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate)
        {
            var memory = instruction.Operands.OfType<A64MemoryOperand>().SingleOrDefault();
            if (memory is null)
            {
                return false;
            }

            value = memory.Offset;
            return true;
        }

        return false;
    }

    private static void ReplaceTarget(A64Operand[] operands, ulong target)
    {
        var index = Array.FindIndex(operands, operand => operand is A64TargetOperand);
        if (index >= 0)
        {
            operands[index] = new A64TargetOperand(target);
        }
    }

    private static void ReplaceImmediate(
        A64Operand[] operands,
        long value,
        uint? encodedValue = null)
    {
        var index = Array.FindIndex(operands, operand => operand is A64ImmediateOperand);
        if (index >= 0 && operands[index] is A64ImmediateOperand immediate)
        {
            operands[index] = immediate with { Value = value, EncodedValue = encodedValue };
        }
    }

    private static void ReplaceMemoryOffset(A64Operand[] operands, long value)
    {
        var index = Array.FindIndex(operands, operand => operand is A64MemoryOperand);
        if (index >= 0 && operands[index] is A64MemoryOperand memory)
        {
            operands[index] = memory with { Offset = value };
        }
    }

    private static bool TryGetOutputRegisterWidth(
        A64InstructionModel instruction,
        out int width)
    {
        var output = instruction.OperandSemantics
            .FirstOrDefault(operand => operand.Direction is A64OperandDirection.Output or A64OperandDirection.InputOutput)
            ?.Operand as A64RegisterOperand;
        width = output?.Register.Width ?? 0;
        return width is 32 or 64;
    }

    private static bool IsMoveWideSourceName(string? sourceName) => sourceName is
        MovzWSourceName or MovnWSourceName or MovkWSourceName
        or MovzXSourceName or MovnXSourceName or MovkXSourceName;

    private static bool IsMoveRegisterSourceName(string? sourceName) => sourceName is OrrWSourceName or OrrXSourceName;

    private static bool IsMoveWideWidthConsistent(string? sourceName, int width) => width switch
    {
        32 => sourceName is MovzWSourceName or MovnWSourceName or MovkWSourceName,
        64 => sourceName is MovzXSourceName or MovnXSourceName or MovkXSourceName,
        _ => false,
    };

    private static bool IsCanonicalCompareImmediate(A64InstructionModel instruction, out int width)
    {
        width = 0;
        if (instruction.SourceName is not ("SUBSWri" or "SUBSXri")
            || instruction.Operands.Count != 3
            || instruction.Operands[0] is not A64RegisterOperand destination
            || instruction.Operands[1] is not A64RegisterOperand source
            || instruction.Operands[2] is not A64ImmediateOperand)
        {
            return false;
        }

        width = instruction.SourceName == "SUBSWri" ? 32 : 64;
        return destination.Register.Class == global::AsmStone.Model.A64RegisterClass.General
            && destination.Register.Role == global::AsmStone.Model.A64RegisterRole.Zero
            && destination.Register.Width == width
            && source.Register.Class == global::AsmStone.Model.A64RegisterClass.General
            && source.Register.Width == width
            && source.Register.Role is global::AsmStone.Model.A64RegisterRole.None or global::AsmStone.Model.A64RegisterRole.StackPointer;
    }

    private static bool IsCanonicalMoveRegister(A64InstructionModel instruction)
    {
        if (!IsMoveRegisterSourceName(instruction.SourceName)
            || instruction.Operands.Count != 3
            || instruction.Operands[0] is not A64RegisterOperand destination
            || instruction.Operands[1] is not A64RegisterOperand zeroSource
            || instruction.Operands[2] is not A64ModifiedRegisterOperand source)
        {
            return false;
        }

        var width = destination.Register.Width;
        var codec = width == 32 ? LogicalShiftedRegister32Codec : LogicalShiftedRegister64Codec;
        return width is 32 or 64
            && instruction.SourceName == (width == 32 ? OrrWSourceName : OrrXSourceName)
            && destination.Register.Class == global::AsmStone.Model.A64RegisterClass.General
            && (destination.Register.Role is global::AsmStone.Model.A64RegisterRole.None or global::AsmStone.Model.A64RegisterRole.Zero)
            && zeroSource.Register.Class == global::AsmStone.Model.A64RegisterClass.General
            && zeroSource.Register.Role == global::AsmStone.Model.A64RegisterRole.Zero
            && zeroSource.Register.Width == width
            && source.Register.Class == global::AsmStone.Model.A64RegisterClass.General
            && (source.Register.Role is global::AsmStone.Model.A64RegisterRole.None or global::AsmStone.Model.A64RegisterRole.Zero)
            && source.Register.Width == width
            && source.Modifier == 0
            && string.Equals(source.Codec, codec, StringComparison.Ordinal);
    }

    private static bool IsValidMoveWideShift(int width, int shift) => width switch
    {
        32 => shift is 0 or 16,
        64 => shift is 0 or 16 or 32 or 48,
        _ => false,
    };

    private static bool IsValidAddSubImmediate(ulong value) => value <= 0xFFF000
        && (value <= 0xFFF || (value & 0xFFF) == 0);

    private static bool MatchesExpectedValue(
        A64InstructionModel instruction,
        A64InstructionModel expectedInstruction,
        Aarch64InstructionEncodingFamily family,
        ulong expected)
    {
        if (family is Aarch64InstructionEncodingFamily.Branch26
            or Aarch64InstructionEncodingFamily.Call26
            or Aarch64InstructionEncodingFamily.ConditionalBranch19
            or Aarch64InstructionEncodingFamily.TestBranch14
            or Aarch64InstructionEncodingFamily.AdrPrelLo21
            or Aarch64InstructionEncodingFamily.AdrPrelPgHi21
            or Aarch64InstructionEncodingFamily.Literal19)
        {
            var targetMatches = family == Aarch64InstructionEncodingFamily.AdrPrelPgHi21
                ? (instruction.Operands.OfType<A64TargetOperand>().SingleOrDefault()?.Address & ~0xFFFUL)
                    == (expected & ~0xFFFUL)
                : instruction.Operands.OfType<A64TargetOperand>().SingleOrDefault()?.Address == expected;
            if (!targetMatches)
            {
                return false;
            }

            if (family == Aarch64InstructionEncodingFamily.ConditionalBranch19)
            {
                var actualCondition = instruction.Operands
                    .OfType<A64ImmediateOperand>()
                    .SingleOrDefault(operand => operand.EnumKind == A64EnumKind.ConditionCode)?.Value;
                var expectedCondition = expectedInstruction.Operands
                    .OfType<A64ImmediateOperand>()
                    .SingleOrDefault(operand => operand.EnumKind == A64EnumKind.ConditionCode)?.Value;
                return actualCondition == expectedCondition;
            }

            return true;
        }

        if (family == Aarch64InstructionEncodingFamily.MoveWideImmediate)
        {
            var actualImmediates = instruction.Operands.OfType<A64ImmediateOperand>().ToArray();
            var expectedImmediates = expectedInstruction.Operands.OfType<A64ImmediateOperand>().ToArray();
            return actualImmediates.Length == 2
                && expectedImmediates.Length == 2
                && actualImmediates[0].Value == checked((long)expected)
                && actualImmediates[1].Value == expectedImmediates[1].Value
                && RegisterOperandsMatch(instruction, expectedInstruction);
        }

        if (family is Aarch64InstructionEncodingFamily.CompareImmediate
            or Aarch64InstructionEncodingFamily.AddImmediate)
        {
            return instruction.Operands.OfType<A64ImmediateOperand>().FirstOrDefault()?.Value == checked((long)expected)
                && RegisterOperandsMatch(instruction, expectedInstruction);
        }

        if (family == Aarch64InstructionEncodingFamily.MoveRegister)
        {
            return RegisterOperandsMatch(instruction, expectedInstruction)
                && ModifiedRegisterOperandsMatch(instruction, expectedInstruction);
        }

        if (family == Aarch64InstructionEncodingFamily.Return)
        {
            return RegisterOperandsMatch(instruction, expectedInstruction);
        }

        return family == Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate
            && instruction.Operands.OfType<A64MemoryOperand>().SingleOrDefault()?.Offset == checked((long)expected);
    }

    private static bool RegisterOperandsMatch(
        A64InstructionModel actual,
        A64InstructionModel expected) => actual.Operands
            .OfType<A64RegisterOperand>()
            .Select(operand => operand.Register)
            .SequenceEqual(expected.Operands
                .OfType<A64RegisterOperand>()
                .Select(operand => operand.Register));

    private static bool ModifiedRegisterOperandsMatch(
        A64InstructionModel actual,
        A64InstructionModel expected) => actual.Operands
            .OfType<A64ModifiedRegisterOperand>()
            .SequenceEqual(expected.Operands.OfType<A64ModifiedRegisterOperand>());

    private static int GetExpectedAccessWidth(
        A64InstructionModel instruction,
        Aarch64InstructionEncodingFamily family) => family switch
        {
            Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate =>
                instruction.Operands.OfType<A64MemoryOperand>().SingleOrDefault()?.AccessSize * 8 ?? 0,
            _ => 0,
        };

    private static string GetUnsignedLoadStoreSourceName(int width, bool store) => (width, store) switch
    {
        (8, false) => "LDRBBui",
        (8, true) => "STRBBui",
        (16, false) => "LDRHHui",
        (16, true) => "STRHHui",
        (32, false) => "LDRWui",
        (32, true) => "STRWui",
        (64, false) => "LDRXui",
        (64, true) => "STRXui",
        _ => throw new ArgumentOutOfRangeException(nameof(width)),
    };

    private static Aarch64InstructionEncodeDiagnosticCode MapBackendDiagnostic(
        global::AsmStone.Model.A64DiagnosticCode code,
        Aarch64InstructionEncodingFamily family) => code switch
        {
            global::AsmStone.Model.A64DiagnosticCode.MisalignedTarget =>
                Aarch64InstructionEncodeDiagnosticCode.TargetMisaligned,
            global::AsmStone.Model.A64DiagnosticCode.OutOfRange when IsPcRelative(family) =>
                Aarch64InstructionEncodeDiagnosticCode.TargetOutOfRange,
            global::AsmStone.Model.A64DiagnosticCode.OutOfRange =>
                Aarch64InstructionEncodeDiagnosticCode.InvalidOperand,
            global::AsmStone.Model.A64DiagnosticCode.InvalidOperand =>
                Aarch64InstructionEncodeDiagnosticCode.InvalidOperand,
            _ => Aarch64InstructionEncodeDiagnosticCode.BackendEncodeFailed,
        };

    private static bool IsPcRelative(Aarch64InstructionEncodingFamily family) => family is
        Aarch64InstructionEncodingFamily.Branch26
        or Aarch64InstructionEncodingFamily.Call26
        or Aarch64InstructionEncodingFamily.ConditionalBranch19
        or Aarch64InstructionEncodingFamily.TestBranch14
        or Aarch64InstructionEncodingFamily.AdrPrelLo21
        or Aarch64InstructionEncodingFamily.AdrPrelPgHi21
        or Aarch64InstructionEncodingFamily.Literal19;

    private static Aarch64InstructionEncodeResult Failure(
        Aarch64InstructionEncodeDiagnosticCode code,
        string message) => Aarch64InstructionEncodeResult.Failure(code, message);

    private static A64Operand MapGeneralRegisters(
        A64Operand operand,
        IReadOnlyDictionary<byte, byte> mapping) => operand switch
        {
            global::AsmStone.Model.RegisterOperand register =>
                register with { Register = MapGeneralRegister(register.Register, mapping) },
            global::AsmStone.Model.ModifiedRegisterOperand modified =>
                modified with { Register = MapGeneralRegister(modified.Register, mapping) },
            global::AsmStone.Model.RegisterPairOperand pair => pair with
            {
                First = MapGeneralRegister(pair.First, mapping),
                Second = MapGeneralRegister(pair.Second, mapping),
            },
            global::AsmStone.Model.VectorRegisterListOperand list => list with
            {
                Registers = list.Registers.Select(register => MapGeneralRegister(register, mapping)).ToArray(),
            },
            global::AsmStone.Model.RegisterGroupOperand group => group with
            {
                Registers = group.Registers.Select(register => MapGeneralRegister(register, mapping)).ToArray(),
            },
            A64MemoryOperand memory => memory with
            {
                Base = MapGeneralRegister(memory.Base, mapping),
                Index = memory.Index is { } index ? MapGeneralRegister(index, mapping) : null,
            },
            _ => operand,
        };

    private static A64Register MapGeneralRegister(
        A64Register register,
        IReadOnlyDictionary<byte, byte> mapping)
    {
        if (register.Class != global::AsmStone.Model.A64RegisterClass.General
            || register.Role != global::AsmStone.Model.A64RegisterRole.None
            || !mapping.TryGetValue(register.Index, out var mappedIndex))
        {
            return register;
        }

        return register with { Index = mappedIndex };
    }
}
