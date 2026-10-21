using System.Numerics;
using System.Security.Cryptography;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Aarch64Semantics;

/// <summary>
/// Application-established HostContext invocation facts available to selected-function
/// indirect-call analysis. The entry symbol is the exact validated dynamic symbol whose
/// address and extent establish the AAPCS64 HostContext root for X0.
/// </summary>
public sealed class Aarch64HostContextProofContext
{
    internal Aarch64HostContextProofContext(
        ElfFunctionSymbol entryFunction,
        string sourceSha256,
        uint abiVersion,
        uint minimumContextSize,
        uint threadLifetimeContextSize,
        uint structSizeOffset,
        uint capabilitiesOffset,
        uint userDataOffset,
        uint emitDiagnosticCallbackOffset,
        uint createImageThreadCallbackOffset,
        uint joinImageThreadCallbackOffset,
        ulong threadLifetimeCapabilityMask)
    {
        EntryFunction = entryFunction;
        SourceSha256 = sourceSha256;
        AbiVersion = abiVersion;
        MinimumContextSize = minimumContextSize;
        ThreadLifetimeContextSize = threadLifetimeContextSize;
        StructSizeOffset = structSizeOffset;
        CapabilitiesOffset = capabilitiesOffset;
        UserDataOffset = userDataOffset;
        EmitDiagnosticCallbackOffset = emitDiagnosticCallbackOffset;
        CreateImageThreadCallbackOffset = createImageThreadCallbackOffset;
        JoinImageThreadCallbackOffset = joinImageThreadCallbackOffset;
        ThreadLifetimeCapabilityMask = threadLifetimeCapabilityMask;
    }

    public ElfFunctionSymbol EntryFunction { get; }

    public string SourceSha256 { get; }

    public uint AbiVersion { get; }

    public uint MinimumContextSize { get; }

    public uint ThreadLifetimeContextSize { get; }

    public uint StructSizeOffset { get; }

    public uint CapabilitiesOffset { get; }

    public uint UserDataOffset { get; }

    public uint EmitDiagnosticCallbackOffset { get; }

    public uint CreateImageThreadCallbackOffset { get; }

    public uint JoinImageThreadCallbackOffset { get; }

    public ulong ThreadLifetimeCapabilityMask { get; }

    public int ThreadLifetimeCapabilityBitIndex => ThreadLifetimeCapabilityMask == 0
        ? -1
        : BitOperations.TrailingZeroCount(ThreadLifetimeCapabilityMask);

    internal bool MatchesEntry(ElfFunctionSymbol function) => EntryFunction == function;

    internal bool MatchesSource(ElfFile file) => string.Equals(
        SourceSha256,
        Convert.ToHexString(SHA256.HashData(file.Bytes.Span)).ToLowerInvariant(),
        StringComparison.Ordinal);
}
