using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using AsmStone.Decode;
using AsmStone.Encode;
using AsmStone.Generated;
using AsmStone.Model;

var options = Options.Parse(args);
if (options.Diagnose)
{
    Diagnose(options);
    return;
}

var chunkCount = (options.Count + options.ChunkSize - 1) / options.ChunkSize;
using var oracle = StartOracle(options);
var oracleDigestsTask = Task.Run(() => ReadOracleDigests(oracle.StandardOutput.BaseStream, chunkCount));
var oracleDigests = oracleDigestsTask.GetAwaiter().GetResult();
oracle.WaitForExit();
if (oracle.ExitCode != 0)
{
    throw new InvalidOperationException($"LLVM oracle exited with status {oracle.ExitCode}.");
}

var stopwatch = Stopwatch.StartNew();
var expected = new List<ChunkDigest>(checked((int)chunkCount));
var processed = 0UL;
var totalSoftFailCount = 0UL;
while (processed < options.Count)
{
    var currentCount = (uint)Math.Min(options.ChunkSize, options.Count - processed);
    var chunkIndex = expected.Count;
    var oracleChunk = oracleDigests[chunkIndex];
    totalSoftFailCount += oracleChunk.SoftFailCount;
    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    var validCount = 0u;

    for (var offset = 0u; offset < currentCount; offset++)
    {
        if ((oracleChunk.SoftFailMask[offset / 8] & (1u << ((int)offset % 8))) != 0)
        {
            continue;
        }

        var encoding = checked((uint)(options.Start + processed + offset));
        var info = default(A64EncodingInfo);
        A64Instruction instruction = default!;
        var diagnostic = A64Diagnostic.None;
        var valid = A64InstructionCatalog.TryLookup(encoding, A64FeatureSet.All, out info);
        if (valid)
        {
            valid = A64Decoder.TryDecode(
                encoding,
                0,
                A64FeatureSet.All,
                out instruction,
                out diagnostic);
        }

        uint reencoded = 0;
        byte flags = 0;
        string? name = null;
        if (valid)
        {
            validCount++;
            name = info.Name;
            flags = SemanticFlags(info.Flags);
            if (!A64Encoder.TryEncode(instruction, A64FeatureSet.All, out reencoded, out var encodeDiagnostic)
                || reencoded != encoding)
            {
                throw new InvalidOperationException(
                    $"AsmStone re-encode failure at 0x{encoding:X8}: {encodeDiagnostic}");
            }

            reencoded = CanonicalReencoded(encoding, info);
        }
        else if (A64Decoder.TryDecode(
                     encoding,
                     0,
                     A64FeatureSet.All,
                     out _,
                     out _))
        {
            throw new InvalidOperationException(
                $"AsmStone decoder matched 0x{encoding:X8} without a generated catalog record ({diagnostic}).");
        }

        AppendRecord(hash, valid, flags, reencoded, name);
    }

    expected.Add(new ChunkDigest(
        options.Start + processed,
        currentCount,
        validCount,
        0,
        hash.GetHashAndReset(),
        Array.Empty<byte>()));
    processed += currentCount;

    if (options.Progress && (expected.Count == 1 || expected.Count % 10 == 0 || processed == options.Count))
    {
        Console.Error.WriteLine(
            $"[{Environment.GetEnvironmentVariable("CI_NODE_INDEX") ?? "1"}] "
            + $"{processed:N0}/{options.Count:N0} words ({stopwatch.Elapsed}).");
    }
}

if (oracleDigests.Count != expected.Count)
{
    throw new InvalidOperationException(
        $"LLVM oracle returned {oracleDigests.Count} chunks; expected {expected.Count}.");
}

for (var index = 0; index < expected.Count; index++)
{
    var actual = oracleDigests[index];
    var wanted = expected[index];
    if (actual.Start != wanted.Start
        || actual.Count != wanted.Count
        || actual.ValidCount != wanted.ValidCount
        || actual.SoftFailCount != CountBits(oracleDigests[index].SoftFailMask)
        || !CryptographicOperations.FixedTimeEquals(actual.Digest, wanted.Digest))
    {
        throw new InvalidOperationException(
            $"LLVM semantic mismatch in chunk 0x{wanted.Start:X8}.."
            + $"0x{wanted.Start + wanted.Count - 1:X8}: "
            + $"expected count={wanted.Count}, valid={wanted.ValidCount}, digest={Convert.ToHexString(wanted.Digest)}; "
            + $"LLVM count={actual.Count}, valid={actual.ValidCount}, digest={Convert.ToHexString(actual.Digest)}.");
    }
}

Console.WriteLine(
    $"AsmStone.Exhaustive: PASS start=0x{options.Start:X8} "
    + $"count={options.Count:N0} valid={expected.Aggregate(0UL, (sum, chunk) => sum + chunk.ValidCount)} "
    + $"softfail={totalSoftFailCount:N0} "
    + $"chunks={expected.Count} elapsed={stopwatch.Elapsed}");

static void Diagnose(Options options)
{
    using var oracle = StartOracle(options, true);
    ulong processed = 0;
    string? line;
    while ((line = oracle.StandardOutput.ReadLine()) is not null)
    {
        var parts = line.Split(' ', 4, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !uint.TryParse(parts[0], System.Globalization.NumberStyles.HexNumber, null, out var word))
        {
            throw new InvalidOperationException($"Malformed LLVM oracle dump line: {line}");
        }

        var status = parts[1][0];
        if (status == 'S')
        {
            continue;
        }

        var oursValid = A64InstructionCatalog.TryLookup(word, A64FeatureSet.All, out var oursInfo);
        var oursDiagnostic = A64Diagnostic.None;
        if (oursValid)
        {
            oursValid = A64Decoder.TryDecode(
                word,
                0,
                A64FeatureSet.All,
                out _,
                out oursDiagnostic);
        }
        var oracleValid = status == 'V';
        var oracleName = oracleValid && parts.Length == 4 ? parts[3] : string.Empty;
        if (oursValid != oracleValid
            || oracleValid && !string.Equals(oursInfo.Name, oracleName, StringComparison.Ordinal))
        {
            Console.WriteLine(
                $"Mismatch word=0x{word:X8} oracle={status} {oracleName} "
                + $"asmstone={(oursValid ? oursInfo.Name : oursDiagnostic.Code.ToString())}");
            return;
        }

        processed++;
    }

    oracle.WaitForExit();
    if (oracle.ExitCode != 0)
    {
        throw new InvalidOperationException($"LLVM oracle exited with status {oracle.ExitCode}.");
    }

    Console.WriteLine($"AsmStone.Exhaustive: no mismatch in {processed:N0} oracle records.");
}

static Process StartOracle(Options options, bool dump = false)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = options.Oracle,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = false,
        CreateNoWindow = true,
    };
    startInfo.ArgumentList.Add($"--start={options.Start}");
    startInfo.ArgumentList.Add($"--count={options.Count}");
    startInfo.ArgumentList.Add($"--chunk-size={options.ChunkSize}");
    if (dump)
    {
        startInfo.ArgumentList.Add("--dump");
    }

    var process = Process.Start(startInfo)
        ?? throw new InvalidOperationException($"Could not start LLVM oracle '{options.Oracle}'.");
    return process;
}

static ChunkDigest ReadChunkDigest(Stream stream)
{
    Span<byte> header = stackalloc byte[20];
    stream.ReadExactly(header);
    var digest = new byte[32];
    stream.ReadExactly(digest);
    var softFailMask = new byte[(BinaryPrimitives.ReadUInt32LittleEndian(header[8..]) + 7) / 8];
    stream.ReadExactly(softFailMask);
    return new ChunkDigest(
        BinaryPrimitives.ReadUInt64LittleEndian(header),
        BinaryPrimitives.ReadUInt32LittleEndian(header[8..]),
        BinaryPrimitives.ReadUInt32LittleEndian(header[12..]),
        BinaryPrimitives.ReadUInt32LittleEndian(header[16..]),
        digest,
        softFailMask);
}

static List<ChunkDigest> ReadOracleDigests(Stream stream, ulong chunkCount)
{
    var result = new List<ChunkDigest>(checked((int)chunkCount));
    for (var index = 0UL; index < chunkCount; index++)
    {
        result.Add(ReadChunkDigest(stream));
    }

    if (stream.ReadByte() != -1)
    {
        throw new InvalidOperationException("LLVM oracle returned trailing data.");
    }

    return result;
}

static uint CountBits(byte[] values)
{
    uint count = 0;
    foreach (var value in values)
    {
        count += (uint)System.Numerics.BitOperations.PopCount(value);
    }

    return count;
}

static void AppendRecord(
    IncrementalHash hash,
    bool valid,
    byte flags,
    uint reencoded,
    string? name)
{
    var nameBytes = valid ? Encoding.UTF8.GetBytes(name!) : Array.Empty<byte>();
    if (nameBytes.Length > ushort.MaxValue)
    {
        throw new InvalidOperationException("Instruction name is too long for the oracle record format.");
    }

    Span<byte> header = stackalloc byte[8];
    header[0] = valid ? (byte)1 : (byte)0;
    header[1] = flags;
    BinaryPrimitives.WriteUInt32LittleEndian(header[2..], reencoded);
    BinaryPrimitives.WriteUInt16LittleEndian(header[6..], (ushort)nameBytes.Length);
    hash.AppendData(header);
    if (nameBytes.Length != 0)
    {
        hash.AppendData(nameBytes);
    }
}

static uint CanonicalReencoded(uint encoding, A64EncodingInfo info)
{
    if (!CanonicalEncodingBits.Values.TryGetValue(info.Name, out var mappedBits))
    {
        mappedBits = ParseMappedEncodingBits(info.FieldEncoding);
        CanonicalEncodingBits.Values.Add(info.Name, mappedBits);
    }

    var preservedBits = info.Mask | mappedBits;
    return (encoding & preservedBits) | (info.Value & ~preservedBits);
}

static uint ParseMappedEncodingBits(string fieldEncoding)
{
    var result = 0u;
    foreach (var field in fieldEncoding.Split(';', StringSplitOptions.RemoveEmptyEntries))
    {
        var separator = field.IndexOf('=');
        if (separator < 0)
        {
            continue;
        }

        foreach (var mapping in field[(separator + 1)..].Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = mapping.Split(':');
            if (parts.Length == 2
                && int.TryParse(parts[0], out var encodingBit)
                && encodingBit is >= 0 and < 32)
            {
                result |= 1u << encodingBit;
            }
        }
    }

    return result;
}

static byte SemanticFlags(A64InstructionFlags flags)
{
    var result = 0;
    if (flags.HasFlag(A64InstructionFlags.IsCompare)) result |= 1 << 0;
    if (flags.HasFlag(A64InstructionFlags.IsBranch)) result |= 1 << 1;
    if (flags.HasFlag(A64InstructionFlags.IsCall)) result |= 1 << 2;
    if (flags.HasFlag(A64InstructionFlags.IsReturn)) result |= 1 << 3;
    if (flags.HasFlag(A64InstructionFlags.IsBarrier)) result |= 1 << 4;
    if (flags.HasFlag(A64InstructionFlags.IsTerminator)) result |= 1 << 5;
    return (byte)result;
}

readonly record struct ChunkDigest(
    ulong Start,
    uint Count,
    uint ValidCount,
    uint SoftFailCount,
    byte[] Digest,
    byte[] SoftFailMask);

sealed record Options(
    string Oracle,
    ulong Start,
    ulong Count,
    uint ChunkSize,
    bool Progress,
    bool Diagnose)
{
    public static Options Parse(string[] args)
    {
        string? oracle = Environment.GetEnvironmentVariable("ASMSTONE_LLVM_ORACLE");
        ulong? start = null;
        ulong? count = null;
        uint chunkSize = ExhaustiveConstants.DefaultChunkSize;
        var progress = true;

        foreach (var argument in args)
        {
            var separator = argument.IndexOf('=');
            var key = separator < 0 ? argument : argument[..separator];
            var value = separator < 0 ? string.Empty : argument[(separator + 1)..];
            switch (key)
            {
                case "--oracle":
                    oracle = value;
                    break;
                case "--start":
                    start = ParseUnsigned(value, key);
                    break;
                case "--count":
                    count = ParseUnsigned(value, key);
                    break;
                case "--chunk-size":
                    chunkSize = checked((uint)ParseUnsigned(value, key));
                    break;
                case "--no-progress":
                    progress = false;
                    break;
                case "--diagnose":
                    break;
                default:
                    throw new ArgumentException($"Unknown option '{argument}'.");
            }
        }

        var shardTotal = ParseEnvironmentUnsigned("CI_NODE_TOTAL", 1);
        var shardIndex = ParseEnvironmentUnsigned("CI_NODE_INDEX", 1);
        if (shardTotal == 0 || shardIndex == 0 || shardIndex > shardTotal)
        {
            throw new ArgumentException("CI_NODE_INDEX/CI_NODE_TOTAL must describe a 1-based shard.");
        }

        start ??= ExhaustiveConstants.InstructionSpace * (shardIndex - 1) / shardTotal;
        var end = ExhaustiveConstants.InstructionSpace * shardIndex / shardTotal;
        count ??= end - start.Value;
        if (start > ExhaustiveConstants.InstructionSpace
            || count > ExhaustiveConstants.InstructionSpace - start
            || count == 0
            || chunkSize == 0)
        {
            throw new ArgumentException("The exhaustive range or chunk size is invalid.");
        }

        return new Options(
            oracle ?? "asmstone-llvm-oracle",
            start.Value,
            count.Value,
            chunkSize,
            progress,
            args.Contains("--diagnose", StringComparer.Ordinal));
    }

    private static ulong ParseEnvironmentUnsigned(string name, ulong fallback)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(value) ? fallback : ParseUnsigned(value, name);
    }

    private static ulong ParseUnsigned(string value, string name)
    {
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return Convert.ToUInt64(value[2..], 16);
        }

        return ulong.TryParse(value, out var result)
            ? result
            : throw new ArgumentException($"Option {name} requires an unsigned integer.");
    }
}

static class ExhaustiveConstants
{
    public const ulong InstructionSpace = 1UL << 32;
    public const uint DefaultChunkSize = 1u << 20;
}

static class CanonicalEncodingBits
{
    public static readonly Dictionary<string, uint> Values = new(StringComparer.Ordinal);
}
