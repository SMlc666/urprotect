namespace AsmStone.Model;

public enum A64ExecutionMode
{
    Unspecified,
    NonStreaming,
    Streaming,
}

public sealed class A64FeatureSet
{
    private static readonly A64FeatureSet all = new(true, A64ExecutionMode.Unspecified, new HashSet<string>(StringComparer.Ordinal));
    private static readonly A64FeatureSet baseFeatures = From(A64Feature.Base);

    private readonly HashSet<string> predicates;

    private A64FeatureSet(bool allowAll, A64ExecutionMode executionMode, HashSet<string> predicates)
    {
        AllowAll = allowAll;
        ExecutionMode = executionMode;
        this.predicates = predicates;
    }

    public static A64FeatureSet All => all;

    public static A64FeatureSet Base => baseFeatures;

    public bool AllowAll { get; }

    public A64ExecutionMode ExecutionMode { get; }

    public static A64FeatureSet From(A64Feature features)
    {
        return From(features, A64ExecutionMode.Unspecified);
    }

    public static A64FeatureSet From(A64Feature features, A64ExecutionMode executionMode)
    {
        if (features.HasFlag(A64Feature.Full))
        {
            return All;
        }

        var predicates = new HashSet<string>(StringComparer.Ordinal);
        AddFeature(predicates, features, A64Feature.Neon, "HasNEON");
        AddFeature(predicates, features, A64Feature.FloatingPoint, "HasFPARMv8", "HasFPARMv8_2", "HasFPARMv8_3", "HasFPRCVT");
        if (features.HasFlag(A64Feature.Crypto))
        {
            predicates.Add("HasNEON");
            predicates.Add("HasFPARMv8");
            AddFeature(predicates, features, A64Feature.Crypto, "HasAES", "HasSHA1", "HasSHA2", "HasSHA3", "HasSM3", "HasSM4");
        }
        AddFeature(predicates, features, A64Feature.Lse, "HasLSE");
        AddFeature(predicates, features, A64Feature.Rcpc, "HasRCPC", "HasRCPC_IMMO", "HasRCPC3", "HasLRCPC2", "HasLRCPC3");
        if (features.HasFlag(A64Feature.DotProduct))
        {
            predicates.Add("HasNEON");
            predicates.Add("HasFPARMv8");
            predicates.Add("HasDotProd");
        }
        AddFeature(predicates, features, A64Feature.Ras, "HasRAS", "HasRASv2");
        AddFeature(predicates, features, A64Feature.PointerAuthentication, "HasPAuth");
        AddFeature(predicates, features, A64Feature.BranchTargetIdentification, "HasBTI");
        AddFeature(predicates, features, A64Feature.Sme, "HasSME", "HasSME2", "HasSME2p1", "HasSME2p2", "HasSME2p3");
        AddFeature(predicates, features, A64Feature.Sve, "HasSVE");
        AddFeature(predicates, features, A64Feature.Sve2, "HasSVE", "HasSVE2");
        AddFeature(predicates, features, A64Feature.Mte, "HasMTE");
        AddFeature(predicates, features, A64Feature.Rme, "HasRME");
        AddFeature(predicates, features, A64Feature.Mops, "HasMOPS", "HasMOPS_GO");
        AddFeature(predicates, features, A64Feature.Crc, "HasCRC");
        if (features.HasFlag(A64Feature.FullFp16))
        {
            predicates.Add("HasNEON");
            predicates.Add("HasFPARMv8");
            predicates.Add("HasFullFP16");
        }

        if (features.HasFlag(A64Feature.Bf16))
        {
            predicates.Add("HasFPARMv8");
            predicates.Add("HasBF16");
        }

        if (features.HasFlag(A64Feature.I8mm))
        {
            predicates.Add("HasNEON");
            predicates.Add("HasMatMulInt8");
        }

        AddFeature(predicates, features, A64Feature.Fp8, "HasFP8");
        if (features.HasFlag(A64Feature.Lse2))
        {
            predicates.Add("HasLSE");
            predicates.Add("HasLSE2");
        }

        AddFeature(predicates, features, A64Feature.Sme2, "HasSME", "HasSME2");
        AddFeature(predicates, features, A64Feature.Sme2p1, "HasSME", "HasSME2", "HasSME2p1");
        AddFeature(predicates, features, A64Feature.Sme2p2, "HasSME", "HasSME2", "HasSME2p2");
        AddFeature(predicates, features, A64Feature.Sme2p3, "HasSME", "HasSME2", "HasSME2p3");
        AddFeature(predicates, features, A64Feature.Sve2p1, "HasSVE", "HasSVE2", "HasSVE2p1");
        AddFeature(predicates, features, A64Feature.Sve2p2, "HasSVE", "HasSVE2", "HasSVE2p2");
        AddFeature(predicates, features, A64Feature.Sve2p3, "HasSVE", "HasSVE2", "HasSVE2p3");
        AddFeature(predicates, features, A64Feature.Mte2, "HasMTE", "HasMTE2");
        return new A64FeatureSet(false, executionMode, predicates);
    }

    public static A64FeatureSet FromPredicates(IEnumerable<string> predicates)
    {
        return FromPredicates(predicates, A64ExecutionMode.Unspecified);
    }

    public static A64FeatureSet FromPredicates(
        IEnumerable<string> predicates,
        A64ExecutionMode executionMode)
    {
        ArgumentNullException.ThrowIfNull(predicates);
        return new A64FeatureSet(
            false,
            executionMode,
            predicates
                .Where(predicate => !string.IsNullOrWhiteSpace(predicate))
                .ToHashSet(StringComparer.Ordinal));
    }

    public bool SupportsAll(string predicateList)
    {
        if (AllowAll || string.IsNullOrWhiteSpace(predicateList))
        {
            return true;
        }

        return predicateList
            .Split('|', StringSplitOptions.RemoveEmptyEntries)
            .All(Supports);
    }

    internal bool SupportsAll(IReadOnlyList<string> predicateList)
    {
        if (AllowAll || predicateList.Count == 0)
        {
            return true;
        }

        for (var index = 0; index < predicateList.Count; index++)
        {
            if (!Supports(predicateList[index]))
            {
                return false;
            }
        }

        return true;
    }

    public bool Supports(string predicate)
    {
        if (AllowAll || string.IsNullOrWhiteSpace(predicate))
        {
            return true;
        }

        if (predicates.Contains(predicate))
        {
            return true;
        }

        if (TryGetModePredicate(predicate, "NonStreamingSafe", out var nonStreamingBase, out var nonStreamingCapability))
        {
            return ExecutionMode == A64ExecutionMode.NonStreaming
                && Supports(nonStreamingBase)
                && (nonStreamingCapability.Length == 0 || Supports($"Has{nonStreamingCapability}"));
        }

        if (TryGetModePredicate(predicate, "StreamingSafe", out var streamingBase, out var streamingCapability))
        {
            return ExecutionMode == A64ExecutionMode.Streaming
                && Supports(streamingBase)
                && (streamingCapability.Length == 0 || Supports($"Has{streamingCapability}"));
        }

        if (predicate.StartsWith("Has", StringComparison.Ordinal)
            && predicate.Contains("and", StringComparison.Ordinal))
        {
            var compound = predicate[3..];
            var separator = compound.IndexOf("and", StringComparison.Ordinal);
            if (separator > 0)
            {
                return Supports($"Has{compound[..separator]}")
                    && Supports($"Has{compound[(separator + 3)..]}");
            }
        }

        var alternatives = predicate.Split("_or_", StringSplitOptions.RemoveEmptyEntries);
        return alternatives.Length > 1 && alternatives.Any(SupportsAlternative);

        bool SupportsAlternative(string alternative)
        {
            var featureName = alternative.StartsWith("Has", StringComparison.Ordinal)
                ? alternative[3..]
                : alternative;
            if (featureName.StartsWith("Streaming", StringComparison.Ordinal))
            {
                return ExecutionMode == A64ExecutionMode.Streaming
                    && Supports($"Has{featureName["Streaming".Length..]}");
            }

            if (featureName.StartsWith("NonStreaming", StringComparison.Ordinal))
            {
                return ExecutionMode == A64ExecutionMode.NonStreaming
                    && Supports($"Has{featureName["NonStreaming".Length..]}");
            }

            return predicates.Contains(alternative)
                || predicates.Contains($"Has{alternative}");
        }
    }

    private static void AddFeature(
        HashSet<string> predicates,
        A64Feature features,
        A64Feature feature,
        params string[] names)
    {
        if (!features.HasFlag(feature))
        {
            return;
        }

        foreach (var name in names)
        {
            predicates.Add(name);
        }
    }

    private static bool TryGetModePredicate(
        string predicate,
        string modeSuffix,
        out string basePredicate,
        out string capability)
    {
        basePredicate = string.Empty;
        capability = string.Empty;
        if (!predicate.EndsWith(modeSuffix, StringComparison.Ordinal))
        {
            return false;
        }

        var suffixStart = predicate.Length - modeSuffix.Length;
        var marker = predicate.LastIndexOf("andIs", suffixStart, StringComparison.Ordinal);
        if (marker <= 0 || suffixStart < marker + "andIs".Length)
        {
            return false;
        }

        basePredicate = predicate[..marker];
        capability = predicate[(marker + "andIs".Length)..suffixStart];
        return true;
    }
}
