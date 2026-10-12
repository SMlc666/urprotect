using System.Text.Json;
using System.Text.Json.Serialization;

namespace AsmStone.Generator;

internal static class Program
{
    private static int Main(string[] args)
    {
        var isInventory = string.Equals(args.ElementAtOrDefault(0), "inventory", StringComparison.OrdinalIgnoreCase);
        var isLlvmInventory = string.Equals(args.ElementAtOrDefault(0), "llvm-inventory", StringComparison.OrdinalIgnoreCase);
        var isEmitCSharp = string.Equals(args.ElementAtOrDefault(0), "emit-csharp", StringComparison.OrdinalIgnoreCase);
        if ((isInventory || isLlvmInventory) && args.Length < 2 || isEmitCSharp && args.Length < 3 || !isInventory && !isLlvmInventory && !isEmitCSharp)
        {
            Console.Error.WriteLine(
                "Usage: AsmStone.Generator inventory <Instructions.json> [output.json]"
                + Environment.NewLine
                + "       AsmStone.Generator llvm-inventory <tablegen.json> [output.json]"
                + Environment.NewLine
                + "       AsmStone.Generator emit-csharp <tablegen.json> <output.cs> [source-commit]");
            return 1;
        }

        try
        {
            if (isEmitCSharp)
            {
                var outputPath = Path.GetFullPath(args[2]);
                var sourceCommit = args.ElementAtOrDefault(3)
                    ?? Environment.GetEnvironmentVariable("ASMSTONE_LLVM_COMMIT")
                    ?? "unknown";
                LlvmTablegenInventory.EmitCSharp(args[1], outputPath, sourceCommit);
                Console.WriteLine($"Wrote {outputPath}");
                return 0;
            }

            var isLlvm = isLlvmInventory;
            object inventory = isLlvm
                ? LlvmTablegenInventory.Read(args[1])
                : AarchmrsInventory.Read(args[1]);
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            };

            if (args.Length >= 3)
            {
                var outputPath = Path.GetFullPath(args[2]);
                Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
                File.WriteAllText(outputPath, JsonSerializer.Serialize(inventory, inventory.GetType(), options));
                Console.WriteLine($"Wrote {outputPath}");
            }
            else
            {
                Console.WriteLine(JsonSerializer.Serialize(inventory, inventory.GetType(), options));
            }

            if (inventory is InventoryDocument aarchmrs)
            {
                Console.Error.WriteLine(
                    $"AARCHMRS inventory: {aarchmrs.InstructionCount} instructions, "
                    + $"{aarchmrs.OperationCount} operations, {aarchmrs.GroupCount} groups.");
            }
            else if (inventory is LlvmInventoryDocument llvm)
            {
                Console.Error.WriteLine(
                    $"LLVM inventory: {llvm.RecordCount} AArch64 records, "
                    + $"{llvm.EncodableRecordCount} encodable, {llvm.PseudoRecordCount} pseudo.");
            }

            return 0;
        }
        catch (Exception exception) when (exception is IOException or JsonException or InvalidDataException)
        {
            Console.Error.WriteLine($"Inventory failed: {exception.Message}");
            return 2;
        }
    }
}

internal static class AarchmrsInventory
{
    public static InventoryDocument Read(string path)
    {
        using var input = File.OpenRead(path);
        using var document = JsonDocument.Parse(input);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("instructions", out var instructionSets))
        {
            throw new InvalidDataException("The input is not an AARCHMRS Instructions.json document.");
        }

        var instructions = new List<SourceInstruction>();
        var operationIds = new HashSet<string>(StringComparer.Ordinal);
        var instructionNames = new HashSet<string>(StringComparer.Ordinal);
        var groupCount = 0;
        var encodingNodeCount = 0;
        Visit(instructionSets, [], instructions, operationIds, instructionNames, ref groupCount, ref encodingNodeCount);

        if (instructions.Count == 0)
        {
            throw new InvalidDataException("The AARCHMRS document contains no instruction leaves.");
        }

        return new InventoryDocument(
            "AARCHMRS",
            ReadVersion(root),
            instructions.Count,
            operationIds.Count,
            groupCount,
            encodingNodeCount,
            instructions.OrderBy(item => item.Name, StringComparer.Ordinal).ToArray());
    }

    private static void Visit(
        JsonElement node,
        IReadOnlyList<string> scope,
        List<SourceInstruction> instructions,
        HashSet<string> operationIds,
        HashSet<string> instructionNames,
        ref int groupCount,
        ref int encodingNodeCount)
    {
        if (node.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in node.EnumerateArray())
            {
                Visit(child, scope, instructions, operationIds, instructionNames, ref groupCount, ref encodingNodeCount);
            }

            return;
        }

        if (node.ValueKind != JsonValueKind.Object
            || !node.TryGetProperty("_type", out var typeElement)
            || typeElement.ValueKind != JsonValueKind.String)
        {
            return;
        }

        var type = typeElement.GetString();
        if (type == "Instruction.Instruction")
        {
            var name = RequiredString(node, "name");
            if (!instructionNames.Add(name))
            {
                throw new InvalidDataException($"Duplicate instruction name '{name}'.");
            }

            var operationId = OptionalString(node, "operation_id");
            if (operationId is not null)
            {
                operationIds.Add(operationId);
            }

            var (encodingWidth, instructionEncodingNodes) = ReadEncodingSummary(node);
            encodingNodeCount += instructionEncodingNodes;
            instructions.Add(new SourceInstruction(
                name,
                operationId,
                string.Join('/', scope),
                ReadAssemblyTemplate(node),
                encodingWidth,
                instructionEncodingNodes));
            return;
        }

        var nextScope = scope;
        if (type == "Instruction.InstructionGroup")
        {
            groupCount++;
            var groupName = OptionalString(node, "name");
            if (!string.IsNullOrEmpty(groupName))
            {
                nextScope = [.. scope, groupName];
            }
        }
        else if (type == "Instruction.InstructionSet")
        {
            var setName = OptionalString(node, "name");
            if (!string.IsNullOrEmpty(setName))
            {
                nextScope = [.. scope, setName];
            }
        }

        if (node.TryGetProperty("children", out var children))
        {
            Visit(children, nextScope, instructions, operationIds, instructionNames, ref groupCount, ref encodingNodeCount);
        }
    }

    private static SourceVersion ReadVersion(JsonElement root)
    {
        if (root.TryGetProperty("_meta", out var meta)
            && meta.TryGetProperty("version", out var version))
        {
            return new SourceVersion(
                OptionalString(version, "architecture"),
                OptionalString(version, "build"),
                OptionalString(version, "ref"),
                OptionalString(version, "schema"),
                OptionalString(version, "timestamp"));
        }

        return new SourceVersion(null, null, null, null, null);
    }

    private static (int Width, int NodeCount) ReadEncodingSummary(JsonElement instruction)
    {
        if (!instruction.TryGetProperty("encoding", out var encoding)
            || encoding.ValueKind != JsonValueKind.Object)
        {
            return (0, 0);
        }

        var width = encoding.TryGetProperty("width", out var widthElement)
            && widthElement.TryGetInt32(out var parsedWidth)
            ? parsedWidth
            : 0;
        var nodeCount = encoding.TryGetProperty("values", out var values)
            && values.ValueKind == JsonValueKind.Array
            ? values.GetArrayLength()
            : 0;
        return (width, nodeCount);
    }

    private static string ReadAssemblyTemplate(JsonElement instruction)
    {
        if (!instruction.TryGetProperty("assembly", out var assembly)
            || !assembly.TryGetProperty("symbols", out var symbols)
            || symbols.ValueKind != JsonValueKind.Array)
        {
            return string.Empty;
        }

        var parts = new List<string>();
        foreach (var symbol in symbols.EnumerateArray())
        {
            if (symbol.ValueKind != JsonValueKind.Object
                || !symbol.TryGetProperty("_type", out var type)
                || type.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            switch (type.GetString())
            {
                case "Instruction.Symbols.Literal":
                    parts.Add(OptionalString(symbol, "value") ?? string.Empty);
                    break;
                case "Instruction.Symbols.RuleReference":
                    var rule = OptionalString(symbol, "rule_id") ?? string.Empty;
                    parts.Add(rule == "SPACE" ? " " : $"<{rule}>");
                    break;
            }
        }

        return string.Concat(parts);
    }

    private static string RequiredString(JsonElement objectElement, string propertyName)
    {
        var value = OptionalString(objectElement, propertyName);
        return value ?? throw new InvalidDataException($"Missing string property '{propertyName}'.");
    }

    private static string? OptionalString(JsonElement objectElement, string propertyName)
    {
        return objectElement.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }
}

internal sealed record InventoryDocument(
    string Source,
    SourceVersion Version,
    int InstructionCount,
    int OperationCount,
    int GroupCount,
    int EncodingNodeCount,
    IReadOnlyList<SourceInstruction> Instructions);

internal sealed record SourceVersion(
    string? Architecture,
    string? Build,
    string? Reference,
    string? Schema,
    string? Timestamp);

internal sealed record SourceInstruction(
    string Name,
    string? OperationId,
    string Scope,
    string AssemblyTemplate,
    int EncodingWidth,
    int EncodingNodeCount);
