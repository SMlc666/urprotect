using UrProtect.Core.Pipeline;

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    PrintUsage();
    return 0;
}

if (!string.Equals(args[0], "validate", StringComparison.OrdinalIgnoreCase) || args.Length < 2)
{
    Console.Error.WriteLine("Usage: urprotect validate <input> [--copy <output>] [--no-analysis]");
    return 2;
}

var inputPath = args[1];
string? outputPath = null;
var analyze = true;
for (var index = 2; index < args.Length; index++)
{
    switch (args[index])
    {
        case "--copy" when index + 1 < args.Length:
            outputPath = args[++index];
            break;
        case "--no-analysis":
            analyze = false;
            break;
        default:
            Console.Error.WriteLine($"Unknown argument: {args[index]}");
            return 2;
    }
}

NoOpValidationResult result;
if (outputPath is null)
{
    try
    {
        result = new NoOpPipeline().Validate(File.ReadAllBytes(inputPath), analyzeInstructions: analyze);
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"Input error: {exception.Message}");
        return 1;
    }
}
else
{
    result = new NoOpPipeline().ValidateAndCopy(inputPath, outputPath, analyze);
}

foreach (var diagnostic in result.Diagnostics)
{
    var writer = diagnostic.IsError ? Console.Error : Console.Out;
    writer.WriteLine(diagnostic);
}

if (result.File is not null)
{
    Console.WriteLine(
        $"Validated ET_DYN AArch64 {result.File.Kind}: "
        + $"{result.File.ProgramHeaders.Count} program headers, "
        + $"{result.File.DynamicEntries.Count} dynamic entries, "
        + $"{result.File.RelaRelocations.Count} RELA relocations.");
}

if (result.IsSuccess && outputPath is not null)
{
    Console.WriteLine($"Byte-identical output written to {outputPath}.");
}

return result.IsSuccess ? 0 : 1;

static void PrintUsage()
{
    Console.WriteLine("urprotect - conservative AArch64 ELF validation foundation");
    Console.WriteLine();
    Console.WriteLine("Usage:");
    Console.WriteLine("  urprotect validate <input> [--copy <output>] [--no-analysis]");
}
