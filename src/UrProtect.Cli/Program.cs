using UrProtect.Cli;

var embeddedExitCode = CliApplication.TryRunEmbeddedPayload();
if (embeddedExitCode is int exitCode)
{
    return exitCode;
}

return CliApplication.Run(args, Console.Out, Console.Error);
