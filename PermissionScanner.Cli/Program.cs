using System.CommandLine;
using PermissionScanner.Cli.Commands;

namespace PermissionScanner.Cli;

/// <summary>
/// Permission Scanner CLI Tool
/// Discovers API endpoints and generates permission constants.
/// </summary>
class Program
{
    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("Permission Scanner Tool - Discovers API endpoints and generates permission constants");

        // Shared options
        var solutionOption = new Option<string>(
            aliases: new[] { "--solution", "-s" },
            description: "Path to solution directory or .sln file")
        {
            IsRequired = true
        };

        // Scan command
        var scanCommand = new Command("scan", "Scan solution for API endpoints and suggest permissions");
        var outputOption = new Option<string>(
            aliases: new[] { "--output", "-o" },
            description: "Output file path for JSON report")
        {
            IsRequired = false
        };
        
        scanCommand.AddOption(solutionOption);
        scanCommand.AddOption(outputOption);
        scanCommand.SetHandler(ScanCommand.ExecuteAsync, solutionOption, outputOption);

        // Generate command
        var generateCommand = new Command("generate", "Generate permission and policy constants");
        var platformServicesOption = new Option<string>(
            aliases: new[] { "--platform-services", "-p" },
            description: "Path to PlatformServices project directory")
        {
            IsRequired = true
        };
        var updateFilesOption = new Option<bool>(
            aliases: new[] { "--update-files", "-u" },
            description: "Update Permissions.cs and AuthorizationPolicies.cs files")
        {
            IsRequired = false
        };
        
        generateCommand.AddOption(solutionOption);
        generateCommand.AddOption(platformServicesOption);
        generateCommand.AddOption(updateFilesOption);
        generateCommand.SetHandler(GenerateCommand.ExecuteAsync, solutionOption, platformServicesOption, updateFilesOption);

        // Validate command
        var validateCommand = new Command("validate", "Validate that all endpoints have authorization policies");
        validateCommand.AddOption(solutionOption);
        validateCommand.SetHandler(ValidateCommand.ExecuteAsync, solutionOption);

        rootCommand.AddCommand(scanCommand);
        rootCommand.AddCommand(generateCommand);
        rootCommand.AddCommand(validateCommand);

        return await rootCommand.InvokeAsync(args);
    }
}
