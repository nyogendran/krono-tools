using System.CommandLine;
using System.CommandLine.Invocation;
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
        var scopeOption = new Option<string>(
            aliases: new[] { "--scope" },
            description: "Scope for generation: 'shared' (PlatformServices only), 'all' (hybrid - shared + service-specific), or service name (e.g., 'ProductService')")
        {
            IsRequired = false
        };
        scopeOption.SetDefaultValue("all");
        
        generateCommand.AddOption(solutionOption);
        generateCommand.AddOption(platformServicesOption);
        generateCommand.AddOption(updateFilesOption);
        generateCommand.AddOption(scopeOption);
        generateCommand.SetHandler(GenerateCommand.ExecuteAsync, solutionOption, platformServicesOption, updateFilesOption, scopeOption);

        // Validate command
        var validateCommand = new Command("validate", "Validate that all endpoints have authorization policies");
        validateCommand.AddOption(solutionOption);
        validateCommand.SetHandler(ValidateCommand.ExecuteAsync, solutionOption);

        // Validate alignment command
        var validateAlignmentCommand = new Command("validate-alignment", "Validate alignment between existing and generated permissions/policies");
        var platformServicesOptionForValidation = new Option<string>(
            aliases: new[] { "--platform-services", "-p" },
            description: "Path to PlatformServices project directory")
        {
            IsRequired = true
        };
        validateAlignmentCommand.AddOption(solutionOption);
        validateAlignmentCommand.AddOption(platformServicesOptionForValidation);
        validateAlignmentCommand.SetHandler(ValidateAlignmentCommand.ExecuteAsync, solutionOption, platformServicesOptionForValidation);

        // Apply command
        var applyCommand = new Command("apply", "Apply generated permissions and policies to endpoints and Program.cs (fixes namespace mismatches)");
        var platformServicesOptionForApply = new Option<string>(
            aliases: new[] { "--platform-services", "-p" },
            description: "Path to PlatformServices project directory")
        {
            IsRequired = true
        };
        var dryRunOption = new Option<bool>(
            aliases: new[] { "--dry-run" },
            description: "Preview changes without applying them")
        {
            IsRequired = false
        };
        // Note: Default is false (apply changes). Use --dry-run to preview only.
        var applyEndpointsOption = new Option<bool>(
            aliases: new[] { "--apply-endpoints" },
            description: "Apply fixes to endpoint files")
        {
            IsRequired = false
        };
        var applyPoliciesOption = new Option<bool>(
            aliases: new[] { "--apply-policies" },
            description: "Apply fixes to Program.cs policy registrations")
        {
            IsRequired = false
        };
        var migrateApiConstantsOption = new Option<bool>(
            aliases: new[] { "--migrate-api-constants" },
            description: "Migrate ApiConstants.Require* references to KS.PlatformServices.Constants.AuthorizationPolicies.*")
        {
            IsRequired = false
        };
        var applyPoliciesToEndpointsOption = new Option<bool>(
            aliases: new[] { "--apply-policies-to-endpoints" },
            description: "Automatically apply authorization policies to endpoints missing them")
        {
            IsRequired = false
        };
        var excludePathsOption = new Option<string>(
            aliases: new[] { "--exclude-paths" },
            description: "Comma-separated list of path patterns to exclude from policy application (supports wildcards)")
        {
            IsRequired = false
        };
        var defaultPolicyOption = new Option<string>(
            aliases: new[] { "--default-policy" },
            description: "Default policy to use when no specific policy can be determined")
        {
            IsRequired = false
        };
        
        applyCommand.AddOption(solutionOption);
        applyCommand.AddOption(platformServicesOptionForApply);
        applyCommand.AddOption(dryRunOption);
        applyCommand.AddOption(applyEndpointsOption);
        applyCommand.AddOption(applyPoliciesOption);
        applyCommand.AddOption(migrateApiConstantsOption);
        applyCommand.AddOption(applyPoliciesToEndpointsOption);
        applyCommand.AddOption(excludePathsOption);
        applyCommand.AddOption(defaultPolicyOption);
        applyCommand.SetHandler(async (InvocationContext context) =>
        {
            var solution = context.ParseResult.GetValueForOption(solutionOption)!;
            var platformServices = context.ParseResult.GetValueForOption(platformServicesOptionForApply)!;
            var dryRun = context.ParseResult.GetValueForOption(dryRunOption);
            var applyEndpoints = context.ParseResult.GetValueForOption(applyEndpointsOption);
            var applyPolicies = context.ParseResult.GetValueForOption(applyPoliciesOption);
            var migrateApiConstants = context.ParseResult.GetValueForOption(migrateApiConstantsOption);
            var applyPoliciesToEndpoints = context.ParseResult.GetValueForOption(applyPoliciesToEndpointsOption);
            var excludePaths = context.ParseResult.GetValueForOption(excludePathsOption);
            var defaultPolicy = context.ParseResult.GetValueForOption(defaultPolicyOption);

            await ApplyCommand.ExecuteAsync(
                solution,
                platformServices,
                dryRun,
                applyEndpoints,
                applyPolicies,
                migrateApiConstants,
                applyPoliciesToEndpoints,
                excludePaths,
                defaultPolicy
            );
        });

        // Test Phase 1 command
        var testPhase1Command = new Command("test-phase1", "Test Phase 1 - Core Detection functionality");
        var platformServicesOptionForTest = new Option<string>(
            aliases: new[] { "--platform-services", "-p" },
            description: "Path to PlatformServices project directory")
        {
            IsRequired = true
        };
        testPhase1Command.AddOption(solutionOption);
        testPhase1Command.AddOption(platformServicesOptionForTest);
        testPhase1Command.SetHandler(TestPhase1Command.ExecuteAsync, solutionOption, platformServicesOptionForTest);

        rootCommand.AddCommand(scanCommand);
        rootCommand.AddCommand(generateCommand);
        rootCommand.AddCommand(validateCommand);
        rootCommand.AddCommand(validateAlignmentCommand);
        rootCommand.AddCommand(applyCommand);
        rootCommand.AddCommand(testPhase1Command);

        return await rootCommand.InvokeAsync(args);
    }
}
