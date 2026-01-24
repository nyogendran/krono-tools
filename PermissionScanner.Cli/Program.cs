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

        var emitFrontendOption = new Option<string?>(
            aliases: new[] { "--emit-frontend" },
            description: "Path to kronos-app root. Emits src/constants/permissions.generated.ts (BACKEND_PERMISSIONS) for frontend alignment.")
        {
            IsRequired = false
        };
        
        generateCommand.AddOption(solutionOption);
        generateCommand.AddOption(platformServicesOption);
        generateCommand.AddOption(updateFilesOption);
        generateCommand.AddOption(scopeOption);
        generateCommand.AddOption(emitFrontendOption);
        generateCommand.SetHandler(GenerateCommand.ExecuteAsync, solutionOption, platformServicesOption, updateFilesOption, scopeOption, emitFrontendOption);

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
        
        var detectMissingPoliciesOption = new Option<bool>(
            aliases: new[] { "--detect-missing-policies" },
            description: "Detect missing authorization policy registrations in Program.cs files")
        {
            IsRequired = false
        };
        var autoRegisterPoliciesOption = new Option<bool>(
            aliases: new[] { "--auto-register-policies" },
            description: "Automatically generate and register missing authorization policies in Program.cs")
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
        applyCommand.AddOption(detectMissingPoliciesOption);
        applyCommand.AddOption(autoRegisterPoliciesOption);
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
            var detectMissingPolicies = context.ParseResult.GetValueForOption(detectMissingPoliciesOption);
            var autoRegisterPolicies = context.ParseResult.GetValueForOption(autoRegisterPoliciesOption);

            var exitCode = await ApplyCommand.ExecuteAsync(
                solution,
                platformServices,
                dryRun,
                applyEndpoints,
                applyPolicies,
                migrateApiConstants,
                applyPoliciesToEndpoints,
                excludePaths,
                defaultPolicy,
                detectMissingPolicies,
                autoRegisterPolicies);
            
            context.ExitCode = exitCode;
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

        // Migrate command
        var migrateCommand = new Command("migrate", "Generate FluentMigrator migration files for seeding permissions");
        var platformServicesOptionForMigrate = new Option<string>(
            aliases: new[] { "--platform-services", "-p" },
            description: "Path to PlatformServices project directory")
        {
            IsRequired = true
        };
        var migrationServiceOption = new Option<string>(
            aliases: new[] { "--migration-service", "-m" },
            description: "Path to MigrationService project directory")
        {
            IsRequired = true
        };
        var dryRunOptionForMigrate = new Option<bool>(
            aliases: new[] { "--dry-run" },
            description: "Preview migration files without generating them")
        {
            IsRequired = false
        };
        var generateOption = new Option<bool>(
            aliases: new[] { "--generate" },
            description: "Generate migration files (required to actually create files)")
        {
            IsRequired = false
        };
        var generateRoleAssignmentsOption = new Option<bool>(
            aliases: new[] { "--generate-role-assignments" },
            description: "Also generate role assignment migration files")
        {
            IsRequired = false
        };
        
        migrateCommand.AddOption(solutionOption);
        migrateCommand.AddOption(platformServicesOptionForMigrate);
        migrateCommand.AddOption(migrationServiceOption);
        migrateCommand.AddOption(dryRunOptionForMigrate);
        migrateCommand.AddOption(generateOption);
        migrateCommand.AddOption(generateRoleAssignmentsOption);
        migrateCommand.SetHandler(MigrateCommand.ExecuteAsync, solutionOption, platformServicesOptionForMigrate, migrationServiceOption, dryRunOptionForMigrate, generateOption, generateRoleAssignmentsOption);

        // Validate-database command
        var validateDatabaseCommand = new Command("validate-database", "Validate permissions by comparing constants, migrations, and database");
        var platformServicesOptionForValidateDb = new Option<string>(
            aliases: new[] { "--platform-services", "-p" },
            description: "Path to PlatformServices Constants directory")
        {
            IsRequired = true
        };
        var migrationServiceOptionForValidateDb = new Option<string>(
            aliases: new[] { "--migration-service", "-m" },
            description: "Path to MigrationService project directory (optional, for migration validation)")
        {
            IsRequired = false
        };
        var connectionStringOption = new Option<string>(
            aliases: new[] { "--connection-string", "-c" },
            description: "PostgreSQL connection string (or use DB_CONNECTION_STRING env var)")
        {
            IsRequired = false
        };
        var schemaOption = new Option<string>(
            aliases: new[] { "--schema", "--db-schema" },
            description: "Database schema name (default: extracted from connection string or 'app_schema')")
        {
            IsRequired = false
        };
        var validateMigrationsOption = new Option<bool>(
            aliases: new[] { "--validate-migrations" },
            description: "Also validate migration files against database")
        {
            IsRequired = false
        };
        var findOrphanedOption = new Option<bool>(
            aliases: new[] { "--find-orphaned" },
            description: "Find orphaned permissions in database (not in constants or migrations)")
        {
            IsRequired = false
        };
        var fixSuggestionsOption = new Option<bool>(
            aliases: new[] { "--fix-suggestions" },
            description: "Show SQL suggestions to fix discrepancies")
        {
            IsRequired = false
        };
        var autoGenerateConstantsOption = new Option<bool>(
            aliases: new[] { "--auto-generate-constants" },
            description: "Generate constants for permissions in database but not in constants")
        {
            IsRequired = false
        };
        var findStringLiteralsOption = new Option<bool>(
            aliases: new[] { "--find-string-literals" },
            description: "Find code references using string literals instead of constants")
        {
            IsRequired = false
        };
        var autoFixLiteralsOption = new Option<bool>(
            aliases: new[] { "--auto-fix-literals" },
            description: "Automatically replace string literals with constants (requires --find-string-literals)")
        {
            IsRequired = false
        };
        var dryRunOptionForValidateDb = new Option<bool>(
            aliases: new[] { "--dry-run" },
            description: "Preview changes without applying (for constants generation and literal replacement)")
        {
            IsRequired = false
        };
        
        validateDatabaseCommand.AddOption(solutionOption);
        validateDatabaseCommand.AddOption(platformServicesOptionForValidateDb);
        validateDatabaseCommand.AddOption(migrationServiceOptionForValidateDb);
        validateDatabaseCommand.AddOption(connectionStringOption);
        validateDatabaseCommand.AddOption(schemaOption);
        validateDatabaseCommand.AddOption(validateMigrationsOption);
        validateDatabaseCommand.AddOption(findOrphanedOption);
        validateDatabaseCommand.AddOption(fixSuggestionsOption);
        validateDatabaseCommand.AddOption(autoGenerateConstantsOption);
        validateDatabaseCommand.AddOption(findStringLiteralsOption);
        validateDatabaseCommand.AddOption(autoFixLiteralsOption);
        validateDatabaseCommand.AddOption(dryRunOptionForValidateDb);
        validateDatabaseCommand.SetHandler(async (InvocationContext context) =>
        {
            var solution = context.ParseResult.GetValueForOption(solutionOption)!;
            var platformServices = context.ParseResult.GetValueForOption(platformServicesOptionForValidateDb)!;
            var migrationService = context.ParseResult.GetValueForOption(migrationServiceOptionForValidateDb);
            var connectionString = context.ParseResult.GetValueForOption(connectionStringOption);
            var schema = context.ParseResult.GetValueForOption(schemaOption);
            var validateMigrations = context.ParseResult.GetValueForOption(validateMigrationsOption);
            var findOrphaned = context.ParseResult.GetValueForOption(findOrphanedOption);
            var fixSuggestions = context.ParseResult.GetValueForOption(fixSuggestionsOption);
            var autoGenerateConstants = context.ParseResult.GetValueForOption(autoGenerateConstantsOption);
            var findStringLiterals = context.ParseResult.GetValueForOption(findStringLiteralsOption);
            var autoFixLiterals = context.ParseResult.GetValueForOption(autoFixLiteralsOption);
            var dryRun = context.ParseResult.GetValueForOption(dryRunOptionForValidateDb);
            
            var exitCode = await ValidateDatabaseCommand.ExecuteAsync(
                solution, platformServices, migrationService, connectionString, schema,
                validateMigrations, findOrphaned, fixSuggestions,
                autoGenerateConstants, findStringLiterals, autoFixLiterals, dryRun);
            
            context.ExitCode = exitCode;
        });

        rootCommand.AddCommand(scanCommand);
        rootCommand.AddCommand(generateCommand);
        rootCommand.AddCommand(validateCommand);
        rootCommand.AddCommand(validateAlignmentCommand);
        rootCommand.AddCommand(applyCommand);
        rootCommand.AddCommand(testPhase1Command);
        rootCommand.AddCommand(migrateCommand);
        rootCommand.AddCommand(validateDatabaseCommand);

        return await rootCommand.InvokeAsync(args);
    }
}
