using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Generators;
using PermissionScanner.Core.Models;
using PermissionScanner.Core.Services;

namespace PermissionScanner.Cli.Commands;

/// <summary>
/// Command to validate permissions by comparing constants, migrations, and database.
/// </summary>
public class ValidateDatabaseCommand
{
    public static async Task<int> ExecuteAsync(
        string solutionPath,
        string platformServicesPath,
        string? migrationServicePath,
        string? connectionString,
        string? schemaName,
        bool validateMigrations,
        bool findOrphaned,
        bool fixSuggestions)
    {
        try
        {
            Console.WriteLine("📊 Permission Database Validation");
            Console.WriteLine("==================================");
            Console.WriteLine();

            // Step 1: Get connection string from parameter or environment variable
            var connString = connectionString ?? Environment.GetEnvironmentVariable("DB_CONNECTION_STRING");
            if (string.IsNullOrWhiteSpace(connString))
            {
                Console.WriteLine("❌ Error: Connection string is required. Provide --connection-string or set DB_CONNECTION_STRING environment variable.");
                Console.WriteLine();
                Console.WriteLine("Example connection string:");
                Console.WriteLine("  Host=localhost;Port=5432;Database=kronos;Username=app_user;Password=***;SearchPath=app_schema");
                return 1;
            }

            // Step 2: Extract schema name from connection string if not provided
            var schema = schemaName ?? DatabasePermissionReader.ExtractSchemaFromConnectionString(connString);
            Console.WriteLine($"📋 Using schema: {schema}");
            Console.WriteLine();

            // Step 3: Test database connection
            Console.WriteLine("🔌 Testing database connection...");
            var dbReader = new DatabasePermissionReader();
            if (!await dbReader.TestConnectionAsync(connString))
            {
                Console.WriteLine("❌ Error: Failed to connect to database. Please check your connection string.");
                return 1;
            }
            Console.WriteLine("✅ Database connection successful");
            Console.WriteLine();

            // Step 4: Read permissions from database
            Console.WriteLine($"📊 Reading permissions from database (schema: {schema})...");
            var databasePermissions = await dbReader.ReadPermissionsAsync(connString, schema);
            Console.WriteLine($"   Found {databasePermissions.Count} permissions in database");
            Console.WriteLine();

            // Step 5: Read permissions from constants files
            Console.WriteLine("📄 Reading permissions from Constants files...");
            var endpointAnalyzer = new EndpointAnalyzer();
            var endpoints = await endpointAnalyzer.ScanSolutionAsync(solutionPath);
            
            var constantAnalyzer = new ConstantReferenceAnalyzer();
            var (codeReferencedPermissions, _) = await constantAnalyzer.ScanForConstantReferencesAsync(solutionPath);
            
            var allConstantsPermissions = PermissionConstantsGenerator.ConvertToPermissions(endpoints, codeReferencedPermissions);
            Console.WriteLine($"   Found {allConstantsPermissions.Count} permissions in Constants files");
            Console.WriteLine();

            // Step 6: Read permissions from migration files (if requested)
            List<MigrationPermission> migrationPermissions = new();
            if (validateMigrations && !string.IsNullOrEmpty(migrationServicePath))
            {
                Console.WriteLine($"📄 Parsing migration files in: {migrationServicePath}");
                var migrationParser = new MigrationFileParser();
                migrationPermissions = migrationParser.ParseMigrationFiles(migrationServicePath);
                var uniqueMigrationPermissions = migrationPermissions
                    .Select(p => p.PermissionName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count();
                Console.WriteLine($"   Found {migrationPermissions.Count} permission entries in migration files");
                Console.WriteLine($"   ({uniqueMigrationPermissions} unique permissions after deduplication)");
                Console.WriteLine();
            }

            // Step 7: Run validation
            Console.WriteLine("🔍 Running validation...");
            var validationService = new PermissionValidationService();
            var result = validationService.Validate(
                allConstantsPermissions,
                migrationPermissions,
                databasePermissions);

            // Step 8: Generate report
            GenerateValidationReport(result, findOrphaned, fixSuggestions);

            // Return exit code based on discrepancies
            return result.Summary.DiscrepanciesCount > 0 ? 1 : 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"❌ Error: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.Error.WriteLine($"   {ex.InnerException.Message}");
            }
            Console.Error.WriteLine(ex.StackTrace);
            return 1;
        }
    }

    private static void GenerateValidationReport(
        PermissionValidationResult result,
        bool findOrphaned,
        bool fixSuggestions)
    {
        Console.WriteLine();
        Console.WriteLine("📊 Validation Report");
        Console.WriteLine("====================");
        Console.WriteLine();

        // Summary
        Console.WriteLine("📋 Summary:");
        Console.WriteLine($"   Constants: {result.Summary.ConstantsCount} permissions");
        if (result.Summary.MigrationsCount > 0)
        {
            Console.WriteLine($"   Migrations: {result.Summary.MigrationsCount} unique permissions");
        }
        Console.WriteLine($"   Database: {result.Summary.DatabaseCount} permissions");
        Console.WriteLine($"   Matches: {result.Summary.MatchesCount} permissions (in all sources)");
        Console.WriteLine($"   Discrepancies: {result.Summary.DiscrepanciesCount} permissions");
        Console.WriteLine();

        // Constants vs Database
        Console.WriteLine("1️⃣  Constants vs Database:");
        if (result.MissingInDatabase.Count > 0)
        {
            Console.WriteLine($"   ⚠️  {result.MissingInDatabase.Count} permissions in constants NOT in database:");
            foreach (var perm in result.MissingInDatabase.Take(10))
            {
                Console.WriteLine($"      - {perm}");
            }
            if (result.MissingInDatabase.Count > 10)
            {
                Console.WriteLine($"      ... and {result.MissingInDatabase.Count - 10} more");
            }
        }
        else
        {
            Console.WriteLine("   ✅ All constants are seeded in database");
        }

        if (result.MissingInConstants.Count > 0)
        {
            Console.WriteLine($"   ⚠️  {result.MissingInConstants.Count} permissions in database NOT in constants:");
            foreach (var perm in result.MissingInConstants.Take(10))
            {
                Console.WriteLine($"      - {perm}");
            }
            if (result.MissingInConstants.Count > 10)
            {
                Console.WriteLine($"      ... and {result.MissingInConstants.Count - 10} more");
            }
        }
        else
        {
            Console.WriteLine("   ✅ All database permissions are in constants");
        }
        Console.WriteLine();

        // Migrations vs Database (if migrations were parsed)
        if (result.Summary.MigrationsCount > 0)
        {
            Console.WriteLine("2️⃣  Migrations vs Database:");
            if (result.MissingInDatabaseFromMigrations.Count > 0)
            {
                Console.WriteLine($"   ⚠️  {result.MissingInDatabaseFromMigrations.Count} permissions in migrations NOT in database:");
                Console.WriteLine("      (These migrations may not have been run yet)");
                foreach (var perm in result.MissingInDatabaseFromMigrations.Take(10))
                {
                    Console.WriteLine($"      - {perm}");
                }
                if (result.MissingInDatabaseFromMigrations.Count > 10)
                {
                    Console.WriteLine($"      ... and {result.MissingInDatabaseFromMigrations.Count - 10} more");
                }
            }
            else
            {
                Console.WriteLine("   ✅ All migration permissions are in database");
            }

            if (result.MissingInMigrations.Count > 0)
            {
                Console.WriteLine($"   ⚠️  {result.MissingInMigrations.Count} permissions in database NOT in migrations:");
                Console.WriteLine("      (These may have been manually added to the database)");
                foreach (var perm in result.MissingInMigrations.Take(10))
                {
                    Console.WriteLine($"      - {perm}");
                }
                if (result.MissingInMigrations.Count > 10)
                {
                    Console.WriteLine($"      ... and {result.MissingInMigrations.Count - 10} more");
                }
            }
            else
            {
                Console.WriteLine("   ✅ All database permissions are in migrations");
            }
            Console.WriteLine();
        }

        // Orphaned permissions
        if (findOrphaned)
        {
            Console.WriteLine("3️⃣  Orphaned Permissions:");
            if (result.OrphanedInDatabase.Count > 0)
            {
                Console.WriteLine($"   ⚠️  Found {result.OrphanedInDatabase.Count} orphaned permissions in database:");
                Console.WriteLine("      (Not in constants or migrations - may be legacy)");
                foreach (var perm in result.OrphanedInDatabase.Take(10))
                {
                    Console.WriteLine($"      - {perm}");
                }
                if (result.OrphanedInDatabase.Count > 10)
                {
                    Console.WriteLine($"      ... and {result.OrphanedInDatabase.Count - 10} more");
                }
            }
            else
            {
                Console.WriteLine("   ✅ No orphaned permissions found");
                Console.WriteLine("      (All database permissions are in constants or migrations)");
            }
            Console.WriteLine();
        }

        // Fix suggestions
        if (fixSuggestions)
        {
            GenerateFixSuggestions(result);
        }

        // Recommendations
        Console.WriteLine("💡 Recommendations:");
        if (result.MissingInDatabase.Count > 0)
        {
            Console.WriteLine($"   1. Run migrations to seed {result.MissingInDatabase.Count} missing permissions");
        }
        if (result.MissingInConstants.Count > 0)
        {
            Console.WriteLine($"   2. Review {result.MissingInConstants.Count} database permissions not in constants");
            Console.WriteLine("      - Add to constants if still needed");
            Console.WriteLine("      - Remove from database if legacy");
        }
        if (result.OrphanedInDatabase.Count > 0)
        {
            Console.WriteLine($"   3. Review {result.OrphanedInDatabase.Count} orphaned permissions");
            Console.WriteLine("      - Remove if legacy/unused");
            Console.WriteLine("      - Add to constants/migrations if still needed");
        }
        if (result.Summary.DiscrepanciesCount == 0)
        {
            Console.WriteLine("   ✅ All permissions are synchronized!");
        }
    }

    private static void GenerateFixSuggestions(PermissionValidationResult result)
    {
        Console.WriteLine();
        Console.WriteLine("🔧 Fix Suggestions:");
        Console.WriteLine("===================");
        Console.WriteLine();

        // SQL to insert missing permissions
        if (result.MissingInDatabase.Count > 0)
        {
            Console.WriteLine("📝 SQL to insert missing permissions (from constants):");
            Console.WriteLine("   (Note: These should be added via migrations, not direct SQL)");
            Console.WriteLine();
            foreach (var perm in result.MissingInDatabase.Take(5))
            {
                Console.WriteLine($"   -- {perm}");
                Console.WriteLine($"   INSERT INTO {{schema}}.permissions (permission_name, resource, action, is_system_permission, is_active)");
                Console.WriteLine($"   VALUES ('{perm}', '...', '...', true, true)");
                Console.WriteLine($"   ON CONFLICT (permission_name) DO NOTHING;");
                Console.WriteLine();
            }
            if (result.MissingInDatabase.Count > 5)
            {
                Console.WriteLine($"   ... and {result.MissingInDatabase.Count - 5} more");
            }
        }

        // SQL to remove orphaned permissions
        if (result.OrphanedInDatabase.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("📝 SQL to remove orphaned permissions:");
            Console.WriteLine("   (Review carefully before executing!)");
            Console.WriteLine();
            Console.WriteLine($"   DELETE FROM {{schema}}.permissions");
            Console.WriteLine($"   WHERE permission_name IN (");
            foreach (var perm in result.OrphanedInDatabase.Take(5))
            {
                Console.WriteLine($"     '{perm}',");
            }
            if (result.OrphanedInDatabase.Count > 5)
            {
                Console.WriteLine($"     ... and {result.OrphanedInDatabase.Count - 5} more");
            }
            Console.WriteLine($"   ) AND is_system_permission = true;");
        }
    }
}
