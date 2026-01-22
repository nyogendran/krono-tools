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
        bool fixSuggestions,
        bool autoGenerateConstants,
        bool findStringLiterals,
        bool autoFixLiterals,
        bool dryRun)
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

            // Step 9: Constants alignment (if requested)
            if (autoGenerateConstants || findStringLiterals || autoFixLiterals)
            {
                await HandleConstantsAlignmentAsync(
                    result,
                    databasePermissions,
                    allConstantsPermissions,
                    platformServicesPath,
                    solutionPath,
                    autoGenerateConstants,
                    findStringLiterals,
                    autoFixLiterals,
                    dryRun);
            }

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

    private static async Task HandleConstantsAlignmentAsync(
        PermissionValidationResult result,
        List<DatabasePermission> databasePermissions,
        List<PermissionDefinition> existingConstants,
        string platformServicesPath,
        string solutionPath,
        bool autoGenerateConstants,
        bool findStringLiterals,
        bool autoFixLiterals,
        bool dryRun)
    {
        Console.WriteLine();
        Console.WriteLine("🔧 Constants Alignment");
        Console.WriteLine("======================");
        Console.WriteLine();

        if (dryRun)
        {
            Console.WriteLine("⚠️  DRY-RUN MODE: No files will be modified");
            Console.WriteLine();
        }

        // Get missing permissions (in database but not in constants)
        var missingPermissionNames = result.MissingInConstants;
        if (missingPermissionNames.Count == 0)
        {
            Console.WriteLine("✅ All database permissions are already in constants");
            Console.WriteLine();
            return;
        }

        var missingDbPermissions = databasePermissions
            .Where(p => missingPermissionNames.Contains(p.PermissionName, StringComparer.OrdinalIgnoreCase))
            .ToList();

        Console.WriteLine($"Found {missingPermissionNames.Count} permissions in database not in constants:");
        foreach (var perm in missingPermissionNames.Take(10))
        {
            Console.WriteLine($"  - {perm}");
        }
        if (missingPermissionNames.Count > 10)
        {
            Console.WriteLine($"  ... and {missingPermissionNames.Count - 10} more");
        }
        Console.WriteLine();

        // Generate constants
        if (autoGenerateConstants)
        {
            await GenerateConstantsAsync(
                missingDbPermissions,
                existingConstants,
                platformServicesPath,
                dryRun);
        }

        // Find string literals
        if (findStringLiterals || autoFixLiterals)
        {
            await FindAndReplaceStringLiteralsAsync(
                solutionPath,
                missingPermissionNames,
                autoFixLiterals,
                dryRun);
        }
    }

    private static async Task GenerateConstantsAsync(
        List<DatabasePermission> missingPermissions,
        List<PermissionDefinition> existingConstants,
        string platformServicesPath,
        bool dryRun)
    {
        Console.WriteLine("📝 Generating Constants");
        Console.WriteLine("-----------------------");
        Console.WriteLine();

        var alignmentService = new ConstantsAlignmentService();
        var constants = alignmentService.GenerateConstantsForMissingPermissions(
            missingPermissions,
            existingConstants);

        if (constants.Count == 0)
        {
            Console.WriteLine("✅ No constants to generate");
            Console.WriteLine();
            return;
        }

        var constantsCode = alignmentService.GenerateConstantsCode(constants);

        Console.WriteLine($"Would generate {constants.Count} constants:");
        Console.WriteLine();
        Console.WriteLine("```csharp");
        Console.WriteLine(constantsCode);
        Console.WriteLine("```");
        Console.WriteLine();

        if (!dryRun)
        {
            var permissionsFilePath = Path.Combine(platformServicesPath, "Permissions.cs");
            if (!File.Exists(permissionsFilePath))
            {
                Console.WriteLine($"❌ Error: Permissions.cs not found at {permissionsFilePath}");
                return;
            }

            // Read existing file
            var existingContent = await File.ReadAllTextAsync(permissionsFilePath);

            // Extract existing constant names from the file to avoid duplicates
            var existingConstantNames = ExtractConstantNamesFromFile(existingContent);
            
            // Filter out constants that already exist
            var constantsToAdd = constants
                .Where(c => !existingConstantNames.Contains(c.ConstantName, StringComparer.OrdinalIgnoreCase))
                .ToList();

            if (constantsToAdd.Count == 0)
            {
                Console.WriteLine("✅ All constants already exist in Permissions.cs");
                Console.WriteLine();
                return;
            }

            if (constantsToAdd.Count < constants.Count)
            {
                var skippedCount = constants.Count - constantsToAdd.Count;
                Console.WriteLine($"⚠️  Skipping {skippedCount} constant(s) that already exist");
                Console.WriteLine();
            }

            // Generate code only for new constants
            var constantsCodeToAdd = alignmentService.GenerateConstantsCode(constantsToAdd);

            // Find insertion point (before the closing brace of the class)
            // Look for the last closing brace that closes the class (should be the last } in the file)
            var lastClosingBrace = existingContent.LastIndexOf('}');
            if (lastClosingBrace == -1)
            {
                Console.WriteLine("❌ Error: Could not find closing brace in Permissions.cs");
                return;
            }

            // Find the start of the line containing the closing brace
            // Work backwards from the closing brace to find the previous newline
            var lineStart = existingContent.LastIndexOf('\n', lastClosingBrace);
            if (lineStart == -1)
            {
                // No newline found before the closing brace, this shouldn't happen in a properly formatted file
                Console.WriteLine("❌ Error: Could not find line start before closing brace in Permissions.cs");
                return;
            }

            // Insert constants before the closing brace line, with proper formatting
            // The constantsCode already has proper indentation (8 spaces)
            var insertionPoint = lineStart + 1; // Insert after the newline (at the start of the closing brace line)
            var newContent = existingContent.Insert(insertionPoint, constantsCodeToAdd + Environment.NewLine);

            // Create backup
            var backupPath = permissionsFilePath + ".backup." + DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            await File.WriteAllTextAsync(backupPath, existingContent);

            // Write new content
            await File.WriteAllTextAsync(permissionsFilePath, newContent);

            Console.WriteLine($"✅ Generated {constantsToAdd.Count} constants in Permissions.cs");
            Console.WriteLine($"   Backup created: {Path.GetFileName(backupPath)}");
        }
        else
        {
            Console.WriteLine("⚠️  DRY-RUN: Constants not written to file");
        }

        Console.WriteLine();
    }

    private static async Task FindAndReplaceStringLiteralsAsync(
        string solutionPath,
        List<string> permissionNames,
        bool autoFix,
        bool dryRun)
    {
        Console.WriteLine("🔍 String Literal Analysis");
        Console.WriteLine("--------------------------");
        Console.WriteLine();

        var finder = new StringLiteralFinder();
        var references = await finder.FindStringLiteralsAsync(solutionPath, permissionNames);

        if (references.Count == 0)
        {
            Console.WriteLine("✅ No string literal references found");
            Console.WriteLine();
            return;
        }

        Console.WriteLine($"Found {references.Count} code reference(s) using string literals:");
        Console.WriteLine();

        // Group by file
        var byFile = references.GroupBy(r => r.FilePath);

        foreach (var fileGroup in byFile.Take(10))
        {
            var filePath = Path.GetRelativePath(solutionPath, fileGroup.Key);
            Console.WriteLine($"  {filePath}:");
            
            foreach (var refItem in fileGroup.Take(5))
            {
                Console.WriteLine($"    Line {refItem.LineNumber}: {refItem.Context}");
                Console.WriteLine($"      Current: {refItem.CurrentCode}");
                Console.WriteLine($"      Suggested: {refItem.SuggestedCode}");
            }
            
            if (fileGroup.Count() > 5)
            {
                Console.WriteLine($"    ... and {fileGroup.Count() - 5} more in this file");
            }
        }

        if (byFile.Count() > 10)
        {
            Console.WriteLine($"  ... and {byFile.Count() - 10} more files");
        }

        Console.WriteLine();

        if (autoFix)
        {
            Console.WriteLine("🔧 Applying Replacements");
            Console.WriteLine("-----------------------");
            Console.WriteLine();

            var replacementService = new LiteralReplacementService();
            var results = await replacementService.ApplyReplacementsAsync(references, dryRun);

            var successCount = results.Count(r => r.Success);
            var totalReplacements = results.Sum(r => r.ReplacementsCount);

            Console.WriteLine($"Processed {results.Count} file(s):");
            foreach (var result in results.Take(10))
            {
                var relativePath = Path.GetRelativePath(solutionPath, result.FilePath);
                if (result.Success)
                {
                    Console.WriteLine($"  ✅ {relativePath}: {result.Message}");
                }
                else
                {
                    Console.WriteLine($"  ❌ {relativePath}: {result.ErrorMessage}");
                }
            }

            if (results.Count > 10)
            {
                Console.WriteLine($"  ... and {results.Count - 10} more files");
            }

            Console.WriteLine();
            Console.WriteLine($"Total: {totalReplacements} replacement(s) in {successCount} file(s)");

            if (dryRun)
            {
                Console.WriteLine("⚠️  DRY-RUN: No files were modified");
            }
            else
            {
                Console.WriteLine("✅ Replacements applied (backups created)");
            }
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Extracts constant names from Permissions.cs file content.
    /// </summary>
    private static HashSet<string> ExtractConstantNamesFromFile(string fileContent)
    {
        var constantNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        // Pattern to match: public const string ConstantName = ...
        // This will match: public const string TenantBillingManage = "tenant-billing:manage";
        var pattern = @"public\s+const\s+string\s+(\w+)\s*=";
        var matches = System.Text.RegularExpressions.Regex.Matches(fileContent, pattern);
        
        foreach (System.Text.RegularExpressions.Match match in matches)
        {
            if (match.Groups.Count > 1)
            {
                var constantName = match.Groups[1].Value;
                constantNames.Add(constantName);
            }
        }
        
        return constantNames;
    }
}
