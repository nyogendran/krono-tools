using PermissionScanner.Core.Models;
using PermissionScanner.Core.Services;

namespace PermissionScanner.Cli.Commands;

/// <summary>
/// Command to generate FluentMigrator migration files for seeding permissions.
/// Compares generated Permissions.cs constants with existing migrations to find new permissions.
/// </summary>
public class MigrateCommand
{
    public static async Task<int> ExecuteAsync(
        string solutionPath,
        string platformServicesPath,
        string migrationServicePath,
        bool dryRun,
        bool generate,
        bool generateRoleAssignments)
    {
        try
        {
            Console.WriteLine("🔍 Permission Migration Generator");
            Console.WriteLine("=================================");
            Console.WriteLine();
            
            if (dryRun)
            {
                Console.WriteLine("⚠️  DRY-RUN MODE: No files will be generated");
                Console.WriteLine();
            }
            
            // Step 1: Find Permissions.cs file
            var permissionsFilePath = Path.Combine(platformServicesPath, "Permissions.cs");
            if (!File.Exists(permissionsFilePath))
            {
                Console.WriteLine($"❌ Error: Permissions.cs not found at {permissionsFilePath}");
                return 1;
            }
            
            Console.WriteLine($"📄 Reading permissions from: {permissionsFilePath}");
            
            // Step 2: Extract permissions from Permissions.cs
            var allPermissions = PermissionMigrationAnalyzer.ExtractPermissionsFromConstantsFile(permissionsFilePath);
            Console.WriteLine($"   Found {allPermissions.Count} permissions in constants file");
            
            // Step 3: Extract already-seeded permissions from migrations
            Console.WriteLine();
            Console.WriteLine($"📄 Scanning existing migrations in: {migrationServicePath}");
            var seededPermissions = PermissionMigrationAnalyzer.ExtractSeededPermissionsFromMigrations(migrationServicePath);
            Console.WriteLine($"   Found {seededPermissions.Count} already-seeded permissions");
            
            // Step 4: Find new permissions
            var newPermissions = PermissionMigrationAnalyzer.FindNewPermissions(allPermissions, seededPermissions);
            Console.WriteLine();
            Console.WriteLine($"✨ Found {newPermissions.Count} new permissions that need seeding");
            
            if (newPermissions.Count == 0)
            {
                Console.WriteLine();
                Console.WriteLine("✅ All permissions are already seeded. No migration needed.");
                return 0;
            }
            
            // Step 5: Group by resource
            var groupedPermissions = PermissionMigrationAnalyzer.GroupByResource(newPermissions);
            Console.WriteLine($"   Grouped into {groupedPermissions.Count} resource(s)");
            Console.WriteLine();
            
            // Display summary
            Console.WriteLine("📋 New Permissions Summary:");
            Console.WriteLine("==========================");
            foreach (var group in groupedPermissions.OrderBy(g => g.Key))
            {
                Console.WriteLine($"  {group.Key}: {group.Value.Count} permission(s)");
                foreach (var perm in group.Value)
                {
                    Console.WriteLine($"    - {perm.PermissionName} ({perm.Description})");
                }
            }
            Console.WriteLine();
            
            if (dryRun)
            {
                Console.WriteLine("💡 Run without --dry-run to generate migration files");
                return 0;
            }
            
            if (!generate)
            {
                Console.WriteLine("💡 Use --generate flag to create migration files");
                return 0;
            }
            
            // Step 6: Generate migration files
            Console.WriteLine("📝 Generating migration files...");
            Console.WriteLine();
            
            var migrationsDir = Path.Combine(migrationServicePath, "Migrations", "Stage2_IdentityAccess");
            if (!Directory.Exists(migrationsDir))
            {
                Console.WriteLine($"❌ Error: Migrations directory not found: {migrationsDir}");
                return 1;
            }
            
            // Get next migration timestamp
            var baseTimestamp = MigrationFileGenerator.GetNextMigrationTimestamp(migrationServicePath);
            var displayOrderStart = MigrationFileGenerator.CalculateDisplayOrderStart(migrationServicePath);
            
            var generatedFiles = new List<string>();
            var timestampOffset = 0;
            
            foreach (var group in groupedPermissions.OrderBy(g => g.Key))
            {
                var resourceName = group.Key;
                var permissions = group.Value;
                
                // Generate unique timestamp for each migration
                var migrationTimestamp = baseTimestamp + timestampOffset;
                timestampOffset++;
                
                // Generate migration file content
                var migrationContent = MigrationFileGenerator.GenerateMigrationFile(
                    resourceName,
                    permissions,
                    migrationTimestamp,
                    displayOrderStart);
                
                // Calculate next display order start
                displayOrderStart += permissions.Count;
                
                // Generate file name
                var className = GenerateClassName(resourceName);
                var fileName = $"{migrationTimestamp}_{className}.cs";
                var filePath = Path.Combine(migrationsDir, fileName);
                
                // Write file
                await File.WriteAllTextAsync(filePath, migrationContent);
                generatedFiles.Add(filePath);
                
                Console.WriteLine($"✅ Generated: {fileName}");
                Console.WriteLine($"   Resource: {resourceName}");
                Console.WriteLine($"   Permissions: {permissions.Count}");
                Console.WriteLine($"   Display Order: {displayOrderStart - permissions.Count} - {displayOrderStart - 1}");
                Console.WriteLine();
                
                // Generate role assignment file if requested
                if (generateRoleAssignments)
                {
                    // Determine which roles should get these permissions
                    var rolePermissions = RoleAssignmentAnalyzer.GroupPermissionsByRole(permissions);
                    
                    if (rolePermissions.Count > 0)
                    {
                        // Generate role assignment migration (timestamp + 1 to ensure it runs after permission seeding)
                        var roleAssignmentTimestamp = migrationTimestamp + 1;
                        timestampOffset++; // Account for the extra file
                        
                        var roleAssignmentContent = RoleAssignmentGenerator.GenerateRoleAssignmentMigrationFile(
                            resourceName,
                            permissions,
                            rolePermissions,
                            roleAssignmentTimestamp);
                        
                        var roleAssignmentClassName = GenerateRoleAssignmentClassName(resourceName);
                        var roleAssignmentFileName = $"{roleAssignmentTimestamp}_{roleAssignmentClassName}.cs";
                        var roleAssignmentFilePath = Path.Combine(migrationsDir, roleAssignmentFileName);
                        
                        await File.WriteAllTextAsync(roleAssignmentFilePath, roleAssignmentContent);
                        generatedFiles.Add(roleAssignmentFilePath);
                        
                        Console.WriteLine($"✅ Generated: {roleAssignmentFileName}");
                        Console.WriteLine($"   Resource: {resourceName}");
                        Console.WriteLine($"   Roles: {string.Join(", ", rolePermissions.Keys)}");
                        Console.WriteLine();
                    }
                }
            }
            
            Console.WriteLine("🎉 Migration generation complete!");
            Console.WriteLine();
            Console.WriteLine("📋 Generated Files:");
            foreach (var file in generatedFiles)
            {
                Console.WriteLine($"   - {Path.GetFileName(file)}");
            }
            Console.WriteLine();
            Console.WriteLine("⚠️  Next Steps:");
            Console.WriteLine("   1. Review the generated migration files");
            Console.WriteLine("   2. Update MigrationStageService.cs if needed");
            Console.WriteLine("   3. Run migrations: dotnet run --project MigrationService -- migrate");
            
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            return 1;
        }
    }

    /// <summary>
    /// Generates a class name from resource name (e.g., "products" → "SeedProductPermissions").
    /// </summary>
    private static string GenerateClassName(string resourceName)
    {
        // Convert "products:variants" → "ProductsVariants"
        var parts = resourceName.Split(':', '-');
        var className = string.Join("", parts.Select(CapitalizeFirst));
        return $"Seed{className}Permissions";
    }

    /// <summary>
    /// Capitalizes the first letter of a string.
    /// </summary>
    private static string CapitalizeFirst(string text)
    {
        if (string.IsNullOrEmpty(text))
            return text;
        
        if (text.Length == 1)
            return text.ToUpper();
        
        return char.ToUpper(text[0]) + text.Substring(1);
    }

    /// <summary>
    /// Generates a class name for role assignment migration (e.g., "products" → "AssignProductPermissionsToRoles").
    /// </summary>
    private static string GenerateRoleAssignmentClassName(string resourceName)
    {
        // Convert "products:variants" → "ProductsVariants"
        var parts = resourceName.Split(':', '-');
        var className = string.Join("", parts.Select(CapitalizeFirst));
        return $"Assign{className}PermissionsToRoles";
    }
}
