using System.Text.RegularExpressions;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Parses migration files to extract permission seeding information.
/// </summary>
public class MigrationFileParser
{
    /// <summary>
    /// Parses all migration files in Stage2_IdentityAccess directory to extract permissions.
    /// </summary>
    /// <param name="migrationServicePath">Path to MigrationService directory</param>
    /// <returns>List of permissions extracted from migration files</returns>
    public List<MigrationPermission> ParseMigrationFiles(string migrationServicePath)
    {
        var permissions = new List<MigrationPermission>();
        
        var migrationsDir = Path.Combine(migrationServicePath, "Migrations", "Stage2_IdentityAccess");
        if (!Directory.Exists(migrationsDir))
        {
            Console.WriteLine($"⚠️  Warning: Migration directory not found: {migrationsDir}");
            return permissions;
        }

        var migrationFiles = Directory.GetFiles(migrationsDir, "*.cs")
            .Where(f => Path.GetFileName(f).StartsWith("202") && 
                       Path.GetFileName(f).Contains("Seed") && 
                       Path.GetFileName(f).Contains("Permissions"))
            .OrderBy(f => f)
            .ToList();

        Console.WriteLine($"📄 Found {migrationFiles.Count} permission seeding migration files");

        foreach (var filePath in migrationFiles)
        {
            try
            {
                var filePermissions = ParseMigrationFile(filePath);
                if (filePermissions.Count > 0)
                {
                    permissions.AddRange(filePermissions);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Warning: Failed to parse migration file {Path.GetFileName(filePath)}: {ex.Message}");
            }
        }

        return permissions;
    }

    /// <summary>
    /// Parses a single migration file to extract permissions from INSERT statements.
    /// </summary>
    private List<MigrationPermission> ParseMigrationFile(string filePath)
    {
        var permissions = new List<MigrationPermission>();
        var content = File.ReadAllText(filePath);

        // Extract migration version from filename (e.g., "20260128020197_SeedProductsPermissions.cs" -> 20260128020197)
        var fileName = Path.GetFileNameWithoutExtension(filePath);
        var versionMatch = Regex.Match(fileName, @"^(\d{14})");
        var migrationVersion = versionMatch.Success ? long.Parse(versionMatch.Groups[1].Value) : 0;

        // Extract migration version from Migration attribute if available
        var migrationAttrMatch = Regex.Match(content, @"\[Migration\((\d+)\)\]");
        if (migrationAttrMatch.Success)
        {
            migrationVersion = long.Parse(migrationAttrMatch.Groups[1].Value);
        }

        // Find INSERT INTO permissions statements
        // The format is: INSERT INTO {schema}.permissions (...) VALUES (tuple1), (tuple2), ...
        // Each tuple is multi-line with: 'name', 'desc', 'resource', 'action', bool, bool, int, NOW(), NOW(), int
        // The SQL is inside Execute.Sql($@"...") so we need to extract the SQL content first
        
        // Find the SQL content inside Execute.Sql($@"...")
        // Pattern needs to handle verbatim strings with $@"..." format
        // The closing quote might be on a new line, so we need to be flexible
        var sqlContentPattern = new Regex(
            @"Execute\.Sql\(\$@""([\s\S]+?)""\s*\)",
            RegexOptions.IgnoreCase);

        var sqlContentMatch = sqlContentPattern.Match(content);
        if (!sqlContentMatch.Success)
        {
            return permissions; // No SQL found
        }

        var sqlContent = sqlContentMatch.Groups[1].Value;
        
        // Find the VALUES section within the SQL
        // Look for VALUES followed by content until ON CONFLICT or end of string
        var valuesSectionPattern = new Regex(
            @"VALUES\s+([\s\S]+?)(?:\s*ON\s+CONFLICT|$)",
            RegexOptions.IgnoreCase);

        var valuesSectionMatch = valuesSectionPattern.Match(sqlContent);
        if (valuesSectionMatch.Success)
        {
            var valuesSection = valuesSectionMatch.Groups[1].Value.Trim();
            
            // Remove SQL comments (-- comment)
            valuesSection = Regex.Replace(valuesSection, @"--[^\r\n]*", "", RegexOptions.Multiline);
            
            // Extract individual tuples by matching balanced parentheses
            // Each tuple starts with ( and ends with ), and may contain nested parentheses (NOW())
            var tuples = ExtractBalancedTuples(valuesSection);
            
            foreach (var tuple in tuples)
            {
                var permission = ParsePermissionTuple(tuple, filePath, migrationVersion);
                if (permission != null)
                {
                    permissions.Add(permission);
                }
            }
        }

        return permissions;
    }

    /// <summary>
    /// Extracts balanced tuples from VALUES section (handles nested parentheses).
    /// </summary>
    private List<string> ExtractBalancedTuples(string valuesSection)
    {
        var tuples = new List<string>();
        var depth = 0;
        var start = -1;
        
        for (int i = 0; i < valuesSection.Length; i++)
        {
            var ch = valuesSection[i];
            
            if (ch == '(')
            {
                if (depth == 0)
                {
                    start = i;
                }
                depth++;
            }
            else if (ch == ')')
            {
                depth--;
                if (depth == 0 && start >= 0)
                {
                    // Found a complete tuple
                    var tuple = valuesSection.Substring(start + 1, i - start - 1).Trim();
                    if (!string.IsNullOrWhiteSpace(tuple))
                    {
                        tuples.Add(tuple);
                    }
                    start = -1;
                }
            }
        }
        
        return tuples;
    }

    /// <summary>
    /// Parses a single permission tuple from VALUES clause.
    /// Format: 'permission_name', 'description', 'resource', 'action', true/false, true/false, number, NOW(), NOW(), 1
    /// </summary>
    private MigrationPermission? ParsePermissionTuple(string tuple, string filePath, long migrationVersion)
    {
        try
        {
            // Extract values using regex to handle SQL string escaping
            // Pattern: 'value' or 'value with ''escaped'' quotes'
            var valuePattern = new Regex(@"'((?:[^']|'')*)'", RegexOptions.None);
            var matches = valuePattern.Matches(tuple);

            if (matches.Count < 4)
                return null;

            // Values order: permission_name, description, resource, action, is_system_permission, is_active, display_order, created_at, updated_at, version
            var permissionName = matches[0].Groups[1].Value.Replace("''", "'");
            var description = matches.Count > 1 ? matches[1].Groups[1].Value.Replace("''", "'") : null;
            var resource = matches.Count > 2 ? matches[2].Groups[1].Value.Replace("''", "'") : string.Empty;
            var action = matches.Count > 3 ? matches[3].Groups[1].Value.Replace("''", "'") : string.Empty;

            // Skip if permission name is empty
            if (string.IsNullOrWhiteSpace(permissionName))
                return null;

            return new MigrationPermission
            {
                PermissionName = permissionName,
                Description = string.IsNullOrWhiteSpace(description) ? null : description,
                Resource = resource,
                Action = action,
                MigrationFile = Path.GetFileName(filePath),
                MigrationVersion = migrationVersion
            };
        }
        catch
        {
            // If parsing fails, return null (skip this permission)
            return null;
        }
    }
}
