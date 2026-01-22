using System.Text;
using System.Text.RegularExpressions;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Analyzes permissions from generated constants and existing migrations to identify new permissions that need seeding.
/// </summary>
public class PermissionMigrationAnalyzer
{
    /// <summary>
    /// Extracts permissions from a Permissions.cs file.
    /// </summary>
    public static List<PermissionDefinition> ExtractPermissionsFromConstantsFile(string filePath)
    {
        if (!File.Exists(filePath))
            return new List<PermissionDefinition>();

        var content = File.ReadAllText(filePath);
        return ExtractPermissionsFromConstantsContent(content);
    }

    /// <summary>
    /// Extracts permissions from Permissions.cs content.
    /// </summary>
    public static List<PermissionDefinition> ExtractPermissionsFromConstantsContent(string content)
    {
        var permissions = new List<PermissionDefinition>();
        
        var lines = content.Split('\n');
        string? currentDescription = null;
        string? currentDomain = null;
        var capturingComment = false;
        var descriptionBuilder = new StringBuilder();
        
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            
            // Detect region (domain)
            if (line.Contains("#region"))
            {
                var regionMatch = Regex.Match(line, @"#region\s+(.+?)\s+Permissions");
                if (regionMatch.Success)
                {
                    currentDomain = regionMatch.Groups[1].Value;
                }
                continue;
            }
            
            if (line.Contains("#endregion"))
            {
                currentDomain = null;
                continue;
            }
            
            // Capture XML comments (description)
            if (line.StartsWith("///"))
            {
                var commentText = line.Substring(3).Trim();
                
                if (commentText.StartsWith("<summary>"))
                {
                    capturingComment = true;
                    continue;
                }
                if (commentText.StartsWith("</summary>"))
                {
                    capturingComment = false;
                    currentDescription = descriptionBuilder.ToString().Trim();
                    descriptionBuilder.Clear();
                    continue;
                }
                
                if (capturingComment && !string.IsNullOrWhiteSpace(commentText))
                {
                    // Skip "Endpoints:" lines
                    if (!commentText.StartsWith("Endpoints:"))
                    {
                        if (descriptionBuilder.Length > 0)
                            descriptionBuilder.Append(" ");
                        descriptionBuilder.Append(commentText);
                    }
                }
                continue;
            }
            
            // Extract constant declaration
            if (line.StartsWith("public const string"))
            {
                var match = Regex.Match(
                    line,
                    @"public\s+const\s+string\s+(\w+)\s*=\s*""([^""]+)""");
                
                if (match.Success)
                {
                    var constantName = match.Groups[1].Value;
                    var permissionName = match.Groups[2].Value;
                    
                    // Parse resource and action from permission name
                    var (resource, action) = ParsePermissionName(permissionName);
                    
                    // Clean description by removing file header text
                    var cleanedDescription = CleanDescription(currentDescription);
                    
                    var permission = new PermissionDefinition
                    {
                        PermissionName = permissionName,
                        ConstantName = constantName,
                        Resource = resource,
                        Action = action,
                        Description = cleanedDescription ?? GenerateDefaultDescription(resource, action),
                        Domain = currentDomain ?? "Other"
                    };
                    
                    permissions.Add(permission);
                    
                    // Reset for next constant
                    currentDescription = null;
                    descriptionBuilder.Clear();
                }
            }
            else if (!string.IsNullOrWhiteSpace(line) && !capturingComment)
            {
                // Reset description if we hit non-comment, non-constant code
                currentDescription = null;
                descriptionBuilder.Clear();
            }
        }
        
        return permissions;
    }

    /// <summary>
    /// Extracts permissions that are already seeded in migration files.
    /// </summary>
    public static HashSet<string> ExtractSeededPermissionsFromMigrations(string migrationServicePath)
    {
        var seededPermissions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        var migrationsDir = Path.Combine(migrationServicePath, "Migrations", "Stage2_IdentityAccess");
        if (!Directory.Exists(migrationsDir))
            return seededPermissions;
        
        var migrationFiles = Directory.GetFiles(migrationsDir, "*.cs", SearchOption.TopDirectoryOnly)
            .Where(f => f.Contains("Seed") && f.Contains("Permission"))
            .ToList();
        
        foreach (var file in migrationFiles)
        {
            var content = File.ReadAllText(file);
            ExtractPermissionsFromMigrationContent(content, seededPermissions);
        }
        
        return seededPermissions;
    }

    /// <summary>
    /// Extracts permission names from migration SQL content.
    /// </summary>
    private static void ExtractPermissionsFromMigrationContent(string content, HashSet<string> permissions)
    {
        // Match permission_name values in INSERT statements
        // Pattern: 'permission-name', or "permission-name"
        var pattern = @"(?:permission_name|')(\s*,\s*)?'([^']+)'";
        var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
        
        foreach (Match match in matches)
        {
            if (match.Groups.Count >= 3)
            {
                var permissionName = match.Groups[2].Value.Trim();
                if (!string.IsNullOrEmpty(permissionName))
                {
                    permissions.Add(permissionName);
                }
            }
        }
        
        // Also check for permission_name IN ('...', '...') patterns in DELETE statements
        var deletePattern = @"permission_name\s+IN\s*\(([^)]+)\)";
        var deleteMatch = Regex.Match(content, deletePattern, RegexOptions.IgnoreCase);
        if (deleteMatch.Success)
        {
            var permissionList = deleteMatch.Groups[1].Value;
            var permissionMatches = Regex.Matches(permissionList, @"'([^']+)'");
            foreach (Match permMatch in permissionMatches)
            {
                if (permMatch.Groups.Count >= 2)
                {
                    var permissionName = permMatch.Groups[1].Value.Trim();
                    if (!string.IsNullOrEmpty(permissionName))
                    {
                        permissions.Add(permissionName);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Finds new permissions that need to be seeded (exist in constants but not in migrations).
    /// Filters out "unknown" permissions as they don't represent real resources.
    /// </summary>
    public static List<PermissionDefinition> FindNewPermissions(
        List<PermissionDefinition> allPermissions,
        HashSet<string> seededPermissions)
    {
        return allPermissions
            .Where(p => !seededPermissions.Contains(p.PermissionName))
            .Where(p => !p.Resource.Equals("unknown", StringComparison.OrdinalIgnoreCase)) // Filter out unknown permissions
            .OrderBy(p => p.Resource)
            .ThenBy(p => p.Action)
            .ToList();
    }

    /// <summary>
    /// Groups permissions by resource for migration file organization.
    /// </summary>
    public static Dictionary<string, List<PermissionDefinition>> GroupByResource(List<PermissionDefinition> permissions)
    {
        return permissions
            .GroupBy(p => p.Resource)
            .ToDictionary(g => g.Key, g => g.OrderBy(p => p.Action).ToList());
    }

    /// <summary>
    /// Parses resource and action from permission name (e.g., "products:create" → resource="products", action="create").
    /// </summary>
    private static (string Resource, string Action) ParsePermissionName(string permissionName)
    {
        var parts = permissionName.Split(':', StringSplitOptions.RemoveEmptyEntries);
        
        if (parts.Length == 0)
            return ("unknown", "unknown");
        
        if (parts.Length == 1)
            return (parts[0], "read"); // Default action
        
        // Last part is action, everything before is resource
        var action = parts[^1];
        var resource = string.Join(":", parts[..^1]);
        
        return (resource, action);
    }

    /// <summary>
    /// Generates a default description if none is provided.
    /// </summary>
    private static string GenerateDefaultDescription(string resource, string action)
    {
        var actionVerb = action switch
        {
            "read" => "View",
            "create" => "Create",
            "update" => "Update",
            "write" => "Create and update",
            "delete" => "Delete",
            "manage" => "Manage",
            "approve" => "Approve",
            "reject" => "Reject",
            "view" => "View",
            _ => CapitalizeFirst(action)
        };
        
        var resourceName = resource.Replace(":", " ").Replace("-", " ");
        return $"{actionVerb} {resourceName}";
    }

    private static string CapitalizeFirst(string text)
    {
        if (string.IsNullOrEmpty(text))
            return text;
        return char.ToUpper(text[0]) + text.Substring(1).ToLower();
    }

    /// <summary>
    /// Cleans description by removing file header text and boilerplate.
    /// </summary>
    private static string? CleanDescription(string? description)
    {
        if (string.IsNullOrWhiteSpace(description))
            return null;

        var cleaned = description;

        // Remove file header patterns
        cleaned = Regex.Replace(cleaned, 
            @"Permission constants for the Intelligent Krono Application\.?\s*", 
            "", RegexOptions.IgnoreCase);
        
        cleaned = Regex.Replace(cleaned, 
            @"Auto-generated by Permission Scanner Tool\s*-\s*DO NOT EDIT MANUALLY\.?\s*", 
            "", RegexOptions.IgnoreCase);
        
        cleaned = Regex.Replace(cleaned, 
            @"Last Generated:\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+UTC\.?\s*", 
            "", RegexOptions.IgnoreCase);
        
        cleaned = Regex.Replace(cleaned, 
            @"To regenerate:\s*[^.]*\.?\s*", 
            "", RegexOptions.IgnoreCase);

        // Remove "Endpoints:" lines (they're handled separately)
        cleaned = Regex.Replace(cleaned, 
            @"Endpoints:\s*[^.]*\.?\s*", 
            "", RegexOptions.IgnoreCase);

        // Clean up multiple spaces and trim
        cleaned = Regex.Replace(cleaned, @"\s+", " ");
        cleaned = cleaned.Trim();

        // If description is empty or only contains punctuation after cleaning, return null
        if (string.IsNullOrWhiteSpace(cleaned) || cleaned.All(c => char.IsPunctuation(c) || char.IsWhiteSpace(c)))
            return null;

        return cleaned;
    }
}
