using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Service for generating constants for missing permissions and aligning them with database.
/// </summary>
public class ConstantsAlignmentService
{
    /// <summary>
    /// Generates constant definitions for permissions that exist in database but not in constants.
    /// </summary>
    public List<ConstantDefinition> GenerateConstantsForMissingPermissions(
        List<DatabasePermission> missingPermissions,
        List<PermissionDefinition> existingConstants)
    {
        var constants = new List<ConstantDefinition>();
        var existingConstantNames = existingConstants
            .Select(p => p.PermissionName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var dbPermission in missingPermissions)
        {
            // Skip if already exists
            if (existingConstantNames.Contains(dbPermission.PermissionName))
                continue;

            // Parse resource and action from permission name
            var parts = dbPermission.PermissionName.Split(':', 2);
            var resource = parts.Length > 0 ? parts[0] : dbPermission.Resource;
            var action = parts.Length > 1 ? parts[1] : dbPermission.Action;

            // Generate constant name
            var constantName = PermissionNameGenerator.GenerateConstantName(dbPermission.PermissionName);

            constants.Add(new ConstantDefinition
            {
                PermissionName = dbPermission.PermissionName,
                ConstantName = constantName,
                Resource = resource,
                Action = action,
                Description = dbPermission.Description,
                Namespace = "Shared" // Default to shared, can be refined later
            });
        }

        return constants.OrderBy(c => c.Resource).ThenBy(c => c.Action).ToList();
    }

    /// <summary>
    /// Generates formatted constant code to add to Permissions.cs.
    /// </summary>
    public string GenerateConstantsCode(List<ConstantDefinition> constants)
    {
        if (constants.Count == 0)
            return string.Empty;

        var lines = new List<string>();
        
        // Group by resource for better organization
        var grouped = constants.GroupBy(c => c.Resource);

        foreach (var group in grouped)
        {
            var resource = group.Key;
            var resourceConstants = group.ToList();

            // Add comment for resource group
            lines.Add($"        // {CapitalizeFirst(resource)} permissions");
            
            foreach (var constant in resourceConstants)
            {
                // Add XML comment if description available
                if (!string.IsNullOrWhiteSpace(constant.Description))
                {
                    lines.Add($"        /// <summary>");
                    lines.Add($"        /// {constant.Description}");
                    lines.Add($"        /// </summary>");
                }
                
                lines.Add($"        public const string {constant.ConstantName} = \"{constant.PermissionName}\";");
            }
            
            lines.Add(string.Empty); // Empty line between resource groups
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string CapitalizeFirst(string text)
    {
        if (string.IsNullOrEmpty(text))
            return text;
        
        return char.ToUpper(text[0]) + (text.Length > 1 ? text.Substring(1) : string.Empty);
    }
}
