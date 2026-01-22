using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Analyzes permissions and determines which roles should be assigned to them.
/// </summary>
public class RoleAssignmentAnalyzer
{
    /// <summary>
    /// Standard system roles and their permission patterns.
    /// </summary>
    public static readonly Dictionary<string, RolePermissionPattern> RolePatterns = new()
    {
        ["admin"] = new RolePermissionPattern
        {
            RoleName = "admin",
            Description = "System Administrator - Full access to all features and settings",
            IncludeAll = true, // Admin gets all permissions
            ExcludePatterns = new List<string>() // No exclusions
        },
        ["manager"] = new RolePermissionPattern
        {
            RoleName = "manager",
            Description = "Manager - Access to product management, cost management, and user management",
            IncludeAll = false,
            IncludePatterns = new List<string>
            {
                "read", "write", "create", "update", "manage", "approve", "reject"
            },
            ExcludePatterns = new List<string>
            {
                "delete", // Managers typically don't delete
                "system:", // System-level operations
                "platform:" // Platform admin operations
            }
        },
        ["user"] = new RolePermissionPattern
        {
            RoleName = "user",
            Description = "Standard User - Access to products and costs for assigned organizations",
            IncludeAll = false,
            IncludePatterns = new List<string>
            {
                "read", "write", "create", "update"
            },
            ExcludePatterns = new List<string>
            {
                "delete", "manage", "approve", "reject",
                "system:", "platform:", "admin:",
                "users:", "roles:", "permissions:" // User management
            }
        },
        ["viewer"] = new RolePermissionPattern
        {
            RoleName = "viewer",
            Description = "Read-Only User - View-only access to products and costs",
            IncludeAll = false,
            IncludePatterns = new List<string>
            {
                "read", "view"
            },
            ExcludePatterns = new List<string>
            {
                "write", "create", "update", "delete", "manage", "approve", "reject",
                "system:", "platform:", "admin:",
                "users:", "roles:", "permissions:"
            }
        }
    };

    /// <summary>
    /// Determines which roles should be assigned a given permission.
    /// </summary>
    public static List<string> DetermineRolesForPermission(PermissionDefinition permission)
    {
        var roles = new List<string>();

        foreach (var (roleName, pattern) in RolePatterns)
        {
            if (ShouldAssignPermissionToRole(permission, pattern))
            {
                roles.Add(roleName);
            }
        }

        return roles;
    }

    /// <summary>
    /// Determines if a permission should be assigned to a role based on the role's pattern.
    /// </summary>
    private static bool ShouldAssignPermissionToRole(PermissionDefinition permission, RolePermissionPattern pattern)
    {
        // Admin gets everything
        if (pattern.IncludeAll)
            return true;

        var permissionName = permission.PermissionName.ToLowerInvariant();
        var action = permission.Action.ToLowerInvariant();

        // Check exclusions first
        foreach (var excludePattern in pattern.ExcludePatterns)
        {
            if (permissionName.Contains(excludePattern.ToLowerInvariant()) ||
                action.Contains(excludePattern.ToLowerInvariant()))
            {
                return false;
            }
        }

        // Check inclusions
        foreach (var includePattern in pattern.IncludePatterns)
        {
            if (action.Contains(includePattern.ToLowerInvariant()))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Groups permissions by the roles they should be assigned to.
    /// </summary>
    public static Dictionary<string, List<PermissionDefinition>> GroupPermissionsByRole(
        List<PermissionDefinition> permissions)
    {
        var rolePermissions = new Dictionary<string, List<PermissionDefinition>>();

        // Initialize with all roles
        foreach (var roleName in RolePatterns.Keys)
        {
            rolePermissions[roleName] = new List<PermissionDefinition>();
        }

        // Assign permissions to roles
        foreach (var permission in permissions)
        {
            var roles = DetermineRolesForPermission(permission);
            foreach (var roleName in roles)
            {
                rolePermissions[roleName].Add(permission);
            }
        }

        // Remove empty role lists
        return rolePermissions
            .Where(kvp => kvp.Value.Count > 0)
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
    }
}

/// <summary>
/// Defines a pattern for which permissions a role should have.
/// </summary>
public class RolePermissionPattern
{
    /// <summary>
    /// The name of the role (e.g., "admin", "manager", "user", "viewer").
    /// </summary>
    public string RoleName { get; set; } = string.Empty;
    
    /// <summary>
    /// Human-readable description of the role.
    /// </summary>
    public string Description { get; set; } = string.Empty;
    
    /// <summary>
    /// If true, the role gets all permissions (e.g., admin role).
    /// </summary>
    public bool IncludeAll { get; set; } = false;
    
    /// <summary>
    /// List of action patterns to include (e.g., "read", "write", "create").
    /// </summary>
    public List<string> IncludePatterns { get; set; } = new();
    
    /// <summary>
    /// List of patterns to exclude (e.g., "delete", "system:", "platform:").
    /// </summary>
    public List<string> ExcludePatterns { get; set; } = new();
}
