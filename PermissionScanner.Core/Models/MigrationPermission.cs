namespace PermissionScanner.Core.Models;

/// <summary>
/// Represents a permission extracted from a migration file.
/// </summary>
public class MigrationPermission
{
    /// <summary>
    /// Permission name (e.g., "products:read").
    /// </summary>
    public string PermissionName { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable description of the permission.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Resource name (e.g., "products", "products:variants").
    /// </summary>
    public string Resource { get; set; } = string.Empty;

    /// <summary>
    /// Action name (e.g., "read", "create", "update", "delete").
    /// </summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// Migration file name (e.g., "20260128020197_SeedProductsPermissions.cs").
    /// </summary>
    public string MigrationFile { get; set; } = string.Empty;

    /// <summary>
    /// Migration version/timestamp (e.g., 20260128020197).
    /// </summary>
    public long MigrationVersion { get; set; }
}
