namespace PermissionScanner.Core.Models;

/// <summary>
/// Represents a permission as stored in the database.
/// </summary>
public class DatabasePermission
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
    /// Whether this is a system permission (auto-generated).
    /// </summary>
    public bool IsSystemPermission { get; set; }

    /// <summary>
    /// Whether this permission is active.
    /// </summary>
    public bool IsActive { get; set; }

    /// <summary>
    /// Display order for UI sorting.
    /// </summary>
    public int DisplayOrder { get; set; }

    /// <summary>
    /// When this permission was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }
}
