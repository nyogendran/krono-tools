namespace PermissionScanner.Core.Models;

/// <summary>
/// Represents a permission definition with metadata.
/// </summary>
public class PermissionDefinition
{
    /// <summary>
    /// Permission name following {resource}:{action} convention (e.g., "products:create").
    /// </summary>
    public string PermissionName { get; set; } = string.Empty;

    /// <summary>
    /// Resource name (e.g., "products", "products:variants").
    /// </summary>
    public string Resource { get; set; } = string.Empty;

    /// <summary>
    /// Action name (e.g., "read", "create", "update", "delete").
    /// </summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable description of the permission.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// List of endpoints that use this permission.
    /// </summary>
    public List<string> Endpoints { get; set; } = new();

    /// <summary>
    /// Suggested constant name in Permissions.cs (e.g., "ProductsCreate").
    /// </summary>
    public string ConstantName { get; set; } = string.Empty;

    /// <summary>
    /// Domain/category for grouping (e.g., "Products", "Inventory", "Approvals").
    /// </summary>
    public string Domain { get; set; } = string.Empty;
}
