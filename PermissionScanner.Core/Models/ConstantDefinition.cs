namespace PermissionScanner.Core.Models;

/// <summary>
/// Represents a constant definition to be added to Permissions.cs.
/// </summary>
public class ConstantDefinition
{
    /// <summary>
    /// Permission name (e.g., "products:write").
    /// </summary>
    public string PermissionName { get; set; } = string.Empty;

    /// <summary>
    /// Constant name (e.g., "ProductsWrite").
    /// </summary>
    public string ConstantName { get; set; } = string.Empty;

    /// <summary>
    /// Resource name (e.g., "products").
    /// </summary>
    public string Resource { get; set; } = string.Empty;

    /// <summary>
    /// Action name (e.g., "write").
    /// </summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// Description for the constant (from database if available).
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Target namespace ("Shared" for PlatformServices, or service name for service-specific).
    /// </summary>
    public string Namespace { get; set; } = "Shared";
}
