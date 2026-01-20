namespace PermissionScanner.Core.Models;

/// <summary>
/// Represents an authorization policy definition.
/// </summary>
public class PolicyDefinition
{
    /// <summary>
    /// Policy name constant (e.g., "RequireProductCreate").
    /// </summary>
    public string PolicyName { get; set; } = string.Empty;

    /// <summary>
    /// Permission name that this policy requires (e.g., "products:create").
    /// </summary>
    public string RequiredPermission { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable description of the policy.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Domain/category for grouping (e.g., "Products", "Inventory").
    /// </summary>
    public string Domain { get; set; } = string.Empty;
}
