namespace PermissionScanner.Core.Models;

/// <summary>
/// Represents a code reference using a string literal instead of a constant.
/// </summary>
public class StringLiteralReference
{
    /// <summary>
    /// File path where the reference was found.
    /// </summary>
    public string FilePath { get; set; } = string.Empty;

    /// <summary>
    /// Line number (1-based).
    /// </summary>
    public int LineNumber { get; set; }

    /// <summary>
    /// Column number (1-based).
    /// </summary>
    public int ColumnNumber { get; set; }

    /// <summary>
    /// Permission name found as string literal (e.g., "products:write").
    /// </summary>
    public string PermissionName { get; set; } = string.Empty;

    /// <summary>
    /// Current code snippet (e.g., "HasPermission(user, \"products:write\")").
    /// </summary>
    public string CurrentCode { get; set; } = string.Empty;

    /// <summary>
    /// Suggested replacement code (e.g., "HasPermission(user, Permissions.ProductsWrite)").
    /// </summary>
    public string SuggestedCode { get; set; } = string.Empty;

    /// <summary>
    /// Context description (e.g., "HasPermission call", "if statement").
    /// </summary>
    public string Context { get; set; } = string.Empty;

    /// <summary>
    /// Namespace for the constant (e.g., "KS.PlatformServices.Constants").
    /// </summary>
    public string ConstantNamespace { get; set; } = string.Empty;

    /// <summary>
    /// Constant name to use (e.g., "ProductsWrite").
    /// </summary>
    public string ConstantName { get; set; } = string.Empty;
}
