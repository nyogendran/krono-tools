namespace PermissionScanner.Core.Models;

/// <summary>
/// Represents a discovered API endpoint from the codebase.
/// </summary>
public class DiscoveredEndpoint
{
    /// <summary>
    /// Name of the microservice containing this endpoint (e.g., "ProductService").
    /// </summary>
    public string ServiceName { get; set; } = string.Empty;

    /// <summary>
    /// Relative file path from solution root (e.g., "ProductService/KS.ProductService.Api/Endpoints/ProductEndpoints.cs").
    /// </summary>
    public string FilePath { get; set; } = string.Empty;

    /// <summary>
    /// Line number where the endpoint is defined.
    /// </summary>
    public int LineNumber { get; set; }

    /// <summary>
    /// HTTP method (GET, POST, PUT, PATCH, DELETE).
    /// </summary>
    public string HttpMethod { get; set; } = string.Empty;

    /// <summary>
    /// Route template (e.g., "/api/v1/products" or "/api/v1/products/{id}").
    /// </summary>
    public string RouteTemplate { get; set; } = string.Empty;

    /// <summary>
    /// Existing authorization policy name if already applied (e.g., "RequireProductCreate"), or null if not found.
    /// </summary>
    public string? ExistingPolicy { get; set; }

    /// <summary>
    /// Suggested permission name following {resource}:{action} convention (e.g., "products:create").
    /// </summary>
    public string SuggestedPermission { get; set; } = string.Empty;

    /// <summary>
    /// Suggested authorization policy name (e.g., "RequireProductCreate").
    /// </summary>
    public string SuggestedPolicy { get; set; } = string.Empty;

    /// <summary>
    /// Whether this endpoint already has an authorization policy applied.
    /// </summary>
    public bool HasPolicy => !string.IsNullOrEmpty(ExistingPolicy);

    /// <summary>
    /// Resource name extracted from route (e.g., "products", "products:variants").
    /// </summary>
    public string Resource { get; set; } = string.Empty;

    /// <summary>
    /// Action name extracted from HTTP method or route (e.g., "read", "create", "update", "delete").
    /// </summary>
    public string Action { get; set; } = string.Empty;
}
