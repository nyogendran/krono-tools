using System.Text.RegularExpressions;

namespace PermissionScanner.Core.Analyzers;

/// <summary>
/// Generates permission names following the {resource}:{action} convention.
/// </summary>
public static class PermissionNameGenerator
{
    /// <summary>
    /// Generates a permission name from HTTP method and route template.
    /// </summary>
    /// <param name="httpMethod">HTTP method (GET, POST, PUT, PATCH, DELETE).</param>
    /// <param name="routeTemplate">Route template (e.g., "/api/v1/products" or "/api/v1/products/{id}/variants").</param>
    /// <returns>Permission name in {resource}:{action} format.</returns>
    public static (string Resource, string Action, string PermissionName) Generate(
        string httpMethod,
        string routeTemplate)
    {
        // Extract resource from route
        var resource = ExtractResource(routeTemplate);
        
        // Extract action from HTTP method and route
        var action = ExtractAction(httpMethod, routeTemplate);
        
        // Combine into permission name
        var permissionName = $"{resource}:{action}";
        
        return (resource, action, permissionName);
    }

    /// <summary>
    /// Extracts resource name from route template.
    /// </summary>
    /// <example>
    /// "/api/v1/products" → "products"
    /// "/api/v1/products/{id}/variants" → "products:variants"
    /// "/api/v1/platform/clients" → "platform:clients"
    /// "/api/v1/admin/number-sequences" → "number-sequences" (admin is a prefix, not resource)
    /// "/api/v1/rbac/roles" → "roles" (rbac is a prefix, not resource)
    /// "/internal/events" → "events" (internal is a prefix, not resource)
    /// </example>
    private static string ExtractResource(string routeTemplate)
    {
        // Remove leading/trailing slashes and split
        var parts = routeTemplate.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        
        // Known path prefixes that are not resources
        var pathPrefixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "api", "v1", "v2", "admin", "rbac", "internal", "public", "private"
        };
        
        // Skip API version parts (e.g., "api", "v1", "v{version}")
        var resourceParts = new List<string>();
        
        foreach (var part in parts)
        {
            // Skip API routing parts
            if (part.Equals("api", StringComparison.OrdinalIgnoreCase) ||
                part.StartsWith("v", StringComparison.OrdinalIgnoreCase) ||
                part.Contains("{version}", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            
            // Skip known path prefixes (admin, rbac, internal, etc.)
            if (pathPrefixes.Contains(part))
            {
                continue;
            }
            
            // Check if this is a platform-scoped resource
            if (part.Equals("platform", StringComparison.OrdinalIgnoreCase))
            {
                resourceParts.Add("platform");
                continue;
            }
            
            // Skip parameter placeholders like {id}, {organizationId}
            if (part.StartsWith("{") && part.EndsWith("}"))
            {
                continue;
            }
            
            // This is a resource segment
            resourceParts.Add(part);
        }
        
        if (resourceParts.Count == 0)
        {
            return "unknown";
        }
        
        // Join with colons for nested resources (e.g., "products:variants")
        return string.Join(":", resourceParts);
    }

    /// <summary>
    /// Extracts action name from HTTP method and route.
    /// </summary>
    /// <example>
    /// GET → "read"
    /// POST → "create"
    /// PUT/PATCH → "update"
    /// DELETE → "delete"
    /// POST /approve → "approve"
    /// POST /bulk-delete → "bulk-delete"
    /// </example>
    private static string ExtractAction(string httpMethod, string routeTemplate)
    {
        // Check for custom actions in route (e.g., /approve, /reject, /bulk-delete)
        var routeLower = routeTemplate.ToLowerInvariant();
        
        // Extract the last segment of the route (after last slash, before parameters)
        var lastSegment = routeTemplate.Trim('/').Split('/').LastOrDefault() ?? "";
        lastSegment = lastSegment.Split('?').FirstOrDefault() ?? lastSegment; // Remove query string
        lastSegment = lastSegment.Split('{').FirstOrDefault() ?? lastSegment; // Remove route params
        
        // Custom actions in route
        if (routeLower.Contains("/approve") || lastSegment.Equals("approve", StringComparison.OrdinalIgnoreCase))
            return "approve";
        if (routeLower.Contains("/reject") || lastSegment.Equals("reject", StringComparison.OrdinalIgnoreCase))
            return "reject";
        if (routeLower.Contains("/bulk-delete") || lastSegment.Equals("bulk-delete", StringComparison.OrdinalIgnoreCase))
            return "bulk-delete";
        if (routeLower.Contains("/bulk-update") || lastSegment.Equals("bulk-update", StringComparison.OrdinalIgnoreCase))
            return "bulk-update";
        if (routeLower.Contains("/adjust") || lastSegment.Equals("adjust", StringComparison.OrdinalIgnoreCase))
            return "adjust";
        if (routeLower.Contains("/transfer") || lastSegment.Equals("transfer", StringComparison.OrdinalIgnoreCase))
            return "transfer";
        if (routeLower.Contains("/export") || lastSegment.Equals("export", StringComparison.OrdinalIgnoreCase))
            return "export";
        if (routeLower.Contains("/import") || lastSegment.Equals("import", StringComparison.OrdinalIgnoreCase))
            return "import";
        if (routeLower.Contains("/generate") || lastSegment.Equals("generate", StringComparison.OrdinalIgnoreCase))
            return "generate";
        if (routeLower.Contains("/preview") || lastSegment.Equals("preview", StringComparison.OrdinalIgnoreCase))
            return "preview";
        
        // Standard HTTP method mapping
        return httpMethod.ToUpperInvariant() switch
        {
            "GET" => "read",
            "POST" => "create",
            "PUT" or "PATCH" => "update",
            "DELETE" => "delete",
            _ => "unknown"
        };
    }

    /// <summary>
    /// Generates a policy name from permission name.
    /// </summary>
    /// <example>
    /// "products:create" → "RequireProductCreate"
    /// "products:read" → "RequireProductView"
    /// "approvals:orders:read" → "RequireApprovalOrdersView"
    /// "approvals:orders:request:create" → "RequireApprovalOrdersRequestCreate"
    /// "number-sequences:read" → "RequireNumberSequenceView"
    /// "roles:read" → "RequireRoleView"
    /// </example>
    public static string GeneratePolicyName(string permissionName)
    {
        var parts = permissionName.Split(':');
        if (parts.Length < 2)
        {
            return $"Require{ToPascalCase(permissionName)}";
        }
        
        // Handle nested resources (3+ parts)
        // e.g., "approvals:orders:read" → "RequireApprovalOrdersView"
        // e.g., "approvals:orders:request:create" → "RequireApprovalOrdersRequestCreate"
        if (parts.Length >= 3)
        {
            // All parts except the last are resource components
            var resourceParts = parts.Take(parts.Length - 1).Select(ToPascalCase).ToList();
            // Last part is the action
            var nestedAction = ToPascalCase(parts[parts.Length - 1]);
            
            // Convert first resource part to singular
            if (resourceParts.Count > 0)
            {
                resourceParts[0] = ToSingular(resourceParts[0]);
            }
            
            // Special handling for common actions
            if (nestedAction.Equals("Read", StringComparison.OrdinalIgnoreCase))
                nestedAction = "View";
            else if (nestedAction.Equals("Write", StringComparison.OrdinalIgnoreCase))
                nestedAction = "Edit";
            
            var nestedResource = string.Join("", resourceParts);
            return $"Require{nestedResource}{nestedAction}";
        }
        
        // Handle simple 2-part permissions (resource:action)
        var resource = ToPascalCase(parts[0]);
        var action = ToPascalCase(parts[1]);
        
        // Convert plural resources to singular for policy names
        resource = ToSingular(resource);
        
        // Special handling for common actions
        if (action.Equals("Read", StringComparison.OrdinalIgnoreCase))
            action = "View";
        else if (action.Equals("Write", StringComparison.OrdinalIgnoreCase))
            action = "Edit";
        
        return $"Require{resource}{action}";
    }

    /// <summary>
    /// Converts plural nouns to singular (simple heuristic with special cases).
    /// </summary>
    /// <example>
    /// "Products" → "Product"
    /// "Roles" → "Role"
    /// "NumberSequences" → "NumberSequence"
    /// "Clients" → "Client"
    /// </example>
    private static string ToSingular(string word)
    {
        if (string.IsNullOrEmpty(word))
            return word;
        
        // Known exceptions - handle these first
        var wordLower = word.ToLowerInvariant();
        var exceptions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "roles", "Role" },
            { "sequences", "Sequence" },
            { "numbersequences", "NumberSequence" },
            { "clients", "Client" },
            { "products", "Product" },
            { "users", "User" },
            { "events", "Event" }
        };
        
        if (exceptions.TryGetValue(wordLower, out var singular))
        {
            return singular;
        }
        
        // Handle compound words like "NumberSequences"
        if (word.Contains("Sequence", StringComparison.OrdinalIgnoreCase))
        {
            return word.Replace("Sequences", "Sequence", StringComparison.OrdinalIgnoreCase);
        }
        if (word.Contains("Role", StringComparison.OrdinalIgnoreCase) && word.EndsWith("s", StringComparison.OrdinalIgnoreCase))
        {
            return word.Substring(0, word.Length - 1); // "Roles" → "Role"
        }
        
        // Simple plural-to-singular conversion (common cases)
        if (word.EndsWith("ies", StringComparison.OrdinalIgnoreCase))
        {
            // "categories" → "category"
            return word.Substring(0, word.Length - 3) + "y";
        }
        else if (word.EndsWith("es", StringComparison.OrdinalIgnoreCase) && word.Length > 3)
        {
            // For most cases, removing "es" works (e.g., "clients" → "client")
            // But handle special cases above first
            var withoutEs = word.Substring(0, word.Length - 2);
            
            // If it ends with 'c' or 's', might need to add 'e' back
            if (withoutEs.EndsWith("c", StringComparison.OrdinalIgnoreCase) ||
                withoutEs.EndsWith("s", StringComparison.OrdinalIgnoreCase))
            {
                // Check if adding 'e' makes sense (heuristic)
                // "sequenc" → "sequence", "rol" → "role"
                if (withoutEs.EndsWith("quenc", StringComparison.OrdinalIgnoreCase) ||
                    withoutEs.EndsWith("rol", StringComparison.OrdinalIgnoreCase))
                {
                    return withoutEs + "e";
                }
            }
            
            return withoutEs;
        }
        else if (word.EndsWith("s", StringComparison.OrdinalIgnoreCase) && word.Length > 1)
        {
            // "products" → "product", "users" → "user"
            // But skip words that end in "ss" (e.g., "class", "process")
            if (!word.EndsWith("ss", StringComparison.OrdinalIgnoreCase) &&
                !word.EndsWith("us", StringComparison.OrdinalIgnoreCase))
            {
                return word.Substring(0, word.Length - 1);
            }
        }
        
        // Return as-is if no conversion needed or uncertain
        return word;
    }

    /// <summary>
    /// Converts kebab-case or snake_case to PascalCase.
    /// </summary>
    /// <example>
    /// "products" → "Products"
    /// "product-variants" → "ProductVariants"
    /// "approval_levels" → "ApprovalLevels"
    /// </example>
    /// <summary>
    /// Converts a string to PascalCase.
    /// </summary>
    public static string ToPascalCase(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;
        
        // Split by hyphens, underscores, or colons
        var parts = input.Split(new[] { '-', '_', ':' }, StringSplitOptions.RemoveEmptyEntries);
        
        var result = new System.Text.StringBuilder();
        foreach (var part in parts)
        {
            if (part.Length > 0)
            {
                result.Append(char.ToUpperInvariant(part[0]));
                if (part.Length > 1)
                {
                    result.Append(part.Substring(1).ToLowerInvariant());
                }
            }
        }
        
        return result.ToString();
    }

    /// <summary>
    /// Generates a constant name for Permissions.cs from permission name.
    /// </summary>
    /// <example>
    /// "products:create" → "ProductsCreate"
    /// "products:read" → "ProductsRead"
    /// "approvals:orders:read" → "ApprovalsOrdersRead"
    /// "approvals:orders:request:create" → "ApprovalsOrdersRequestCreate"
    /// "approval-levels:view" → "ApprovalLevelsView"
    /// </example>
    public static string GenerateConstantName(string permissionName)
    {
        var parts = permissionName.Split(':');
        if (parts.Length < 2)
        {
            return ToPascalCase(permissionName);
        }
        
        // Handle nested resources (3+ parts)
        // e.g., "approvals:orders:read" → "ApprovalsOrdersRead"
        // e.g., "approvals:orders:request:create" → "ApprovalsOrdersRequestCreate"
        if (parts.Length >= 3)
        {
            // All parts except the last are resource components
            var resourceParts = parts.Take(parts.Length - 1).Select(ToPascalCase).ToList();
            // Last part is the action
            var nestedAction = ToPascalCase(parts[parts.Length - 1]);
            
            var nestedResource = string.Join("", resourceParts);
            return $"{nestedResource}{nestedAction}";
        }
        
        // Handle simple 2-part permissions (resource:action)
        var resource = ToPascalCase(parts[0]);
        var action = ToPascalCase(parts[1]);
        
        return $"{resource}{action}";
    }

    /// <summary>
    /// Determines the domain/category for a permission based on resource.
    /// </summary>
    public static string DetermineDomain(string resource)
    {
        var resourceLower = resource.ToLowerInvariant();
        
        if (resourceLower.StartsWith("product"))
            return "Products";
        if (resourceLower.StartsWith("inventory") || resourceLower.StartsWith("warehouse") || resourceLower.StartsWith("stock"))
            return "Inventory";
        if (resourceLower.StartsWith("approval") || resourceLower.StartsWith("discount"))
            return "Approvals";
        if (resourceLower.StartsWith("pricing") || resourceLower.StartsWith("cost"))
            return "Pricing";
        if (resourceLower.StartsWith("user") || resourceLower.StartsWith("role") || resourceLower.StartsWith("permission"))
            return "User Management";
        if (resourceLower.StartsWith("tenant") || resourceLower.StartsWith("client") || resourceLower.StartsWith("organization"))
            return "Tenant Management";
        if (resourceLower.StartsWith("platform"))
            return "Platform";
        if (resourceLower.StartsWith("analytics") || resourceLower.StartsWith("report"))
            return "Analytics";
        if (resourceLower.StartsWith("system"))
            return "System";
        
        return "Other";
    }
}
