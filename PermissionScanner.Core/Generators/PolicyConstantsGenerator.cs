using System.Text;
using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Generators;

/// <summary>
/// Generates C# code for AuthorizationPolicies.cs constants class.
/// </summary>
public static class PolicyConstantsGenerator
{
    /// <summary>
    /// Generates the AuthorizationPolicies.cs file content with policy constants.
    /// </summary>
    /// <param name="policies">List of policies to generate</param>
    /// <param name="existingContent">Existing file content to merge with</param>
    /// <param name="namespaceName">Namespace for the generated constants (default: KS.PlatformServices.Constants)</param>
    public static string GenerateFileContent(List<PolicyDefinition> policies, string? existingContent = null, string? namespaceName = null)
    {
        var sb = new StringBuilder();
        
        // Parse existing content to preserve manual policies (if exists)
        var manualPolicies = ExtractManualPolicies(existingContent ?? string.Empty);
        
        // Always merge default system policies to ensure all required policies are present (only for PlatformServices)
        var defaultPolicies = GetDefaultSystemPolicies();
        var existingPolicyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        // Policy name mappings for deprecated names (old → new)
        var deprecatedPolicyMappings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "RequiredAdminRole", "RequireAdminRole" },
            { "ServiceAccount", "RequireServiceAccount" },
            { "RequireApprovalPermission", "RequireApprovalApprove" }
        };
        
        // Extract policy names from existing manual policies, excluding deprecated ones
        var filteredManualPolicies = new List<string>();
        foreach (var policy in manualPolicies)
        {
            var policyName = ExtractPolicyNameFromConstant(policy.Trim());
            if (policyName != null)
            {
                // Skip deprecated policy names (they'll be replaced with new ones)
                if (deprecatedPolicyMappings.ContainsKey(policyName))
                {
                    continue; // Skip deprecated policy
                }
                existingPolicyNames.Add(policyName);
                filteredManualPolicies.Add(policy);
            }
            else
            {
                // Keep non-policy lines (comments, blank lines)
                filteredManualPolicies.Add(policy);
            }
        }
        
        // Add default policies that don't already exist (only for PlatformServices)
        if (namespaceName == null || namespaceName.Contains("PlatformServices"))
        {
            foreach (var defaultPolicy in defaultPolicies)
            {
                var defaultPolicyName = ExtractPolicyNameFromConstant(defaultPolicy.Trim());
                if (defaultPolicyName != null && !existingPolicyNames.Contains(defaultPolicyName))
                {
                    filteredManualPolicies.Add(defaultPolicy);
                }
            }
        }
        
        manualPolicies = filteredManualPolicies;
        
        // Validate existing policies against naming conventions (only for PlatformServices)
        if (namespaceName == null || namespaceName.Contains("PlatformServices"))
        {
            ValidateExistingPolicies(existingContent ?? string.Empty);
        }
        
        // Use provided namespace or default to PlatformServices
        var ns = namespaceName ?? "KS.PlatformServices.Constants";
        sb.AppendLine($"namespace {ns};");
        sb.AppendLine();
        sb.AppendLine("/// <summary>");
        sb.AppendLine("/// Constants for authorization policies used in the application.");
        sb.AppendLine("/// Auto-generated permission-based policies - DO NOT EDIT MANUALLY");
        sb.AppendLine($"/// Last Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine("/// To regenerate: dotnet tool run permission-scanner generate");
        sb.AppendLine("/// </summary>");
        sb.AppendLine("public static class AuthorizationPolicies");
        sb.AppendLine("{");

        // Add manual policies first (if any)
        if (manualPolicies.Count > 0)
        {
            sb.AppendLine("    #region Manual Policies (Preserved)");
            sb.AppendLine();
            foreach (var manualPolicy in manualPolicies)
            {
                // Normalize indentation - remove extra tabs/spaces and ensure 4-space indentation
                var normalized = NormalizeIndentation(manualPolicy);
                sb.AppendLine(normalized);
            }
            sb.AppendLine("    #endregion");
            sb.AppendLine();
        }

        // Group by domain for feature/resource-based organization
        var groupedByDomain = policies
            .GroupBy(p => p.Domain)
            .OrderBy(g => g.Key)
            .ToList();

        foreach (var domainGroup in groupedByDomain)
        {
            // Use consistent naming: "Product Policies" instead of "Product Permissions Policies"
            var regionName = domainGroup.Key.EndsWith("Permissions") 
                ? domainGroup.Key.Replace("Permissions", "Policies")
                : $"{domainGroup.Key} Policies";
            
            sb.AppendLine($"    #region {regionName}");
            sb.AppendLine();

            var sortedPolicies = domainGroup.OrderBy(p => p.PolicyName).ToList();
            
            foreach (var policy in sortedPolicies)
            {
                // XML comment
                sb.AppendLine("    /// <summary>");
                sb.AppendLine($"    /// Requires '{policy.RequiredPermission}' permission.");
                if (!string.IsNullOrEmpty(policy.Description))
                {
                    sb.AppendLine($"    /// {policy.Description}");
                }
                sb.AppendLine("    /// </summary>");
                
                // Constant declaration
                sb.AppendLine($"    public const string {policy.PolicyName} = \"{policy.PolicyName}\";");
                sb.AppendLine();
            }

            sb.AppendLine("    #endregion");
            sb.AppendLine();
        }

        sb.AppendLine("}");

        return sb.ToString();
    }

    /// <summary>
    /// Gets the canonical list of system policy names.
    /// This is the single source of truth for all system policies.
    /// </summary>
    private static HashSet<string> GetSystemPolicyNames()
    {
        var defaultPolicies = GetDefaultSystemPolicies();
        var policyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        foreach (var policy in defaultPolicies)
        {
            var policyName = ExtractPolicyNameFromConstant(policy.Trim());
            if (policyName != null)
            {
                policyNames.Add(policyName);
            }
        }
        
        return policyNames;
    }
    
    /// <summary>
    /// Extracts manual (non-permission-based) policies from existing content.
    /// Preserves system-level policies that don't map to specific permissions.
    /// Uses the canonical system policy list to identify which policies to preserve.
    /// </summary>
    private static List<string> ExtractManualPolicies(string existingContent)
    {
        var manualPolicies = new List<string>();
        
        if (string.IsNullOrEmpty(existingContent))
            return manualPolicies;

        // Get canonical list of system policy names (single source of truth)
        var systemPolicyIdentifiers = GetSystemPolicyNames();
        
        // Deprecated policy names that should be excluded (replaced by new names)
        var deprecatedPolicyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "RequiredAdminRole",      // Replaced by RequireAdminRole
            "ServiceAccount",          // Replaced by RequireServiceAccount
            "RequireApprovalPermission" // Replaced by RequireApprovalApprove
        };

        var lines = existingContent.Split('\n');
        var inManualRegion = false;
        var currentComment = new List<string>();
        var capturingComment = false;
        
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            
            // Detect manual policy region
            if (line.Contains("#region") && 
                (line.Contains("Manual") || line.Contains("System") || line.Contains("General")))
            {
                inManualRegion = true;
                continue;
            }
            
            if (line.Contains("#endregion") && inManualRegion)
            {
                inManualRegion = false;
                continue;
            }
            
            // Capture XML comments
            if (line.StartsWith("///"))
            {
                if (!capturingComment)
                {
                    currentComment.Clear();
                    capturingComment = true;
                }
                // Normalize to 4-space indentation
                var normalizedComment = NormalizeIndentation(lines[i]);
                currentComment.Add(normalizedComment);
                continue;
            }
            
            // Check if this is a policy constant
            if (line.StartsWith("public const string"))
            {
                var policyName = ExtractPolicyNameFromConstant(line);
                
                // Skip deprecated policy names (they'll be replaced with new ones)
                if (policyName != null && deprecatedPolicyNames.Contains(policyName))
                {
                    capturingComment = false;
                    currentComment.Clear();
                    continue; // Skip deprecated policy
                }
                
                // If it's a system policy or in manual region, preserve it
                if (inManualRegion || (policyName != null && systemPolicyIdentifiers.Contains(policyName)))
                {
                    // Add captured comment if any
                    if (capturingComment && currentComment.Count > 0)
                    {
                        manualPolicies.AddRange(currentComment);
                    }
                    // Normalize to 4-space indentation
                    var normalizedLine = NormalizeIndentation(lines[i]);
                    manualPolicies.Add(normalizedLine);
                    capturingComment = false;
                    currentComment.Clear();
                }
            }
            else if (capturingComment && !string.IsNullOrWhiteSpace(line))
            {
                // Non-comment, non-constant line - reset comment capture
                capturingComment = false;
                currentComment.Clear();
            }
        }

        return manualPolicies;
    }
    
    /// <summary>
    /// Extracts policy name from a constant declaration line.
    /// </summary>
    private static string? ExtractPolicyNameFromConstant(string line)
    {
        // Pattern: public const string PolicyName = "PolicyName";
        var match = System.Text.RegularExpressions.Regex.Match(
            line, 
            @"public\s+const\s+string\s+(\w+)\s*=");
        
        return match.Success ? match.Groups[1].Value : null;
    }
    
    /// <summary>
    /// Normalizes indentation to 4 spaces (standard C# indentation).
    /// Removes leading tabs/spaces and replaces with proper 4-space indentation.
    /// </summary>
    private static string NormalizeIndentation(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return line;
        
        // Count leading whitespace
        var leadingWhitespace = 0;
        foreach (var c in line)
        {
            if (c == ' ')
                leadingWhitespace++;
            else if (c == '\t')
                leadingWhitespace += 4; // Tab = 4 spaces
            else
                break;
        }
        
        // Remove leading whitespace
        var content = line.TrimStart();
        
        // Determine proper indentation level
        // If it's a comment or constant, use 4 spaces (1 level)
        // If it's inside a region, it should be at class level (4 spaces)
        var indentLevel = 1; // Default: 4 spaces (1 level)
        
        // Calculate proper indentation (4 spaces per level)
        var properIndent = new string(' ', indentLevel * 4);
        
        return properIndent + content;
    }

    /// <summary>
    /// Converts permission definitions to policy definitions.
    /// Also merges code-referenced policies to ensure all referenced constants are generated.
    /// Handles collisions by making policy names more specific or combining permissions.
    /// </summary>
    public static List<PolicyDefinition> ConvertToPolicies(
        List<PermissionDefinition> permissions,
        List<PolicyDefinition>? codeReferencedPolicies = null)
    {
        // Generate policies and handle collisions
        var policyMap = new Dictionary<string, PolicyDefinition>();
        var policyNameCollisions = new Dictionary<string, List<PermissionDefinition>>();
        
        foreach (var permission in permissions)
        {
            var policyName = PermissionNameGenerator.GeneratePolicyName(permission.PermissionName);
            
            if (!policyMap.ContainsKey(policyName))
            {
                policyMap[policyName] = new PolicyDefinition
                {
                    PolicyName = policyName,
                    RequiredPermission = permission.PermissionName,
                    Description = permission.Description,
                    Domain = permission.Domain
                };
            }
            else
            {
                // Multiple permissions map to the same policy name
                // Track collisions to handle them
                if (!policyNameCollisions.ContainsKey(policyName))
                {
                    // Create a PermissionDefinition from the existing policy for comparison
                    var existingPermDef = new PermissionDefinition
                    {
                        PermissionName = policyMap[policyName].RequiredPermission,
                        Description = policyMap[policyName].Description,
                        Domain = policyMap[policyName].Domain
                    };
                    policyNameCollisions[policyName] = new List<PermissionDefinition> 
                    { 
                        existingPermDef
                    };
                }
                policyNameCollisions[policyName].Add(permission);
            }
        }

        // Merge code-referenced policies (add missing ones)
        if (codeReferencedPolicies != null)
        {
            foreach (var codePolicy in codeReferencedPolicies)
            {
                // If policy doesn't exist, add it
                if (!policyMap.ContainsKey(codePolicy.PolicyName))
                {
                    policyMap[codePolicy.PolicyName] = codePolicy;
                }
                // If it exists but with different permission, prefer the code-referenced one (it's explicit)
                else if (policyMap[codePolicy.PolicyName].RequiredPermission != codePolicy.RequiredPermission)
                {
                    // Keep the code-referenced policy as it's explicitly used
                    policyMap[codePolicy.PolicyName] = codePolicy;
                }
            }
        }
        
        // Handle collisions by making policy names more specific
        foreach (var collision in policyNameCollisions)
        {
            var existingPolicy = policyMap[collision.Key];
            var allPermissions = collision.Value;
            
            // Get the first permission (the one that was already in the map)
            var firstPermission = allPermissions[0];
            
            // If only 1 new permission collides with existing (total of 2)
            if (allPermissions.Count == 2)
            {
                var newPermission = allPermissions[1];
                var existingPermission = firstPermission.PermissionName;
                
                // Check if they're singular/plural variants (e.g., "product:read" vs "products:read")
                if (AreSingularPluralVariants(existingPermission, newPermission.PermissionName))
                {
                    // Keep the plural one (more general) and update the policy
                    var pluralPermission = existingPermission.Contains("s:") ? existingPermission : newPermission.PermissionName;
                    policyMap[collision.Key] = new PolicyDefinition
                    {
                        PolicyName = collision.Key,
                        RequiredPermission = pluralPermission, // Use plural as it's more general
                        Description = $"View {GetResourceName(pluralPermission)}",
                        Domain = existingPolicy.Domain
                    };
                    
                    Console.WriteLine($"ℹ️  Resolved collision: Policy '{collision.Key}' now uses '{pluralPermission}' (plural form, more general)");
                }
                else
                {
                    // Different resources - generate more specific policy name for the new one
                    var specificPolicyName = GenerateSpecificPolicyName(newPermission.PermissionName);
                    policyMap[specificPolicyName] = new PolicyDefinition
                    {
                        PolicyName = specificPolicyName,
                        RequiredPermission = newPermission.PermissionName,
                        Description = newPermission.Description,
                        Domain = newPermission.Domain
                    };
                    
                    Console.WriteLine($"ℹ️  Resolved collision: Created separate policy '{specificPolicyName}' for '{newPermission.PermissionName}'");
                }
            }
            else
            {
                // Multiple collisions - report and keep first
                Console.WriteLine($"⚠️  Warning: Policy '{collision.Key}' collision with {allPermissions.Count} permissions:");
                Console.WriteLine($"    - {firstPermission.PermissionName} (kept)");
                foreach (var perm in allPermissions.Skip(1))
                {
                    Console.WriteLine($"    - {perm.PermissionName} (collision - consider manual policy)");
                }
            }
        }
        
        return policyMap.Values
            .OrderBy(p => p.Domain)
            .ThenBy(p => p.PolicyName)
            .ToList();
    }
    
    /// <summary>
    /// Checks if two permissions are singular/plural variants of the same resource.
    /// </summary>
    private static bool AreSingularPluralVariants(string perm1, string perm2)
    {
        var parts1 = perm1.Split(':');
        var parts2 = perm2.Split(':');
        
        if (parts1.Length != parts2.Length || parts1.Length < 2)
            return false;
        
        // Check if resources differ only by singular/plural
        var resource1 = parts1[0];
        var resource2 = parts2[0];
        
        // Check if one is singular and other is plural
        if (resource1 + "s" == resource2 || resource2 + "s" == resource1)
        {
            // Actions must match
            return parts1.Skip(1).SequenceEqual(parts2.Skip(1));
        }
        
        return false;
    }
    
    /// <summary>
    /// Generates a more specific policy name to avoid collisions.
    /// For singular/plural collisions, preserves the plural form.
    /// </summary>
    private static string GenerateSpecificPolicyName(string permissionName)
    {
        var parts = permissionName.Split(':');
        if (parts.Length < 2)
            return PermissionNameGenerator.GeneratePolicyName(permissionName);
        
        // For nested resources, include more context
        if (parts.Length >= 3)
        {
            var resourceParts = parts.Take(parts.Length - 1).Select(PermissionNameGenerator.ToPascalCase).ToList();
            var action = PermissionNameGenerator.ToPascalCase(parts[parts.Length - 1]);
            
            if (action.Equals("Read", StringComparison.OrdinalIgnoreCase))
                action = "View";
            
            var resource = string.Join("", resourceParts);
            return $"Require{resource}{action}";
        }
        
        // For simple permissions, preserve plural form (don't convert to singular)
        var fullResource = PermissionNameGenerator.ToPascalCase(parts[0]);
        var fullAction = PermissionNameGenerator.ToPascalCase(parts[1]);
        
        if (fullAction.Equals("Read", StringComparison.OrdinalIgnoreCase))
            fullAction = "View";
        
        return $"Require{fullResource}{fullAction}";
    }
    
    /// <summary>
    /// Gets resource name from permission for description.
    /// </summary>
    private static string GetResourceName(string permissionName)
    {
        var parts = permissionName.Split(':');
        if (parts.Length > 0)
            return parts[0].Replace("-", " ");
        return permissionName;
    }
    
    /// <summary>
    /// Returns default system policies that must always be present.
    /// These are non-permission-based policies used for authentication and authorization infrastructure.
    /// </summary>
    private static List<string> GetDefaultSystemPolicies()
    {
        return new List<string>
        {
            "    /// <summary>",
            "    /// Policy that requires admin role.",
            "    /// </summary>",
            "    public const string RequireAdminRole = \"RequireAdminRole\";",
            "",
            "    /// <summary>",
            "    /// Policy that requires product access (Admin or ProductManager roles).",
            "    /// </summary>",
            "    public const string RequireProductAccess = \"RequireProductAccess\";",
            "",
            "    /// <summary>",
            "    /// Policy that requires organization access (Admin role).",
            "    /// </summary>",
            "    public const string RequireOrganizationAccess = \"RequireOrganizationAccess\";",
            "",
            "    /// <summary>",
            "    /// Policy that requires organization context to be set.",
            "    /// </summary>",
            "    public const string RequireOrganizationContext = \"RequireOrganizationContext\";",
            "",
            "    /// <summary>",
            "    /// Policy that requires API key authentication.",
            "    /// </summary>",
            "    public const string RequireApiKey = \"RequireApiKey\";",
            "",
            "    /// <summary>",
            "    /// Policy that requires platform admin authentication (excludes multi-tenant users).",
            "    /// </summary>",
            "    public const string RequirePlatformAdmin = \"RequirePlatformAdmin\";",
            "",
            "    /// <summary>",
            "    /// Policy that accepts either platform admin or multi-tenant authentication.",
            "    /// Useful for endpoints that need to support both user types.",
            "    /// </summary>",
            "    public const string RequireAnyAuthentication = \"RequireAnyAuthentication\";",
            "",
            "    /// <summary>",
            "    /// Policy that accepts both regular JWT tokens (browser-initiated requests) and service account tokens (background services).",
            "    /// Used for service-to-service authentication via OAuth2 Client Credentials flow.",
            "    /// </summary>",
            "    public const string RequireServiceAccount = \"RequireServiceAccount\";",
            "",
            "    /// <summary>",
            "    /// Policy that requires discount approval permission.",
            "    /// Used for discount approval operations.",
            "    /// </summary>",
            "    public const string RequireApprovalApprove = \"RequireApprovalApprove\";",
            "",
            "    /// <summary>",
            "    /// Policy that requires discount approval reject permission.",
            "    /// Used for rejecting discount approvals.",
            "    /// </summary>",
            "    public const string RequireApprovalReject = \"RequireApprovalReject\";"
        };
    }
    
    /// <summary>
    /// Validates existing policies against naming conventions.
    /// Reports policies that don't follow the standard naming pattern.
    /// </summary>
    private static void ValidateExistingPolicies(string existingContent)
    {
        if (string.IsNullOrEmpty(existingContent))
            return;
        
        var lines = existingContent.Split('\n');
        var nonStandardPolicies = new List<string>();
        
        foreach (var line in lines)
        {
            if (line.Trim().StartsWith("public const string"))
            {
                var policyName = ExtractPolicyNameFromConstant(line);
                if (policyName != null)
                {
                    // Check if policy follows naming convention: Require{Resource}{Action}
                    // Exclude manual/system policies
                    var systemPolicies = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    {
                        "RequirePlatformAdmin", "RequireApiKey", "ServiceAccount",
                        "RequireAnyAuthentication", "RequireOrganizationContext",
                        "RequireOrganizationAccess", "RequiredAdminRole", "RequireProductAccess"
                    };
                    
                    if (!systemPolicies.Contains(policyName))
                    {
                        // Check if it follows the pattern
                        if (!policyName.StartsWith("Require", StringComparison.OrdinalIgnoreCase))
                        {
                            nonStandardPolicies.Add(policyName);
                        }
                    }
                }
            }
        }
        
        if (nonStandardPolicies.Count > 0)
        {
            Console.WriteLine($"ℹ️  Found {nonStandardPolicies.Count} existing policy(ies) that may not follow standard naming conventions:");
            foreach (var policy in nonStandardPolicies)
            {
                Console.WriteLine($"    - {policy}");
            }
        }
    }
}
