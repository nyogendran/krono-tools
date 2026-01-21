using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Analyzers;

/// <summary>
/// Analyzes C# source code to discover references to permission and policy constants.
/// This ensures constants referenced in code (but not discovered from endpoints) are generated.
/// </summary>
public class ConstantReferenceAnalyzer
{
    /// <summary>
    /// Scans solution for constant references and returns missing permissions/policies.
    /// </summary>
    public async Task<(List<PermissionDefinition> MissingPermissions, List<PolicyDefinition> MissingPolicies)> 
        ScanForConstantReferencesAsync(string solutionPath)
    {
        var missingPermissions = new Dictionary<string, PermissionDefinition>();
        var missingPolicies = new Dictionary<string, PolicyDefinition>();

        // Find all .cs files (not just Endpoints)
        var allCsFiles = Directory.GetFiles(solutionPath, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/"))
            .ToList();

        foreach (var filePath in allCsFiles)
        {
            try
            {
                var (perms, policies) = await AnalyzeFileForConstantsAsync(filePath, solutionPath);
                
                foreach (var perm in perms)
                {
                    if (!missingPermissions.ContainsKey(perm.PermissionName))
                    {
                        missingPermissions[perm.PermissionName] = perm;
                    }
                }
                
                foreach (var policy in policies)
                {
                    if (!missingPolicies.ContainsKey(policy.PolicyName))
                    {
                        missingPolicies[policy.PolicyName] = policy;
                    }
                }
            }
            catch (Exception ex)
            {
                // Silently skip files that can't be parsed
                Console.WriteLine($"Warning: Failed to analyze {filePath} for constants: {ex.Message}");
            }
        }

        return (missingPermissions.Values.ToList(), missingPolicies.Values.ToList());
    }

    /// <summary>
    /// Analyzes a single file for constant references.
    /// </summary>
    private async Task<(List<PermissionDefinition> Permissions, List<PolicyDefinition> Policies)> 
        AnalyzeFileForConstantsAsync(string filePath, string solutionRoot)
    {
        var permissions = new List<PermissionDefinition>();
        var policies = new List<PolicyDefinition>();

        var sourceCode = await File.ReadAllTextAsync(filePath);
        var syntaxTree = CSharpSyntaxTree.ParseText(sourceCode, path: filePath);
        var root = await syntaxTree.GetRootAsync();

        // Get service name from file path
        var serviceName = ExtractServiceName(filePath, solutionRoot);

        // Extract using statements to determine namespace context
        var usingStatements = ExtractUsingStatements(root);
        var hasPlatformServicesUsing = usingStatements.Any(u => 
            u.Contains("KS.PlatformServices.Constants", StringComparison.OrdinalIgnoreCase));

        // Find all member access expressions (e.g., Permissions.InventoryReadWithCost, AuthorizationPolicies.RequireApprovalView)
        var memberAccesses = root.DescendantNodes()
            .OfType<MemberAccessExpressionSyntax>()
            .ToList();

        foreach (var memberAccess in memberAccesses)
        {
            // Check for Permissions.{ConstantName}
            if (IsPermissionsAccess(memberAccess, out var permissionName, out var isFullyQualified))
            {
                // Determine target namespace based on using statements and fully qualified names
                var targetNamespace = DetermineTargetNamespace(memberAccess, hasPlatformServicesUsing, serviceName, isFullyQualified);
                var perm = CreatePermissionFromReference(permissionName, targetNamespace, filePath);
                if (perm != null)
                {
                    permissions.Add(perm);
                }
            }

            // Check for AuthorizationPolicies.{ConstantName}
            if (IsAuthorizationPoliciesAccess(memberAccess, out var policyName, out var isPolicyFullyQualified))
            {
                // Determine target namespace based on using statements and fully qualified names
                var targetNamespace = DetermineTargetNamespace(memberAccess, hasPlatformServicesUsing, serviceName, isPolicyFullyQualified);
                var policy = CreatePolicyFromReference(policyName, targetNamespace, filePath);
                if (policy != null)
                {
                    policies.Add(policy);
                }
            }
        }

        return (permissions, policies);
    }

    /// <summary>
    /// Extracts using statements from the syntax tree.
    /// </summary>
    private List<string> ExtractUsingStatements(SyntaxNode root)
    {
        var usings = new List<string>();
        
        var usingDirectives = root.DescendantNodes()
            .OfType<UsingDirectiveSyntax>()
            .ToList();

        foreach (var usingDirective in usingDirectives)
        {
            if (usingDirective.Name != null)
            {
                usings.Add(usingDirective.Name.ToString());
            }
        }

        return usings;
    }

    /// <summary>
    /// Determines the target namespace for a constant reference.
    /// Returns "PlatformServices" if it's a PlatformServices constant, otherwise the service name.
    /// </summary>
    private string DetermineTargetNamespace(MemberAccessExpressionSyntax memberAccess, bool hasPlatformServicesUsing, string serviceName, bool isFullyQualified)
    {
        // If fully qualified, extract namespace from the full path
        if (isFullyQualified)
        {
            var current = memberAccess.Expression;
            var parts = new List<string>();

            while (current is MemberAccessExpressionSyntax nested)
            {
                parts.Insert(0, nested.Name.Identifier.ValueText);
                current = nested.Expression;
            }

            if (current is IdentifierNameSyntax identifier)
            {
                parts.Insert(0, identifier.Identifier.ValueText);
            }

            var fullPath = string.Join(".", parts);
            
            // If fully qualified and contains PlatformServices, it's PlatformServices
            if (fullPath.Contains("PlatformServices", StringComparison.OrdinalIgnoreCase))
            {
                return "PlatformServices";
            }

            // If fully qualified and contains service namespace, extract service name
            // e.g., KS.SalesService.Api.Constants -> SalesService
            var serviceMatch = System.Text.RegularExpressions.Regex.Match(fullPath, @"KS\.(\w+Service)\.Api\.Constants", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (serviceMatch.Success)
            {
                return serviceMatch.Groups[1].Value;
            }
        }

        // If using statement has PlatformServices and it's not fully qualified, it's PlatformServices
        if (hasPlatformServicesUsing && !isFullyQualified)
        {
            return "PlatformServices";
        }

        // Otherwise, it's service-specific
        return serviceName;
    }

    /// <summary>
    /// Checks if a member access is accessing Permissions.{ConstantName}.
    /// </summary>
    private bool IsPermissionsAccess(MemberAccessExpressionSyntax memberAccess, out string constantName, out bool isFullyQualified)
    {
        constantName = string.Empty;
        isFullyQualified = false;

        // Pattern: Permissions.{ConstantName}
        if (memberAccess.Expression is IdentifierNameSyntax identifier &&
            identifier.Identifier.ValueText == "Permissions")
        {
            constantName = memberAccess.Name.Identifier.ValueText;
            isFullyQualified = false;
            return true;
        }

        // Pattern: KS.PlatformServices.Constants.Permissions.{ConstantName} or KS.{Service}.Api.Constants.Permissions.{ConstantName}
        if (memberAccess.Expression is MemberAccessExpressionSyntax nestedAccess &&
            nestedAccess.Name.Identifier.ValueText == "Permissions")
        {
            constantName = memberAccess.Name.Identifier.ValueText;
            isFullyQualified = true;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Checks if a member access is accessing AuthorizationPolicies.{ConstantName}.
    /// </summary>
    private bool IsAuthorizationPoliciesAccess(MemberAccessExpressionSyntax memberAccess, out string constantName, out bool isFullyQualified)
    {
        constantName = string.Empty;
        isFullyQualified = false;

        // Pattern: AuthorizationPolicies.{ConstantName}
        if (memberAccess.Expression is IdentifierNameSyntax identifier &&
            identifier.Identifier.ValueText == "AuthorizationPolicies")
        {
            constantName = memberAccess.Name.Identifier.ValueText;
            isFullyQualified = false;
            return true;
        }

        // Pattern: KS.PlatformServices.Constants.AuthorizationPolicies.{ConstantName} or KS.{Service}.Api.Constants.AuthorizationPolicies.{ConstantName}
        if (memberAccess.Expression is MemberAccessExpressionSyntax nestedAccess &&
            nestedAccess.Name.Identifier.ValueText == "AuthorizationPolicies")
        {
            constantName = memberAccess.Name.Identifier.ValueText;
            isFullyQualified = true;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Creates a PermissionDefinition from a constant reference.
    /// </summary>
    private PermissionDefinition? CreatePermissionFromReference(string constantName, string targetNamespace, string filePath)
    {
        // Convert constant name to permission name
        // e.g., "InventoryReadWithCost" -> "inventory:read-with-cost"
        var permissionName = ConvertConstantNameToPermissionName(constantName);
        
        if (string.IsNullOrEmpty(permissionName))
            return null;

        // Extract resource and action
        var parts = permissionName.Split(':');
        var resource = parts.Length > 0 ? parts[0] : string.Empty;
        var action = parts.Length > 1 ? string.Join(":", parts.Skip(1)) : "read";

        return new PermissionDefinition
        {
            PermissionName = permissionName,
            Resource = resource,
            Action = action,
            ConstantName = constantName,
            Domain = PermissionNameGenerator.DetermineDomain(resource),
            Endpoints = new List<string> { $"Referenced in: {Path.GetFileName(filePath)}" },
            Description = GenerateDescriptionFromConstantName(constantName),
            Services = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { targetNamespace },
            Scope = targetNamespace == "PlatformServices" ? "Shared" : "ServiceSpecific" // Will be reclassified later if needed
        };
    }

    /// <summary>
    /// Creates a PolicyDefinition from a constant reference.
    /// </summary>
    private PolicyDefinition? CreatePolicyFromReference(string constantName, string targetNamespace, string filePath)
    {
        // Convert policy constant name to permission name
        // e.g., "RequireApprovalView" -> "approvals:read" or "approval:view"
        var permissionName = ConvertPolicyNameToPermissionName(constantName);
        
        if (string.IsNullOrEmpty(permissionName))
            return null;

        return new PolicyDefinition
        {
            PolicyName = constantName,
            RequiredPermission = permissionName,
            Description = $"Policy referenced in code: {Path.GetFileName(filePath)}",
            Domain = PermissionNameGenerator.DetermineDomain(permissionName.Split(':')[0])
        };
    }

    /// <summary>
    /// Converts constant name to permission name.
    /// Examples:
    /// - "InventoryReadWithCost" -> "inventory:read-with-cost"
    /// - "ProductsCreate" -> "products:create"
    /// - "ApprovalsView" -> "approvals:view"
    /// </summary>
    private string ConvertConstantNameToPermissionName(string constantName)
    {
        if (string.IsNullOrEmpty(constantName))
            return string.Empty;

        // Handle special cases (qualified permissions and known constants)
        var specialCases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "InventoryReadWithCost", "inventory:read-with-cost" },
            { "DiscountApprovalsView", "discount-approvals:view" },
            { "DiscountApprovalsApprove", "discount-approvals:approve" },
            { "DiscountApprovalsReject", "discount-approvals:reject" }
        };

        if (specialCases.TryGetValue(constantName, out var specialCase))
        {
            return specialCase;
        }

        // Convert PascalCase to kebab-case with colon separator
        // Split on capital letters
        var words = Regex.Split(constantName, @"(?<!^)(?=[A-Z])");
        
        if (words.Length < 2)
            return string.Empty;

        var resource = words[0].ToLowerInvariant();
        var actionParts = words.Skip(1).Select(w => w.ToLowerInvariant());
        var action = string.Join("-", actionParts);

        // Map common action patterns
        action = action switch
        {
            "read" or "view" => "read",
            "create" => "create",
            "update" => "update",
            "delete" => "delete",
            "approve" => "approve",
            "reject" => "reject",
            _ => action
        };

        return $"{resource}:{action}";
    }

    /// <summary>
    /// Converts policy name to permission name.
    /// Examples:
    /// - "RequireApprovalView" -> "approvals:read" or "approval:view"
    /// - "RequireProductCreate" -> "products:create"
    /// </summary>
    private string ConvertPolicyNameToPermissionName(string policyName)
    {
        if (string.IsNullOrEmpty(policyName) || !policyName.StartsWith("Require", StringComparison.OrdinalIgnoreCase))
            return string.Empty;

        // Remove "Require" prefix
        var withoutRequire = policyName.Substring("Require".Length);

        // Handle special cases (policy name to permission name mappings)
        var specialCases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "ApprovalView", "approvals:read" },
            { "ApprovalApprove", "approvals:approve" },
            { "ApprovalApproveApprove", "approvals:approve:approve" }
        };

        if (specialCases.TryGetValue(withoutRequire, out var specialCase))
        {
            return specialCase;
        }

        // Convert to permission name
        return ConvertConstantNameToPermissionName(withoutRequire);
    }

    /// <summary>
    /// Generates description from constant name.
    /// </summary>
    private string GenerateDescriptionFromConstantName(string constantName)
    {
        // Convert PascalCase to readable text
        var words = Regex.Split(constantName, @"(?<!^)(?=[A-Z])");
        return string.Join(" ", words).ToLowerInvariant();
    }

    /// <summary>
    /// Extracts service name from file path.
    /// </summary>
    private string ExtractServiceName(string filePath, string solutionRoot)
    {
        var relativePath = Path.GetRelativePath(solutionRoot, filePath).Replace('\\', '/');
        var parts = relativePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        
        foreach (var part in parts)
        {
            if (part.Contains("Service", StringComparison.OrdinalIgnoreCase))
            {
                var serviceParts = part.Split('.');
                var serviceName = serviceParts.LastOrDefault(s => s.Contains("Service", StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrEmpty(serviceName))
                {
                    return serviceName;
                }
            }
        }

        return "UnknownService";
    }
}
