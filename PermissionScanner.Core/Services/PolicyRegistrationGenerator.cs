using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PermissionScanner.Core.Services;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Generates authorization policy registration code for Program.cs files.
/// </summary>
public class PolicyRegistrationGenerator
{
    /// <summary>
    /// Generates AddPolicy code for a missing policy registration.
    /// </summary>
    public string GeneratePolicyRegistrationCode(
        PolicyRegistrationAnalyzer.MissingPolicyRegistration missingPolicy,
        string? permissionConstantName = null)
    {
        var policyConstant = GetPolicyConstantReference(missingPolicy.PolicyName, missingPolicy.ServiceName);
        var permissionClaim = GetPermissionClaim(missingPolicy.PermissionName, permissionConstantName);

        // Generate the AddPolicy call
        var code = $@"    // Register permission-based authorization policy for {missingPolicy.PolicyName}
    options.AddPolicy({policyConstant},
        policy => policy.RequireClaim(""permission"", {permissionClaim}));";

        return code;
    }

    /// <summary>
    /// Generates all policy registration code for a service.
    /// </summary>
    public string GenerateAllPolicyRegistrations(
        List<PolicyRegistrationAnalyzer.MissingPolicyRegistration> missingPolicies,
        string serviceName,
        string? solutionPath = null)
    {
        if (!missingPolicies.Any())
            return string.Empty;

        var lines = new List<string>();
        lines.Add($"    // Register permission-based authorization policies for {serviceName}");
        
        // Build a cache of where policies are defined (PlatformServices vs service-specific)
        var policyLocationCache = solutionPath != null 
            ? BuildPolicyLocationCache(solutionPath) 
            : new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        
        // Build a cache of permission names to constant names from Permissions.cs files
        var permissionConstantCache = solutionPath != null
            ? BuildPermissionConstantCache(solutionPath)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        
        foreach (var policy in missingPolicies.OrderBy(p => p.PolicyName))
        {
            var policyConstant = GetPolicyConstantReference(policy.PolicyName, serviceName, policyLocationCache);
            var permissionClaim = GetPermissionClaim(policy.PermissionName, null, permissionConstantCache);
            
            lines.Add($"    options.AddPolicy({policyConstant},");
            lines.Add($"        policy => policy.RequireClaim(\"permission\", {permissionClaim}));");
            lines.Add(string.Empty);
        }

        return string.Join(Environment.NewLine, lines);
    }
    
    /// <summary>
    /// Builds a cache of policy locations (true = PlatformServices, false = service-specific).
    /// </summary>
    private Dictionary<string, bool> BuildPolicyLocationCache(string solutionPath)
    {
        var cache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        
        // Check PlatformServices first
        var platformServicesPath = Path.Combine(solutionPath, "Kronos.Sales.PlatformServices", "KS.PlatformServices", "Constants", "AuthorizationPolicies.cs");
        if (File.Exists(platformServicesPath))
        {
            var platformContent = File.ReadAllText(platformServicesPath);
            var platformPolicies = ExtractPolicyNames(platformContent);
            foreach (var policy in platformPolicies)
            {
                cache[policy] = true; // PlatformServices
            }
        }
        
        // Check service-specific files
        var servicePolicyFiles = Directory.GetFiles(solutionPath, "AuthorizationPolicies.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && 
                       !f.Contains("PlatformServices", StringComparison.OrdinalIgnoreCase))
            .ToList();
        
        foreach (var filePath in servicePolicyFiles)
        {
            var content = File.ReadAllText(filePath);
            var policies = ExtractPolicyNames(content);
            foreach (var policy in policies)
            {
                if (!cache.ContainsKey(policy))
                {
                    cache[policy] = false; // Service-specific
                }
            }
        }
        
        return cache;
    }
    
    /// <summary>
    /// Extracts policy constant names from AuthorizationPolicies.cs content.
    /// </summary>
    private HashSet<string> ExtractPolicyNames(string content)
    {
        var policies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        // Match: public const string PolicyName = "...";
        var pattern = @"public\s+const\s+string\s+(\w+)\s*=";
        var matches = Regex.Matches(content, pattern, RegexOptions.Multiline);
        
        foreach (Match match in matches)
        {
            if (match.Groups.Count > 1)
            {
                var policyName = match.Groups[1].Value;
                policies.Add(policyName);
            }
        }
        
        return policies;
    }

    /// <summary>
    /// Gets the policy constant reference (e.g., "KS.PlatformServices.Constants.AuthorizationPolicies.RequireWarehousView").
    /// </summary>
    private string GetPolicyConstantReference(string policyName, string serviceName, Dictionary<string, bool>? policyLocationCache = null)
    {
        // Check policy location cache first
        if (policyLocationCache != null && policyLocationCache.TryGetValue(policyName, out var isShared))
        {
            if (isShared)
            {
                return $"KS.PlatformServices.Constants.AuthorizationPolicies.{policyName}";
            }
            else
            {
                return $"KS.{serviceName}.Api.Constants.AuthorizationPolicies.{policyName}";
            }
        }

        // Fallback: Common shared policies (for backward compatibility)
        var sharedPolicies = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "RequireWarehousView",
            "RequireWarehousCreate",
            "RequireWarehousUpdate",
            "RequireWarehousDelete",
            "RequireAnyAuthentication",
            "RequireServiceAccount"
        };

        if (sharedPolicies.Contains(policyName))
        {
            return $"KS.PlatformServices.Constants.AuthorizationPolicies.{policyName}";
        }

        // Default to service-specific policy
        return $"KS.{serviceName}.Api.Constants.AuthorizationPolicies.{policyName}";
    }

    /// <summary>
    /// Gets the permission claim reference (e.g., "KS.PlatformServices.Constants.Permissions.WarehousesRead").
    /// </summary>
    private string GetPermissionClaim(string? permissionName, string? permissionConstantName, Dictionary<string, string>? permissionConstantCache = null)
    {
        if (!string.IsNullOrEmpty(permissionConstantName))
        {
            // Use provided constant name
            return $"KS.PlatformServices.Constants.Permissions.{permissionConstantName}";
        }

        // Try to look up the actual constant name from Permissions.cs files first
        if (!string.IsNullOrEmpty(permissionName) && permissionConstantCache != null && 
            permissionConstantCache.TryGetValue(permissionName, out var cachedConstantName))
        {
            return $"KS.PlatformServices.Constants.Permissions.{cachedConstantName}";
        }

        if (string.IsNullOrEmpty(permissionName))
        {
            // Fallback: generate from policy name
            // e.g., "RequireWarehousView" -> "WarehousesRead"
            var generated = GeneratePermissionConstantFromPolicy(permissionName ?? "Unknown");
            return $"KS.PlatformServices.Constants.Permissions.{generated}";
        }

        // Convert permission name to constant name
        // e.g., "warehouses:read" -> "WarehousesRead"
        var constantName = ConvertPermissionNameToConstant(permissionName);
        return $"KS.PlatformServices.Constants.Permissions.{constantName}";
    }
    
    /// <summary>
    /// Builds a cache mapping permission names (e.g., "packages:print-data:create") to constant names (e.g., "PackagesPrintDataCreate").
    /// </summary>
    private Dictionary<string, string> BuildPermissionConstantCache(string solutionPath)
    {
        var cache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        
        var permissionFiles = Directory.GetFiles(solutionPath, "Permissions.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/"))
            .ToList();
        
        foreach (var filePath in permissionFiles)
        {
            try
            {
                var content = File.ReadAllText(filePath);
                var lines = content.Split('\n');
                
                // Find all permission constants and their values
                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    
                    // Match: public const string ConstantName = "permission:name";
                    var constantMatch = Regex.Match(line, @"public\s+const\s+string\s+(\w+)\s*=\s*""([^""]+)"";");
                    if (constantMatch.Success && constantMatch.Groups.Count >= 3)
                    {
                        var constantName = constantMatch.Groups[1].Value;
                        var permissionName = constantMatch.Groups[2].Value;
                        
                        // Map permission name to constant name
                        if (!cache.ContainsKey(permissionName))
                        {
                            cache[permissionName] = constantName;
                        }
                    }
                }
            }
            catch
            {
                // Skip files that can't be parsed
                continue;
            }
        }
        
        return cache;
    }

    /// <summary>
    /// Converts permission name (e.g., "warehouses:read" or "auth:refresh:create") to constant name (e.g., "WarehousesRead" or "AuthRefreshCreate").
    /// </summary>
    private string ConvertPermissionNameToConstant(string permissionName)
    {
        if (string.IsNullOrEmpty(permissionName))
            return "Unknown";

        // Split by colon to get all parts
        var parts = permissionName.Split(':');
        
        // Convert each part to PascalCase and join them
        var constantParts = new List<string>();
        foreach (var part in parts)
        {
            if (string.IsNullOrEmpty(part))
                continue;
                
            // Split by hyphens/underscores and capitalize each word
            var subParts = part.Split('-', '_');
            var constantPart = string.Join("", subParts.Select(p => 
                char.ToUpper(p[0]) + (p.Length > 1 ? p.Substring(1) : "")));
            
            constantParts.Add(constantPart);
        }

        // Join all parts together (e.g., "auth:refresh:create" -> "AuthRefreshCreate")
        return string.Join("", constantParts);
    }

    /// <summary>
    /// Generates permission constant name from policy name as fallback.
    /// </summary>
    private string GeneratePermissionConstantFromPolicy(string policyName)
    {
        // Remove "Require" prefix and "View"/"Create"/"Update"/"Delete" suffix
        var name = policyName;
        if (name.StartsWith("Require", StringComparison.OrdinalIgnoreCase))
        {
            name = name.Substring(7); // Remove "Require"
        }

        // Handle common suffixes
        var suffixMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "View", "Read" },
            { "Create", "Create" },
            { "Update", "Update" },
            { "Delete", "Delete" },
            { "Manage", "Manage" }
        };

        foreach (var kvp in suffixMap)
        {
            if (name.EndsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
            {
                name = name.Substring(0, name.Length - kvp.Key.Length) + kvp.Value;
                break;
            }
        }

        return name;
    }

    /// <summary>
    /// Finds the insertion point in Program.cs for policy registrations using Roslyn.
    /// Returns the position where new policy registrations should be inserted (before the closing brace).
    /// </summary>
    public int FindInsertionPoint(string programContent)
    {
        try
        {
            // Parse the file using Roslyn
            var syntaxTree = CSharpSyntaxTree.ParseText(programContent);
            var root = syntaxTree.GetRoot();
            
            // Find AddAuthorization invocation - be very specific
            var addAuthorizationInvocations = root.DescendantNodes()
                .OfType<InvocationExpressionSyntax>()
                .Where(inv => IsAddAuthorizationInvocation(inv))
                .ToList();
            
            if (!addAuthorizationInvocations.Any())
            {
                // No AddAuthorization block found - try to find a good place to insert one
                // Look for AddMultiTenantPlatformServices or similar service registration
                var serviceRegistrations = root.DescendantNodes()
                    .OfType<InvocationExpressionSyntax>()
                    .Where(inv => 
                    {
                        var expr = inv.Expression.ToString();
                        return (expr.Contains("AddMultiTenantPlatformServices", StringComparison.OrdinalIgnoreCase) ||
                                expr.Contains("AddPlatformServices", StringComparison.OrdinalIgnoreCase)) &&
                               expr.Contains("builder.Services", StringComparison.OrdinalIgnoreCase);
                    })
                    .ToList();
                
                if (serviceRegistrations.Any())
                {
                    // Insert AddAuthorization block after the last service registration
                    var lastRegistration = serviceRegistrations.Last();
                    var insertPos = lastRegistration.GetLocation().SourceSpan.End;
                    
                    // Find the end of the statement (semicolon or newline)
                    while (insertPos < programContent.Length && 
                           programContent[insertPos] != ';' && 
                           !char.IsWhiteSpace(programContent[insertPos]))
                    {
                        insertPos++;
                    }
                    
                    // Skip to after the semicolon
                    if (insertPos < programContent.Length && programContent[insertPos] == ';')
                    {
                        insertPos++;
                    }
                    
                    // Skip whitespace and newlines
                    while (insertPos < programContent.Length && char.IsWhiteSpace(programContent[insertPos]))
                    {
                        insertPos++;
                    }
                    
                    // Return a special marker position that indicates we need to create the block
                    // We'll use a negative value to indicate this
                    return -insertPos;
                }
                
                // Fallback to regex if Roslyn parsing fails
                return FindInsertionPointFallback(programContent);
            }
            
            // Get the first AddAuthorization invocation
            var addAuthInvocation = addAuthorizationInvocations.First();
            
            // Find the lambda expression (the options => { ... } part)
            var lambda = addAuthInvocation.ArgumentList.Arguments
                .Select(arg => arg.Expression)
                .OfType<LambdaExpressionSyntax>()
                .FirstOrDefault();
            
            // Verify the lambda parameter is "options" (not something else like in JsonOptions)
            if (lambda is SimpleLambdaExpressionSyntax simpleLambda)
            {
                var parameterName = simpleLambda.Parameter.Identifier.ValueText;
                if (!parameterName.Equals("options", StringComparison.OrdinalIgnoreCase))
                {
                    // This is not the AddAuthorization block (might be JsonOptions or something else)
                    // Try to find another AddAuthorization or fallback
                    if (addAuthorizationInvocations.Count > 1)
                    {
                        // Try the next one
                        addAuthInvocation = addAuthorizationInvocations.Skip(1).FirstOrDefault();
                        if (addAuthInvocation != null)
                        {
                            lambda = addAuthInvocation.ArgumentList.Arguments
                                .Select(arg => arg.Expression)
                                .OfType<LambdaExpressionSyntax>()
                                .FirstOrDefault();
                            
                            // Re-check the parameter if we found a new lambda
                            if (lambda is SimpleLambdaExpressionSyntax newSimpleLambda)
                            {
                                var newParameterName = newSimpleLambda.Parameter.Identifier.ValueText;
                                if (!newParameterName.Equals("options", StringComparison.OrdinalIgnoreCase))
                                {
                                    // Still not the right one, fallback
                                    return FindInsertionPointFallback(programContent);
                                }
                            }
                        }
                    }
                    else
                    {
                        // Fallback to regex
                        return FindInsertionPointFallback(programContent);
                    }
                }
            }
            else if (lambda is ParenthesizedLambdaExpressionSyntax parenthesizedLambda)
            {
                // Multi-parameter lambda - check first parameter
                if (parenthesizedLambda.ParameterList.Parameters.Count > 0)
                {
                    var parameterName = parenthesizedLambda.ParameterList.Parameters[0].Identifier.ValueText;
                    if (!parameterName.Equals("options", StringComparison.OrdinalIgnoreCase))
                    {
                        // Fallback to regex
                        return FindInsertionPointFallback(programContent);
                    }
                }
            }
            
            if (lambda?.Body is BlockSyntax block)
            {
                // Additional validation: Check if this block contains AddPolicy calls
                // This ensures we're in the right block (AddAuthorization, not JsonOptions)
                var hasAddPolicy = block.DescendantNodes()
                    .OfType<InvocationExpressionSyntax>()
                    .Any(inv => 
                    {
                        if (inv.Expression is MemberAccessExpressionSyntax memberAccess)
                        {
                            return memberAccess.Name.Identifier.ValueText.Equals("AddPolicy", StringComparison.OrdinalIgnoreCase);
                        }
                        return false;
                    });
                
                if (!hasAddPolicy)
                {
                    // This block doesn't contain AddPolicy calls, might be wrong block
                    // Fallback to regex
                    return FindInsertionPointFallback(programContent);
                }
                
                // Find the last statement in the block
                var statements = block.Statements;
                if (statements.Any())
                {
                    var lastStatement = statements.Last();
                    
                    // Get the position after the last statement
                    var lastStatementEnd = lastStatement.GetLocation().SourceSpan.End;
                    
                    // Skip whitespace and newlines after the last statement
                    var insertPos = lastStatementEnd;
                    while (insertPos < block.CloseBraceToken.SpanStart && 
                           char.IsWhiteSpace(programContent[insertPos]))
                    {
                        insertPos++;
                    }
                    
                    // If we hit a newline, move past it
                    if (insertPos < block.CloseBraceToken.SpanStart && 
                        (programContent[insertPos] == '\r' || programContent[insertPos] == '\n'))
                    {
                        insertPos++;
                        if (insertPos < block.CloseBraceToken.SpanStart && 
                            programContent[insertPos - 1] == '\r' && 
                            programContent[insertPos] == '\n')
                        {
                            insertPos++;
                        }
                    }
                    
                    return insertPos;
                }
                else
                {
                    // Empty block, insert right after the opening brace
                    return block.OpenBraceToken.Span.End;
                }
            }
        }
        catch
        {
            // If Roslyn parsing fails, fall back to regex
        }
        
        return FindInsertionPointFallback(programContent);
    }
    
    /// <summary>
    /// Checks if an invocation is the AddAuthorization call we're looking for.
    /// Must be exactly: builder.Services.AddAuthorization(...)
    /// Excludes Configure&lt;T&gt; calls like Configure&lt;JsonOptions&gt;
    /// </summary>
    private bool IsAddAuthorizationInvocation(InvocationExpressionSyntax invocation)
    {
        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
            return false;
        
        // Check that the method name is AddAuthorization (not Configure or anything else)
        if (!memberAccess.Name.Identifier.ValueText.Equals("AddAuthorization", StringComparison.OrdinalIgnoreCase))
            return false;
        
        // Check that it's called on builder.Services (not builder.Services.Configure)
        if (memberAccess.Expression is not MemberAccessExpressionSyntax servicesAccess)
            return false;
        
        if (!servicesAccess.Name.Identifier.ValueText.Equals("Services", StringComparison.OrdinalIgnoreCase))
            return false;
        
        // Check that it starts with "builder"
        if (servicesAccess.Expression is not IdentifierNameSyntax identifier)
            return false;
        
        if (!identifier.Identifier.ValueText.Equals("builder", StringComparison.OrdinalIgnoreCase))
            return false;
        
        // Additional validation: Check that the parent is not a Configure call
        // This prevents matching Configure<JsonOptions>(options => { ... }) patterns
        var parent = invocation.Parent;
        while (parent != null)
        {
            if (parent is InvocationExpressionSyntax parentInvocation)
            {
                var parentExpr = parentInvocation.Expression.ToString();
                if (parentExpr.Contains("Configure", StringComparison.OrdinalIgnoreCase))
                {
                    return false; // This is inside a Configure call, not AddAuthorization
                }
            }
            parent = parent.Parent;
        }
        
        return true;
    }
    
    /// <summary>
    /// Fallback method using regex if Roslyn parsing fails.
    /// </summary>
    private int FindInsertionPointFallback(string programContent)
    {
        // Look for the closing brace of the AddAuthorization block using regex
        // Pattern: builder.Services.AddAuthorization(options => { ... });
        // Be very specific to avoid matching other similar patterns
        var addAuthPattern = @"builder\s*\.\s*Services\s*\.\s*AddAuthorization\s*\(\s*options\s*=>\s*\{";
        var match = Regex.Match(programContent, addAuthPattern, RegexOptions.Multiline | RegexOptions.IgnoreCase);
        
        if (match.Success)
        {
            var startPos = match.Index + match.Length;
            var braceCount = 1;
            var pos = startPos;
            
            // Find the matching closing brace
            while (pos < programContent.Length && braceCount > 0)
            {
                if (programContent[pos] == '{')
                    braceCount++;
                else if (programContent[pos] == '}')
                    braceCount--;
                
                if (braceCount == 0)
                {
                    // Verify this is followed by ');' (closing the AddAuthorization call)
                    var afterBrace = pos + 1;
                    while (afterBrace < programContent.Length && char.IsWhiteSpace(programContent[afterBrace]))
                    {
                        afterBrace++;
                    }
                    
                    // Check if we have ');' after the brace
                    if (afterBrace < programContent.Length - 1 && 
                        programContent[afterBrace] == ')' && 
                        programContent[afterBrace + 1] == ';')
                    {
                        // This is the correct closing brace for AddAuthorization
                        // Get content before it
                        var beforeBrace = programContent.Substring(startPos, pos - startPos);
                        
                        // Verify this block contains AddPolicy (to ensure it's the right block)
                        if (beforeBrace.Contains("AddPolicy", StringComparison.OrdinalIgnoreCase))
                        {
                            var lastSemicolon = beforeBrace.LastIndexOf(';');
                            if (lastSemicolon >= 0)
                            {
                                var absolutePos = startPos + lastSemicolon + 1;
                                while (absolutePos < pos && char.IsWhiteSpace(programContent[absolutePos]))
                                {
                                    absolutePos++;
                                }
                                return absolutePos;
                            }
                        }
                    }
                    
                    // If validation failed, continue searching
                    braceCount = 1; // Reset to continue searching
                    pos++;
                    continue;
                }
                pos++;
            }
        }
        
        // Last resort: find the last closing brace before app.RunAsync
        var runAsyncPos = programContent.IndexOf("app.RunAsync", StringComparison.OrdinalIgnoreCase);
        if (runAsyncPos > 0)
        {
            var beforeRunAsync = programContent.Substring(0, runAsyncPos);
            var lastBrace = beforeRunAsync.LastIndexOf('}');
            if (lastBrace > 0)
            {
                return lastBrace;
            }
        }
        
        // Final fallback
        var finalLastBrace = programContent.LastIndexOf('}');
        return finalLastBrace > 0 ? finalLastBrace : programContent.Length;
    }
}
