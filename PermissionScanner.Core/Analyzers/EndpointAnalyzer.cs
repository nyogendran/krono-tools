using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Analyzers;

/// <summary>
/// Analyzes C# source code to discover Minimal API endpoints using Roslyn.
/// </summary>
public class EndpointAnalyzer
{

    /// <summary>
    /// Scans a solution directory for all C# files and discovers Minimal API endpoints.
    /// </summary>
    /// <param name="solutionPath">Path to solution directory or .sln file.</param>
    /// <returns>List of discovered endpoints.</returns>
    public async Task<List<DiscoveredEndpoint>> ScanSolutionAsync(string solutionPath)
    {
        var discoveredEndpoints = new List<DiscoveredEndpoint>();

        // Find all .cs files in Endpoints directories
        var endpointFiles = Directory.GetFiles(solutionPath, "*.cs", SearchOption.AllDirectories)
            .Where(f => f.Contains("Endpoints", StringComparison.OrdinalIgnoreCase) ||
                       f.Contains("Endpoint.cs", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var filePath in endpointFiles)
        {
            try
            {
                var endpoints = await AnalyzeFileAsync(filePath, solutionPath);
                discoveredEndpoints.AddRange(endpoints);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to analyze {filePath}: {ex.Message}");
            }
        }

        return discoveredEndpoints;
    }

    /// <summary>
    /// Analyzes a single C# file for Minimal API endpoints.
    /// </summary>
    private async Task<List<DiscoveredEndpoint>> AnalyzeFileAsync(string filePath, string solutionRoot)
    {
        var endpoints = new List<DiscoveredEndpoint>();

        // Read file content
        var sourceCode = await File.ReadAllTextAsync(filePath);
        
        // Parse C# syntax tree
        var syntaxTree = CSharpSyntaxTree.ParseText(sourceCode, path: filePath);
        var root = await syntaxTree.GetRootAsync();

        // Get service name from file path
        var serviceName = ExtractServiceName(filePath, solutionRoot);
        var relativePath = Path.GetRelativePath(solutionRoot, filePath).Replace('\\', '/');

        // Find all method calls to MapGet, MapPost, MapPut, MapPatch, MapDelete
        var methodCalls = root.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(IsMapMethod)
            .ToList();

        // Extract base route from MapGroup if present
        var baseRoute = ExtractBaseRoute(root, filePath);

        foreach (var methodCall in methodCalls)
        {
            try
            {
                var endpoint = ExtractEndpoint(methodCall, filePath, serviceName, relativePath, baseRoute, sourceCode);
                if (endpoint != null)
                {
                    endpoints.Add(endpoint);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to extract endpoint from {filePath}:{methodCall.GetLocation().GetLineSpan().StartLinePosition.Line}: {ex.Message}");
            }
        }

        return endpoints;
    }

    /// <summary>
    /// Checks if an invocation expression is a Map method (MapGet, MapPost, etc.).
    /// </summary>
    private bool IsMapMethod(InvocationExpressionSyntax invocation)
    {
        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
            return false;

        var methodName = memberAccess.Name.Identifier.ValueText;
        return methodName is "MapGet" or "MapPost" or "MapPut" or "MapPatch" or "MapDelete";
    }

    /// <summary>
    /// Extracts endpoint information from a Map method invocation.
    /// </summary>
    private DiscoveredEndpoint? ExtractEndpoint(
        InvocationExpressionSyntax methodCall,
        string filePath,
        string serviceName,
        string relativePath,
        string? baseRoute,
        string sourceCode)
    {
        // Get HTTP method from method name
        if (methodCall.Expression is not MemberAccessExpressionSyntax memberAccess)
            return null;

        var methodName = memberAccess.Name.Identifier.ValueText;
        var httpMethod = ExtractHttpMethod(methodName);

        // Get route template from first argument
        var routeTemplate = ExtractRouteTemplate(methodCall, baseRoute);

        // Get line number
        var lineSpan = methodCall.GetLocation().GetLineSpan();
        var lineNumber = lineSpan.StartLinePosition.Line + 1; // 1-based

        // Check for existing authorization policy
        var existingPolicy = ExtractExistingPolicy(methodCall);

        // Generate suggested permission and policy
        var (resource, action, permissionName) = PermissionNameGenerator.Generate(httpMethod, routeTemplate);
        var policyName = PermissionNameGenerator.GeneratePolicyName(permissionName);

        return new DiscoveredEndpoint
        {
            ServiceName = serviceName,
            FilePath = relativePath,
            LineNumber = lineNumber,
            HttpMethod = httpMethod,
            RouteTemplate = routeTemplate,
            ExistingPolicy = existingPolicy,
            SuggestedPermission = permissionName,
            SuggestedPolicy = policyName,
            Resource = resource,
            Action = action
        };
    }

    /// <summary>
    /// Extracts HTTP method from Map method name.
    /// </summary>
    private string ExtractHttpMethod(string methodName)
    {
        return methodName switch
        {
            "MapGet" => "GET",
            "MapPost" => "POST",
            "MapPut" => "PUT",
            "MapPatch" => "PATCH",
            "MapDelete" => "DELETE",
            _ => "UNKNOWN"
        };
    }

    /// <summary>
    /// Extracts route template from Map method invocation.
    /// </summary>
    private string ExtractRouteTemplate(InvocationExpressionSyntax methodCall, string? baseRoute)
    {
        // Get route from first argument (route string)
        if (methodCall.ArgumentList.Arguments.Count == 0)
            return baseRoute ?? "/";

        var firstArg = methodCall.ArgumentList.Arguments[0].Expression;

        // Handle string literal
        if (firstArg is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
        {
            var route = literal.Token.ValueText;
            if (!string.IsNullOrEmpty(baseRoute))
            {
                // Combine base route with endpoint route
                var combined = baseRoute.TrimEnd('/') + "/" + route.TrimStart('/');
                return combined;
            }
            return route;
        }

        // Handle interpolated string (less common, simplified)
        if (firstArg is InterpolatedStringExpressionSyntax interpolated)
        {
            var route = interpolated.Contents
                .OfType<InterpolatedStringTextSyntax>()
                .Select(t => t.TextToken.ValueText)
                .FirstOrDefault() ?? "/";
            
            if (!string.IsNullOrEmpty(baseRoute))
            {
                return baseRoute.TrimEnd('/') + "/" + route.TrimStart('/');
            }
            return route;
        }

        return baseRoute ?? "/";
    }

    /// <summary>
    /// Extracts base route from MapGroup calls in the file.
    /// </summary>
    private string? ExtractBaseRoute(SyntaxNode root, string filePath)
    {
        // Look for MapGroup calls
        var mapGroupCalls = root.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(IsMapGroupCall)
            .ToList();

        if (mapGroupCalls.Count == 0)
            return null;

        // Get the first MapGroup route (typically the base route for all endpoints in the file)
        var firstMapGroup = mapGroupCalls.First();
        if (firstMapGroup.ArgumentList.Arguments.Count == 0)
            return null;

        var routeArg = firstMapGroup.ArgumentList.Arguments[0].Expression;
        if (routeArg is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
        {
            return literal.Token.ValueText;
        }

        return null;
    }

    /// <summary>
    /// Checks if an invocation is a MapGroup call.
    /// </summary>
    private bool IsMapGroupCall(InvocationExpressionSyntax invocation)
    {
        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
            return false;

        return memberAccess.Name.Identifier.ValueText == "MapGroup";
    }

    /// <summary>
    /// Extracts existing authorization policy from RequireAuthorization call.
    /// </summary>
    private string? ExtractExistingPolicy(InvocationExpressionSyntax methodCall)
    {
        // Look for chained RequireAuthorization calls on the parent (methodCall might be chained)
        var parent = methodCall.Parent;
        while (parent != null)
        {
            if (parent is InvocationExpressionSyntax invocation)
            {
                if (invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                    memberAccess.Name.Identifier.ValueText == "RequireAuthorization")
                {
                    // Get policy name from argument
                    if (invocation.ArgumentList.Arguments.Count > 0)
                    {
                        var arg = invocation.ArgumentList.Arguments[0].Expression;
                        
                        // Handle string literal
                        if (arg is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
                        {
                            return literal.Token.ValueText;
                        }
                        
                        // Handle constant reference (e.g., AuthorizationPolicies.RequireProductCreate)
                        if (arg is MemberAccessExpressionSyntax constantRef)
                        {
                            // Extract the member name (e.g., "RequireProductCreate" from "AuthorizationPolicies.RequireProductCreate")
                            return constantRef.Name.Identifier.ValueText;
                        }
                    }
                }
            }
            
            parent = parent.Parent;
        }

        return null;
    }

    /// <summary>
    /// Extracts service name from file path.
    /// </summary>
    private string ExtractServiceName(string filePath, string solutionRoot)
    {
        var relativePath = Path.GetRelativePath(solutionRoot, filePath).Replace('\\', '/');
        
        // Extract service name from path like "Kronos.Sales.ProductService/..."
        var parts = relativePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        
        // Look for patterns like "Kronos.Sales.*Service" or "*Service"
        foreach (var part in parts)
        {
            if (part.Contains("Service", StringComparison.OrdinalIgnoreCase))
            {
                // Extract service name (e.g., "ProductService" from "Kronos.Sales.ProductService")
                var serviceParts = part.Split('.');
                var serviceName = serviceParts.LastOrDefault(s => s.Contains("Service", StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrEmpty(serviceName))
                {
                    return serviceName;
                }
            }
        }

        // Fallback: use directory name
        var directoryName = Path.GetDirectoryName(relativePath);
        return directoryName?.Split('/').LastOrDefault() ?? "UnknownService";
    }
}
