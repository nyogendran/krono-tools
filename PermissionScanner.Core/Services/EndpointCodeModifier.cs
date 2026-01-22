using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Models;
using PermissionScanner.Core.Services;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Modifies endpoint code to add RequireAuthorization calls using Roslyn.
/// </summary>
public class EndpointCodeModifier
{
    /// <summary>
    /// Modifies an endpoint file to add RequireAuthorization calls for endpoints that need policies.
    /// </summary>
    /// <param name="filePath">Path to the endpoint file.</param>
    /// <param name="suggestions">List of policy suggestions for endpoints in this file.</param>
    /// <param name="solutionPath">Path to solution root (for relative paths).</param>
    /// <returns>Modified file content and list of changes made.</returns>
    public async Task<(string ModifiedContent, List<CodeModification> Modifications)> ModifyFileAsync(
        string filePath,
        List<EndpointPolicySuggestion> suggestions,
        string solutionPath)
    {
        if (!suggestions.Any())
        {
            return (await File.ReadAllTextAsync(filePath), new List<CodeModification>());
        }

        var sourceCode = await File.ReadAllTextAsync(filePath);
        var syntaxTree = CSharpSyntaxTree.ParseText(sourceCode, path: filePath);
        var root = await syntaxTree.GetRootAsync();

        var modifications = new List<CodeModification>();
        var usingStatements = ExtractUsingStatements(root);
        var needsUsingStatement = false;
        string? requiredNamespace = null;

        // Group suggestions by line number for efficient processing
        var suggestionsByLine = suggestions
            .Where(s => s.Endpoint.FilePath == filePath || 
                       Path.GetRelativePath(solutionPath, filePath).Replace('\\', '/') == s.Endpoint.FilePath)
            .GroupBy(s => s.Endpoint.LineNumber)
            .ToDictionary(g => g.Key, g => g.First());

        // Find all Map method calls
        var mapMethodCalls = root.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(IsMapMethod)
            .ToList();

        // Process each map method call
        foreach (var methodCall in mapMethodCalls)
        {
            var lineSpan = syntaxTree.GetLineSpan(methodCall.Span);
            var lineNumber = lineSpan.StartLinePosition.Line + 1;

            if (!suggestionsByLine.TryGetValue(lineNumber, out var suggestion))
                continue;

            // Check if RequireAuthorization already exists
            if (HasRequireAuthorization(methodCall))
                continue;

            // Determine the correct policy reference
            var policyReference = BuildPolicyReference(
                suggestion.SuggestedPolicy,
                usingStatements,
                suggestion.RequiresUsingStatement,
                out var needsUsing);

            if (needsUsing && !needsUsingStatement)
            {
                needsUsingStatement = true;
                // Extract namespace without the class name (e.g., "KS.PlatformServices.Constants.AuthorizationPolicies" -> "KS.PlatformServices.Constants")
                var fullNamespace = suggestion.SuggestedPolicy.Location.Namespace;
                if (fullNamespace.Contains(".AuthorizationPolicies"))
                {
                    requiredNamespace = fullNamespace.Substring(0, fullNamespace.LastIndexOf(".AuthorizationPolicies"));
                }
                else if (fullNamespace.Contains(".Permissions"))
                {
                    requiredNamespace = fullNamespace.Substring(0, fullNamespace.LastIndexOf(".Permissions"));
                }
                else
                {
                    requiredNamespace = fullNamespace;
                }
            }

            // Find the insertion point (before the last fluent method call)
            var insertionPoint = FindInsertionPoint(methodCall);
            if (insertionPoint == null)
                continue;

            modifications.Add(new CodeModification
            {
                LineNumber = lineNumber,
                PolicyName = suggestion.SuggestedPolicy.PolicyName,
                PolicyReference = policyReference,
                InsertionPoint = insertionPoint.Value,
                RequiresUsingStatement = needsUsing && !HasUsingForNamespace(usingStatements, requiredNamespace ?? suggestion.SuggestedPolicy.Location.Namespace)
            });
        }

        // Apply modifications
        var modifiedContent = ApplyModifications(sourceCode, modifications, usingStatements, requiredNamespace);

        return (modifiedContent, modifications);
    }

    /// <summary>
    /// Checks if an invocation is a Map method (MapGet, MapPost, etc.).
    /// </summary>
    private bool IsMapMethod(InvocationExpressionSyntax invocation)
    {
        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
            return false;

        var methodName = memberAccess.Name.Identifier.ValueText;
        return methodName is "MapGet" or "MapPost" or "MapPut" or "MapPatch" or "MapDelete";
    }

    /// <summary>
    /// Checks if a method call already has RequireAuthorization.
    /// </summary>
    private bool HasRequireAuthorization(InvocationExpressionSyntax methodCall)
    {
        var parent = methodCall.Parent;
        while (parent != null)
        {
            if (parent is InvocationExpressionSyntax invocation)
            {
                if (invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                    memberAccess.Name.Identifier.ValueText == "RequireAuthorization")
                {
                    return true;
                }
            }
            parent = parent.Parent;
        }
        return false;
    }

    /// <summary>
    /// Finds the insertion point for RequireAuthorization (before the last fluent method call).
    /// </summary>
    private int? FindInsertionPoint(InvocationExpressionSyntax methodCall)
    {
        // Find the last chained method call
        var current = methodCall;
        while (current.Parent is InvocationExpressionSyntax parentInvocation)
        {
            current = parentInvocation;
        }

        // Insert before the last method call's closing parenthesis
        return current.Span.End;
    }

    /// <summary>
    /// Builds the policy reference string (short form or fully qualified).
    /// </summary>
    private string BuildPolicyReference(
        PolicyResolution policyResolution,
        List<string> usingStatements,
        bool requiresUsing,
        out bool needsUsingStatement)
    {
        needsUsingStatement = false;

        var policyName = policyResolution.PolicyName;
        var namespacePath = policyResolution.Location.Namespace;

        // Check if there's ambiguity (both service-specific and PlatformServices using statements)
        var hasServiceConstants = usingStatements.Any(u => 
            u.Contains(".Api.Constants", StringComparison.OrdinalIgnoreCase) &&
            !u.Contains("PlatformServices", StringComparison.OrdinalIgnoreCase));
        var hasPlatformServices = usingStatements.Any(u => 
            u.Contains("PlatformServices.Constants", StringComparison.OrdinalIgnoreCase));
        
        var isAmbiguous = hasServiceConstants && hasPlatformServices;

        // Check if using statement exists for the target namespace
        var hasUsing = HasUsingForNamespace(usingStatements, namespacePath);

        if (hasUsing && !isAmbiguous)
        {
            // Use short form: AuthorizationPolicies.RequireProductCreate
            return $"AuthorizationPolicies.{policyName}";
        }
        else
        {
            // Use fully qualified form (either no using statement, or ambiguous)
            needsUsingStatement = requiresUsing && !hasUsing;
            return $"{namespacePath}.{policyName}";
        }
    }

    /// <summary>
    /// Checks if a using statement exists for the given namespace.
    /// </summary>
    private bool HasUsingForNamespace(List<string> usingStatements, string namespacePath)
    {
        // Extract namespace without class name if present
        var namespaceOnly = namespacePath;
        if (namespacePath.Contains(".AuthorizationPolicies"))
        {
            namespaceOnly = namespacePath.Substring(0, namespacePath.LastIndexOf(".AuthorizationPolicies"));
        }
        else if (namespacePath.Contains(".Permissions"))
        {
            namespaceOnly = namespacePath.Substring(0, namespacePath.LastIndexOf(".Permissions"));
        }
        
        // Check for exact match or parent namespace
        return usingStatements.Any(u => 
            u.Equals(namespaceOnly, StringComparison.OrdinalIgnoreCase) ||
            namespaceOnly.StartsWith(u + ".", StringComparison.OrdinalIgnoreCase) ||
            u.Equals(namespacePath, StringComparison.OrdinalIgnoreCase) ||
            namespacePath.StartsWith(u + ".", StringComparison.OrdinalIgnoreCase));
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
            var name = usingDirective.Name?.ToString() ?? "";
            if (!string.IsNullOrEmpty(name))
            {
                usings.Add(name);
            }
        }

        return usings;
    }

    /// <summary>
    /// Applies modifications to the source code.
    /// </summary>
    private string ApplyModifications(
        string sourceCode,
        List<CodeModification> modifications,
        List<string> usingStatements,
        string? requiredNamespace)
    {
        if (!modifications.Any() && string.IsNullOrEmpty(requiredNamespace))
        {
            return sourceCode;
        }

        var sb = new StringBuilder(sourceCode);

        // Sort modifications by insertion point (descending) to maintain positions
        var sortedModifications = modifications
            .OrderByDescending(m => m.InsertionPoint)
            .ToList();

        // Apply RequireAuthorization insertions
        foreach (var modification in sortedModifications)
        {
            var insertionPoint = modification.InsertionPoint;
            var requireAuthCall = $"\n            .RequireAuthorization({modification.PolicyReference})";

            // Find the position to insert (before the last method call)
            // We need to find the end of the last chained method call
            var insertPosition = FindActualInsertionPosition(sourceCode, insertionPoint);
            
            if (insertPosition >= 0 && insertPosition <= sb.Length)
            {
                sb.Insert(insertPosition, requireAuthCall);
            }
        }

        // Add using statement if needed
        if (!string.IsNullOrEmpty(requiredNamespace) && 
            !HasUsingForNamespace(usingStatements, requiredNamespace))
        {
            var usingStatement = $"using {requiredNamespace};\n";
            
            // Find the last using statement
            var lastUsingIndex = FindLastUsingStatementIndex(sourceCode);
            if (lastUsingIndex >= 0)
            {
                // Insert after the last using statement
                var insertAfter = sourceCode.IndexOf('\n', lastUsingIndex);
                if (insertAfter >= 0)
                {
                    sb.Insert(insertAfter + 1, usingStatement);
                }
            }
            else
            {
                // Insert at the beginning of the file (after namespace declaration if present)
                var namespaceIndex = sourceCode.IndexOf("namespace ");
                if (namespaceIndex >= 0)
                {
                    var namespaceEnd = sourceCode.IndexOf('\n', namespaceIndex);
                    if (namespaceEnd >= 0)
                    {
                        sb.Insert(namespaceEnd + 1, usingStatement);
                    }
                }
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Finds the actual insertion position in the source code.
    /// </summary>
    private int FindActualInsertionPosition(string sourceCode, int spanEnd)
    {
        // Find the end of the last method call before the closing parenthesis or semicolon
        var position = Math.Min(spanEnd, sourceCode.Length - 1);
        
        // Look backwards for the end of the last fluent method call
        while (position > 0 && 
               sourceCode[position] != ')' && 
               sourceCode[position] != ';' &&
               sourceCode[position] != '\n')
        {
            position--;
        }

        // If we found a closing parenthesis, insert before it
        if (position > 0 && sourceCode[position] == ')')
        {
            return position;
        }

        // Otherwise, use the span end
        return spanEnd;
    }

    /// <summary>
    /// Finds the index of the last using statement in the source code.
    /// </summary>
    private int FindLastUsingStatementIndex(string sourceCode)
    {
        var lastIndex = -1;
        var index = 0;

        while ((index = sourceCode.IndexOf("using ", index, StringComparison.Ordinal)) >= 0)
        {
            lastIndex = index;
            index += 6; // Move past "using "
        }

        return lastIndex;
    }
}

/// <summary>
/// Represents a code modification to be applied.
/// </summary>
public class CodeModification
{
    /// <summary>
    /// Line number where the modification will be applied.
    /// </summary>
    public int LineNumber { get; set; }

    /// <summary>
    /// Policy name being applied.
    /// </summary>
    public string PolicyName { get; set; } = string.Empty;

    /// <summary>
    /// Policy reference string (e.g., "AuthorizationPolicies.RequireProductCreate").
    /// </summary>
    public string PolicyReference { get; set; } = string.Empty;

    /// <summary>
    /// Character position where the modification will be inserted.
    /// </summary>
    public int InsertionPoint { get; set; }

    /// <summary>
    /// Whether a using statement needs to be added.
    /// </summary>
    public bool RequiresUsingStatement { get; set; }
}
