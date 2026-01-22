using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Finds code references using string literals instead of permission constants.
/// </summary>
public class StringLiteralFinder
{
    /// <summary>
    /// Finds all string literal references to permissions in the solution.
    /// </summary>
    public async Task<List<StringLiteralReference>> FindStringLiteralsAsync(
        string solutionPath,
        List<string> permissionNames)
    {
        var references = new List<StringLiteralReference>();
        var permissionSet = permissionNames.ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Find all .cs files
        var csFiles = Directory.GetFiles(solutionPath, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && 
                       !f.Contains("/Tests/") && !f.Contains("/tests/") &&
                       !f.EndsWith(".Tests.cs") && !f.EndsWith(".Test.cs"))
            .ToList();

        foreach (var filePath in csFiles)
        {
            try
            {
                var fileReferences = await AnalyzeFileForStringLiteralsAsync(filePath, permissionSet);
                references.AddRange(fileReferences);
            }
            catch
            {
                // Skip files that can't be parsed
                continue;
            }
        }

        return references;
    }

    private async Task<List<StringLiteralReference>> AnalyzeFileForStringLiteralsAsync(
        string filePath,
        HashSet<string> permissionNames)
    {
        var references = new List<StringLiteralReference>();
        var content = await File.ReadAllTextAsync(filePath);
        var syntaxTree = CSharpSyntaxTree.ParseText(content);
        var root = await syntaxTree.GetRootAsync();

        // Find string literals that match permission names
        var stringLiterals = root.DescendantNodes()
            .OfType<LiteralExpressionSyntax>()
            .Where(l => l.Kind() == SyntaxKind.StringLiteralExpression)
            .ToList();

        foreach (var literal in stringLiterals)
        {
            var literalValue = literal.Token.ValueText;
            
            // Check if this string literal matches a permission name
            if (permissionNames.Contains(literalValue))
            {
                // Skip string literals that are part of constant field declarations
                // (e.g., public const string Permission = "permission:name")
                if (IsPartOfConstantFieldDeclaration(literal))
                {
                    continue;
                }
                
                var location = literal.GetLocation();
                var lineSpan = location.GetLineSpan();
                
                // Get surrounding context
                var parent = literal.Parent;
                if (parent == null)
                    continue;
                    
                var context = GetContext(parent);
                var currentCode = GetCodeSnippet(parent, literal);
                var suggestedCode = GenerateSuggestedCode(parent, literal, literalValue);

                references.Add(new StringLiteralReference
                {
                    FilePath = filePath,
                    LineNumber = lineSpan.StartLinePosition.Line + 1,
                    ColumnNumber = lineSpan.StartLinePosition.Character + 1,
                    PermissionName = literalValue,
                    CurrentCode = currentCode,
                    SuggestedCode = suggestedCode,
                    Context = context,
                    ConstantName = PermissionNameGenerator.GenerateConstantName(literalValue),
                    ConstantNamespace = "KS.PlatformServices.Constants" // Default, can be refined
                });
            }
        }

        return references;
    }

    private string GetContext(SyntaxNode? node)
    {
        if (node == null)
            return "Unknown context";

        // Check for common permission check patterns
        if (node is InvocationExpressionSyntax invocation)
        {
            var methodName = invocation.Expression.ToString();
            if (methodName.Contains("HasPermission"))
                return "HasPermission call";
            if (methodName.Contains("HasAnyPermission"))
                return "HasAnyPermission call";
            if (methodName.Contains("HasAllPermissions"))
                return "HasAllPermissions call";
            if (methodName.Contains("RequireAuthorization"))
                return "RequireAuthorization call";
            if (methodName.Contains("RequirePermission"))
                return "RequirePermission call";
        }

        if (node is IfStatementSyntax)
            return "if statement";
        
        if (node is BinaryExpressionSyntax)
            return "comparison";
        
        if (node is ArgumentSyntax)
            return "method argument";

        return node.Kind().ToString();
    }

    private string GetCodeSnippet(SyntaxNode parent, SyntaxNode literal)
    {
        // Get a reasonable snippet of code around the literal
        var parentText = parent.ToString();
        
        // Limit to 100 characters
        if (parentText.Length > 100)
        {
            var index = parentText.IndexOf(literal.ToString());
            var start = Math.Max(0, index - 30);
            var length = Math.Min(100, parentText.Length - start);
            return parentText.Substring(start, length).Trim();
        }
        
        return parentText.Trim();
    }

    private string GenerateSuggestedCode(SyntaxNode parent, SyntaxNode literal, string permissionName)
    {
        var constantName = PermissionNameGenerator.GenerateConstantName(permissionName);
        var replacement = $"Permissions.{constantName}";
        
        // Replace the literal in the parent node
        var parentText = parent.ToString();
        var literalText = literal.ToString();
        
        // Handle both "permission:name" and 'permission:name' formats
        var literalPattern = Regex.Escape(literalText);
        var suggested = Regex.Replace(parentText, literalPattern, replacement, RegexOptions.IgnoreCase);
        
        return suggested.Trim();
    }

    /// <summary>
    /// Checks if a string literal is part of a constant field declaration.
    /// </summary>
    private bool IsPartOfConstantFieldDeclaration(LiteralExpressionSyntax literal)
    {
        // Walk up the syntax tree to find if this literal is part of a const field
        var node = literal.Parent;
        while (node != null)
        {
            // Check if we're in a FieldDeclaration
            if (node is FieldDeclarationSyntax fieldDeclaration)
            {
                // Check if the field has the 'const' modifier
                return fieldDeclaration.Modifiers.Any(m => m.IsKind(SyntaxKind.ConstKeyword));
            }
            
            node = node.Parent;
        }
        
        return false;
    }
}
