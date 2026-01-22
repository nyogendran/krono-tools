using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Service for replacing string literals with permission constants in code.
/// </summary>
public class LiteralReplacementService
{
    /// <summary>
    /// Applies replacements to files, replacing string literals with constants.
    /// </summary>
    public async Task<List<FileModificationResult>> ApplyReplacementsAsync(
        List<StringLiteralReference> references,
        bool dryRun)
    {
        var results = new List<FileModificationResult>();
        
        // Group by file
        var byFile = references.GroupBy(r => r.FilePath);

        foreach (var fileGroup in byFile)
        {
            var filePath = fileGroup.Key;
            var fileReferences = fileGroup.ToList();

            try
            {
                var result = await ReplaceInFileAsync(filePath, fileReferences, dryRun);
                results.Add(result);
            }
            catch (Exception ex)
            {
                results.Add(new FileModificationResult
                {
                    FilePath = filePath,
                    Success = false,
                    ErrorMessage = ex.Message,
                    ReplacementsCount = 0
                });
            }
        }

        return results;
    }

    private async Task<FileModificationResult> ReplaceInFileAsync(
        string filePath,
        List<StringLiteralReference> references,
        bool dryRun)
    {
        var content = await File.ReadAllTextAsync(filePath);
        var syntaxTree = CSharpSyntaxTree.ParseText(content);
        var root = await syntaxTree.GetRootAsync();

        var replacements = new List<(SyntaxNode Original, SyntaxNode Replacement)>();
        var usingStatements = new HashSet<string>();

        foreach (var reference in references)
        {
            // Find the literal in the syntax tree
            var literal = root.DescendantNodes()
                .OfType<LiteralExpressionSyntax>()
                .FirstOrDefault(l => l.Token.ValueText == reference.PermissionName &&
                                    l.GetLocation().GetLineSpan().StartLinePosition.Line + 1 == reference.LineNumber);

            if (literal == null)
                continue;

            // Create replacement: Permissions.ConstantName
            var constantName = reference.ConstantName;
            var replacement = SyntaxFactory.MemberAccessExpression(
                SyntaxKind.SimpleMemberAccessExpression,
                SyntaxFactory.IdentifierName("Permissions"),
                SyntaxFactory.IdentifierName(constantName));

            replacements.Add((literal, replacement));
            usingStatements.Add(reference.ConstantNamespace);
        }

        if (replacements.Count == 0)
        {
            return new FileModificationResult
            {
                FilePath = filePath,
                Success = true,
                ReplacementsCount = 0,
                Message = "No replacements needed"
            };
        }

        // Apply replacements
        var newRoot = root.ReplaceNodes(
            replacements.Select(r => r.Original),
            (original, _) => replacements.First(r => r.Original == original).Replacement);

        // Add using statements if needed
        newRoot = AddUsingStatementsIfNeeded(newRoot, usingStatements);

        var newContent = newRoot.ToFullString();

        if (!dryRun)
        {
            // Create backup
            var backupPath = filePath + ".backup." + DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            await File.WriteAllTextAsync(backupPath, content);

            // Write new content
            await File.WriteAllTextAsync(filePath, newContent);
        }

        return new FileModificationResult
        {
            FilePath = filePath,
            Success = true,
            ReplacementsCount = replacements.Count,
            Message = dryRun ? $"Would replace {replacements.Count} string literal(s)" : $"Replaced {replacements.Count} string literal(s)"
        };
    }

    private SyntaxNode AddUsingStatementsIfNeeded(SyntaxNode root, HashSet<string> namespaces)
    {
        if (namespaces.Count == 0)
            return root;

        if (root is not CompilationUnitSyntax compilationUnit)
            return root;

        var existingUsings = compilationUnit.Usings
            .Select(u => u.Name?.ToString() ?? string.Empty)
            .ToHashSet();

        var newUsings = new List<UsingDirectiveSyntax>();

        foreach (var ns in namespaces)
        {
            // Extract namespace without class name (e.g., "KS.PlatformServices.Constants" -> "KS.PlatformServices.Constants")
            var namespaceWithoutClass = ns;
            if (ns.Contains(".Constants"))
            {
                namespaceWithoutClass = ns.Substring(0, ns.LastIndexOf(".Constants"));
            }

            if (!existingUsings.Contains(namespaceWithoutClass) && !existingUsings.Contains(ns))
            {
                newUsings.Add(SyntaxFactory.UsingDirective(SyntaxFactory.ParseName(namespaceWithoutClass)));
            }
        }

        if (newUsings.Count > 0)
        {
            var allUsings = compilationUnit.Usings.AddRange(newUsings);
            return compilationUnit.WithUsings(allUsings);
        }

        return root;
    }
}

/// <summary>
/// Result of file modification.
/// </summary>
public class FileModificationResult
{
    /// <summary>
    /// Path to the modified file.
    /// </summary>
    public string FilePath { get; set; } = string.Empty;

    /// <summary>
    /// Whether the modification was successful.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Number of replacements made.
    /// </summary>
    public int ReplacementsCount { get; set; }

    /// <summary>
    /// Success or informational message.
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Error message if modification failed.
    /// </summary>
    public string? ErrorMessage { get; set; }
}
