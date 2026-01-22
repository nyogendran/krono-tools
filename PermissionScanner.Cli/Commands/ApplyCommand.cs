using System.Text;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Models;
using PermissionScanner.Core.Services;

namespace PermissionScanner.Cli.Commands;

/// <summary>
/// Command to apply generated permissions and policies to endpoints and Program.cs.
/// Fixes namespace mismatches and ensures correct constant usage.
/// </summary>
public class ApplyCommand
{
    public static async Task<int> ExecuteAsync(
        string solutionPath,
        string platformServicesPath,
        bool dryRun,
        bool applyEndpoints,
        bool applyPolicies,
        bool migrateApiConstants,
        bool applyPoliciesToEndpoints,
        string? excludePaths,
        string? defaultPolicy)
    {
        try
        {
            Console.WriteLine("🔍 Analyzing solution for namespace mismatches and policy issues...");
            Console.WriteLine();

            // Scan for endpoints and code references
            var endpointAnalyzer = new EndpointAnalyzer();
            var endpoints = await endpointAnalyzer.ScanSolutionAsync(solutionPath);
            
            var constantAnalyzer = new ConstantReferenceAnalyzer();
            var (codeReferencedPermissions, codeReferencedPolicies) = await constantAnalyzer.ScanForConstantReferencesAsync(solutionPath);

            // Read existing constants to understand what should exist where
            var (existingPermissions, existingPolicies) = await ReadExistingConstantsAsync(solutionPath, platformServicesPath);

            // Find all files that need fixing
            var fixes = new List<FileFix>();

            // Apply policies to endpoints if requested
            if (applyPoliciesToEndpoints)
            {
                Console.WriteLine("🔍 Analyzing endpoints for missing authorization policies...");
                Console.WriteLine();

                // Build exclusion matcher
                var customExclusions = new List<string>();
                if (!string.IsNullOrEmpty(excludePaths))
                {
                    customExclusions = excludePaths.Split(',', StringSplitOptions.RemoveEmptyEntries)
                        .Select(p => p.Trim())
                        .ToList();
                }
                var exclusionMatcher = new EndpointExclusionMatcher(customExclusions);

                // Build policy location map
                var policyLocationDict = new Dictionary<string, ApplyCommandPolicyLocation>();
                foreach (var kvp in existingPolicies)
                {
                    policyLocationDict[kvp.Key] = new ApplyCommandPolicyLocation
                    {
                        IsShared = kvp.Value.IsShared,
                        ServiceName = kvp.Value.ServiceName
                    };
                }
                var policyLocationMap = PolicyLocationBuilder.BuildPolicyLocationMap(policyLocationDict);

                // Group endpoints by service and analyze
                var endpointsByService = endpoints.GroupBy(e => e.ServiceName).ToList();
                var endpointModifications = new Dictionary<string, List<EndpointPolicySuggestion>>();

                foreach (var serviceGroup in endpointsByService)
                {
                    var serviceName = serviceGroup.Key;
                    var serviceEndpoints = serviceGroup.ToList();

                    var servicePolicyResolver = new PolicyResolver(
                        policyLocationMap,
                        serviceName,
                        defaultPolicy
                    );

                    var analyzer = new EndpointPolicyAnalyzer(
                        endpointAnalyzer,
                        exclusionMatcher,
                        servicePolicyResolver
                    );

                    var result = analyzer.AnalyzeEndpoints(serviceEndpoints);

                    // Group suggestions by file
                    foreach (var suggestion in result.EndpointsNeedingPolicy)
                    {
                        // Skip test files
                        var relativePath = suggestion.Endpoint.FilePath;
                        if (relativePath.Contains("/Tests/", StringComparison.OrdinalIgnoreCase) ||
                            relativePath.Contains("/tests/", StringComparison.OrdinalIgnoreCase) ||
                            relativePath.Contains(".Tests.", StringComparison.OrdinalIgnoreCase) ||
                            relativePath.Contains("Test", StringComparison.OrdinalIgnoreCase) && 
                            (relativePath.Contains("Endpoints", StringComparison.OrdinalIgnoreCase) || 
                             relativePath.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase)))
                        {
                            continue; // Skip test files
                        }

                        // Endpoint.FilePath is relative, need to find the actual file
                        var filePath = FindEndpointFile(solutionPath, relativePath);
                        
                        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                        {
                            // Try to find by searching for the file
                            var fileName = Path.GetFileName(relativePath);
                            var foundFiles = Directory.GetFiles(solutionPath, fileName, SearchOption.AllDirectories)
                                .Where(f => !f.Contains("/bin/") && 
                                          !f.Contains("/obj/") &&
                                          !f.Contains("/Tests/", StringComparison.OrdinalIgnoreCase) &&
                                          !f.Contains("/tests/", StringComparison.OrdinalIgnoreCase))
                                .ToList();
                            
                            if (foundFiles.Count == 1)
                            {
                                filePath = foundFiles[0];
                            }
                            else
                            {
                                Console.WriteLine($"⚠️  Warning: Could not locate file for endpoint: {relativePath}");
                                continue;
                            }
                        }

                        // Double-check it's not a test file
                        if (filePath.Contains("/Tests/", StringComparison.OrdinalIgnoreCase) ||
                            filePath.Contains("/tests/", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        if (!endpointModifications.ContainsKey(filePath))
                        {
                            endpointModifications[filePath] = new List<EndpointPolicySuggestion>();
                        }
                        endpointModifications[filePath].Add(suggestion);
                    }

                    // Report results
                    Console.WriteLine($"📦 {serviceName}:");
                    Console.WriteLine($"   Total: {result.TotalEndpoints}");
                    Console.WriteLine($"   ✅ With policy: {result.EndpointsWithPolicy.Count}");
                    Console.WriteLine($"   🔧 Needing policy: {result.EndpointsNeedingPolicy.Count}");
                    Console.WriteLine($"   🚫 Excluded: {result.ExcludedEndpoints.Count}");
                    Console.WriteLine($"   ⚠️  Unmapped: {result.EndpointsWithoutPolicy.Count}");
                    Console.WriteLine();
                }

                // Generate code modifications
                var codeModifier = new EndpointCodeModifier();
                foreach (var kvp in endpointModifications)
                {
                    var filePath = kvp.Key;
                    var suggestions = kvp.Value;

                    if (!File.Exists(filePath))
                        continue;

                    var (modifiedContent, modifications) = await codeModifier.ModifyFileAsync(
                        filePath,
                        suggestions,
                        solutionPath
                    );

                    if (modifications.Any())
                    {
                        // Create FileFix entries for each modification
                        foreach (var modification in modifications)
                        {
                            fixes.Add(new FileFix
                            {
                                FilePath = filePath,
                                LineNumber = modification.LineNumber,
                                Type = FixType.Endpoint,
                                Description = $"Add RequireAuthorization({modification.PolicyReference})",
                                OldCode = null, // Will be shown in preview
                                NewCode = $".RequireAuthorization({modification.PolicyReference})",
                                SpanStart = modification.InsertionPoint,
                                SpanLength = 0 // Insertion, not replacement
                            });
                        }

                        // Add using statement fix if needed
                        var needsUsing = modifications.Any(m => m.RequiresUsingStatement);
                        if (needsUsing)
                        {
                            var firstMod = modifications.First(m => m.RequiresUsingStatement);
                            var suggestion = suggestions.First();
                            var namespacePath = suggestion.SuggestedPolicy.Location.Namespace;
                            
                            // Extract namespace without the class name (e.g., "KS.PlatformServices.Constants.AuthorizationPolicies" -> "KS.PlatformServices.Constants")
                            var namespaceWithoutClass = namespacePath;
                            if (namespacePath.Contains(".AuthorizationPolicies"))
                            {
                                namespaceWithoutClass = namespacePath.Substring(0, namespacePath.LastIndexOf(".AuthorizationPolicies"));
                            }
                            else if (namespacePath.Contains(".Permissions"))
                            {
                                namespaceWithoutClass = namespacePath.Substring(0, namespacePath.LastIndexOf(".Permissions"));
                            }
                            
                            fixes.Add(new FileFix
                            {
                                FilePath = filePath,
                                LineNumber = 1, // Will be inserted after using statements
                                Type = FixType.UsingStatementInsertion,
                                Description = $"Add using statement: {namespaceWithoutClass}",
                                OldCode = null,
                                NewCode = $"using {namespaceWithoutClass};",
                                SpanStart = 0,
                                SpanLength = 0
                            });
                        }
                    }
                }

                if (endpointModifications.Any())
                {
                    Console.WriteLine($"✅ Found {endpointModifications.Sum(kvp => kvp.Value.Count)} endpoint(s) needing policies");
                    Console.WriteLine();
                }
            }

            // Migrate ApiConstants.Require* references if requested
            if (migrateApiConstants)
            {
                Console.WriteLine("🔄 Migrating ApiConstants.Require* references to PlatformServices constants...");
                Console.WriteLine();
                
                var migrationEndpointFiles = Directory.GetFiles(solutionPath, "*Endpoints.cs", SearchOption.AllDirectories)
                    .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/"))
                    .ToList();

                foreach (var filePath in migrationEndpointFiles)
                {
                    var apiConstantsFixes = await AnalyzeApiConstantsMigrationAsync(filePath, solutionPath, platformServicesPath);
                    if (apiConstantsFixes.Any())
                    {
                        fixes.AddRange(apiConstantsFixes);
                    }
                }
            }

            // Find endpoint files with namespace issues
            var endpointFiles = Directory.GetFiles(solutionPath, "*Endpoints.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/"))
                .ToList();

            foreach (var filePath in endpointFiles)
            {
                var fileFixes = await AnalyzeEndpointFileAsync(filePath, solutionPath, existingPolicies);
                if (fileFixes.Any())
                {
                    fixes.AddRange(fileFixes);
                }
            }

            // Find Program.cs files with policy registration issues
            var programFiles = Directory.GetFiles(solutionPath, "Program.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/"))
                .ToList();

            foreach (var filePath in programFiles)
            {
                var fileFixes = await AnalyzeProgramFileAsync(filePath, solutionPath, existingPolicies, existingPermissions);
                if (fileFixes.Any())
                {
                    fixes.AddRange(fileFixes);
                }
            }

            // Group fixes by file
            var fixesByFile = fixes.GroupBy(f => f.FilePath).ToList();

            if (!fixesByFile.Any())
            {
                Console.WriteLine("✅ No fixes needed. All files are correctly aligned.");
                return 0;
            }

            // Display preview
            var migrationFixes = fixes.Where(f => f.Description.Contains("Migrate ApiConstants")).ToList();
            if (migrationFixes.Any())
            {
                Console.WriteLine($"🔄 ApiConstants Migration: Found {migrationFixes.Count} migration(s)");
            }
            
            Console.WriteLine($"📋 Found {fixes.Count} fix(es) across {fixesByFile.Count} file(s):");
            Console.WriteLine();

            foreach (var fileGroup in fixesByFile)
            {
                Console.WriteLine($"📄 {GetRelativePath(fileGroup.Key, solutionPath)}");
                foreach (var fix in fileGroup)
                {
                    Console.WriteLine($"   Line {fix.LineNumber}: {fix.Description}");
                    if (fix.OldCode != null && fix.NewCode != null)
                    {
                        Console.WriteLine($"   - {fix.OldCode.Trim()}");
                        Console.WriteLine($"   + {fix.NewCode.Trim()}");
                    }
                }
                Console.WriteLine();
            }

            if (dryRun)
            {
                Console.WriteLine("🔍 DRY-RUN MODE: No changes were made.");
                Console.WriteLine("   Run without --dry-run to apply fixes.");
                return 0;
            }

            if (!applyEndpoints && !applyPolicies && !migrateApiConstants && !applyPoliciesToEndpoints)
            {
                Console.WriteLine("⚠️  No action flags specified. Use --apply-endpoints, --apply-policies, --apply-policies-to-endpoints, and/or --migrate-api-constants to apply fixes.");
                return 1;
            }

            // Apply fixes
            var appliedCount = 0;
            var errorCount = 0;

            foreach (var fileGroup in fixesByFile)
            {
                var filePath = fileGroup.Key;
                var fileFixes = fileGroup.ToList();

                // Filter by action type
                var fixesToApply = fileFixes.Where(f => 
                    ((applyEndpoints || applyPoliciesToEndpoints) && f.Type == FixType.Endpoint) ||
                    (applyPoliciesToEndpoints && f.Type == FixType.UsingStatementInsertion) ||
                    (applyPolicies && f.Type == FixType.PolicyRegistration) ||
                    (migrateApiConstants && f.Description.Contains("Migrate ApiConstants"))).ToList();

                if (!fixesToApply.Any())
                {
                    continue;
                }

                try
                {
                    // Create backup (only if file exists)
                    if (File.Exists(filePath))
                    {
                        var backupPath = $"{filePath}.backup.{DateTime.Now:yyyyMMddHHmmss}";
                        File.Copy(filePath, backupPath, overwrite: true);
                        Console.WriteLine($"💾 Backup created: {GetRelativePath(backupPath, solutionPath)}");
                    }

                    // Apply fixes
                    var content = await File.ReadAllTextAsync(filePath);
                    var modifiedContent = ApplyFixesToContent(content, fixesToApply);

                    await File.WriteAllTextAsync(filePath, modifiedContent, Encoding.UTF8);
                    appliedCount += fixesToApply.Count;
                    Console.WriteLine($"✅ Applied {fixesToApply.Count} fix(es) to {GetRelativePath(filePath, solutionPath)}");
                }
                catch (Exception ex)
                {
                    errorCount++;
                    Console.WriteLine($"❌ Error applying fixes to {GetRelativePath(filePath, solutionPath)}: {ex.Message}");
                }
            }

            Console.WriteLine();
            Console.WriteLine($"✅ Applied {appliedCount} fix(es)");
            if (errorCount > 0)
            {
                Console.WriteLine($"❌ {errorCount} error(s) occurred");
                return 1;
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            return 1;
        }
    }

    private static async Task<List<FileFix>> AnalyzeEndpointFileAsync(
        string filePath,
        string solutionRoot,
        Dictionary<string, PolicyLocation> existingPolicies)
    {
        var fixes = new List<FileFix>();

        var sourceCode = await File.ReadAllTextAsync(filePath);
        var syntaxTree = CSharpSyntaxTree.ParseText(sourceCode, path: filePath);
        var root = await syntaxTree.GetRootAsync();

        // Extract using statements
        var usingStatements = ExtractUsingStatements(root);
        var hasPlatformServicesUsing = usingStatements.Any(u => 
            u.Contains("KS.PlatformServices.Constants", StringComparison.OrdinalIgnoreCase));
        
        // Check for service-specific constants using statement
        var serviceName = ExtractServiceName(filePath, solutionRoot);
        var serviceConstantsNamespace = $"KS.{serviceName}.Api.Constants";
        var hasServiceConstantsUsing = usingStatements.Any(u => 
            u.Equals(serviceConstantsNamespace, StringComparison.OrdinalIgnoreCase));

        // Find all RequireAuthorization calls
        var invocationExpressions = root.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(inv => inv.Expression.ToString().Contains("RequireAuthorization"))
            .ToList();

        foreach (var invocation in invocationExpressions)
        {
            var lineSpan = syntaxTree.GetLineSpan(invocation.Span);
            var lineNumber = lineSpan.StartLinePosition.Line + 1;

            // Check if it has a policy argument
            var arguments = invocation.ArgumentList?.Arguments ?? new SeparatedSyntaxList<ArgumentSyntax>();
            if (arguments.Count == 0)
            {
                continue; // No policy specified, skip
            }

            var firstArg = arguments[0].Expression;
            
            // Check for MemberAccessExpression (e.g., AuthorizationPolicies.X)
            if (firstArg is MemberAccessExpressionSyntax memberAccess)
            {
                var expressionStr = memberAccess.ToString();
                
                // Check if it's a policy reference
                if (memberAccess.Expression.ToString() == "AuthorizationPolicies" ||
                    memberAccess.Expression.ToString().EndsWith(".AuthorizationPolicies"))
                {
                    var policyName = memberAccess.Name.ToString();
                    
                    // Determine correct namespace
                    var correctNamespace = DetermineCorrectNamespace(policyName, existingPolicies, solutionRoot, filePath);
                    var currentNamespace = GetCurrentNamespace(memberAccess);

                    if (correctNamespace != null && currentNamespace != correctNamespace)
                    {
                        // Check if the "local" reference is actually correct given using statements
                        if (currentNamespace == "local")
                        {
                            if ((correctNamespace == "KS.PlatformServices.Constants" && hasPlatformServicesUsing) ||
                                (correctNamespace == serviceConstantsNamespace && hasServiceConstantsUsing))
                            {
                                // Already correct - local reference with proper using statement
                                continue;
                            }
                        }
                        
                        // Need to fix namespace
                        var newCode = BuildCorrectPolicyReference(policyName, correctNamespace, hasPlatformServicesUsing || hasServiceConstantsUsing);
                        
                        // Only add fix if the new code is actually different
                        if (newCode != expressionStr)
                        {
                            fixes.Add(new FileFix
                            {
                                FilePath = filePath,
                                LineNumber = lineNumber,
                                Type = FixType.Endpoint,
                                Description = $"Fix namespace for policy '{policyName}'",
                                OldCode = expressionStr,
                                NewCode = newCode,
                                SpanStart = invocation.Span.Start,
                                SpanLength = invocation.Span.Length
                            });
                        }
                    }
                }
            }
        }

        return fixes;
    }

    private static async Task<List<FileFix>> AnalyzeProgramFileAsync(
        string filePath,
        string solutionRoot,
        Dictionary<string, PolicyLocation> existingPolicies,
        Dictionary<string, PermissionLocation> existingPermissions)
    {
        var fixes = new List<FileFix>();

        var sourceCode = await File.ReadAllTextAsync(filePath);
        var syntaxTree = CSharpSyntaxTree.ParseText(sourceCode, path: filePath);
        var root = await syntaxTree.GetRootAsync();

        // Find AddAuthorization block
        var addAuthorizationInvocations = root.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(inv => inv.Expression.ToString().Contains("AddAuthorization"))
            .ToList();

        if (!addAuthorizationInvocations.Any())
        {
            return fixes; // No authorization configuration
        }

        // Extract using statements
        var usingStatements = ExtractUsingStatements(root);
        var hasPlatformServicesUsing = usingStatements.Any(u => 
            u.Contains("KS.PlatformServices.Constants", StringComparison.OrdinalIgnoreCase));
        
        // Check for service-specific constants using statement
        var serviceName = ExtractServiceName(filePath, solutionRoot);
        var serviceConstantsNamespace = $"KS.{serviceName}.Api.Constants";
        var hasServiceConstantsUsing = usingStatements.Any(u => 
            u.Equals(serviceConstantsNamespace, StringComparison.OrdinalIgnoreCase));

        // Find all AddPolicy calls within AddAuthorization
        foreach (var addAuthInvocation in addAuthorizationInvocations)
        {
            // Find the lambda/block that contains AddPolicy calls
            var parentBlock = addAuthInvocation.Parent;
            while (parentBlock != null && !(parentBlock is BlockSyntax || parentBlock is ArrowExpressionClauseSyntax))
            {
                parentBlock = parentBlock.Parent;
            }

            if (parentBlock == null) continue;

            var addPolicyInvocations = parentBlock.DescendantNodes()
                .OfType<InvocationExpressionSyntax>()
                .Where(inv => inv.Expression.ToString().Contains("AddPolicy"))
                .ToList();

            foreach (var addPolicyInvocation in addPolicyInvocations)
            {
                var lineSpan = syntaxTree.GetLineSpan(addPolicyInvocation.Span);
                var lineNumber = lineSpan.StartLinePosition.Line + 1;

                var arguments = addPolicyInvocation.ArgumentList?.Arguments ?? new SeparatedSyntaxList<ArgumentSyntax>();
                if (arguments.Count < 1) continue;

                var firstArg = arguments[0].Expression;
                
                // Check for policy name reference
                if (firstArg is MemberAccessExpressionSyntax memberAccess)
                {
                    var expressionStr = memberAccess.ToString();
                    
                    if (memberAccess.Expression.ToString() == "AuthorizationPolicies" ||
                        memberAccess.Expression.ToString().EndsWith(".AuthorizationPolicies"))
                    {
                        var policyName = memberAccess.Name.ToString();
                        
                        // Determine correct namespace
                        var correctNamespace = DetermineCorrectNamespace(policyName, existingPolicies, solutionRoot, filePath);
                        var currentNamespace = GetCurrentNamespace(memberAccess);

                        if (correctNamespace != null && currentNamespace != correctNamespace)
                        {
                            // Check if the "local" reference is actually correct given using statements
                            if (currentNamespace == "local")
                            {
                                if ((correctNamespace == "KS.PlatformServices.Constants" && hasPlatformServicesUsing) ||
                                    (correctNamespace == serviceConstantsNamespace && hasServiceConstantsUsing))
                                {
                                    // Already correct - local reference with proper using statement
                                    continue;
                                }
                            }
                            
                            // Need to fix namespace
                            var newCode = BuildCorrectPolicyReference(policyName, correctNamespace, hasPlatformServicesUsing || hasServiceConstantsUsing);
                            
                            // Only add fix if the new code is actually different
                            if (newCode != expressionStr)
                            {
                                fixes.Add(new FileFix
                                {
                                    FilePath = filePath,
                                    LineNumber = lineNumber,
                                    Type = FixType.PolicyRegistration,
                                    Description = $"Fix namespace for policy '{policyName}' in AddPolicy",
                                    OldCode = expressionStr,
                                    NewCode = newCode,
                                    SpanStart = addPolicyInvocation.Span.Start,
                                    SpanLength = addPolicyInvocation.Span.Length
                                });
                            }
                        }
                    }
                }

                // Check for permission reference in RequireClaim
                if (arguments.Count >= 2)
                {
                    var secondArg = arguments[1].Expression;
                    if (secondArg is LambdaExpressionSyntax lambda)
                    {
                        var permissionFixes = AnalyzeLambdaForPermissionReferences(
                            lambda, 
                            filePath, 
                            syntaxTree, 
                            existingPermissions, 
                            solutionRoot, 
                            hasPlatformServicesUsing,
                            hasServiceConstantsUsing);
                        fixes.AddRange(permissionFixes);
                    }
                }
            }
        }

        return fixes;
    }

    private static List<FileFix> AnalyzeLambdaForPermissionReferences(
        LambdaExpressionSyntax lambda,
        string filePath,
        SyntaxTree syntaxTree,
        Dictionary<string, PermissionLocation> existingPermissions,
        string solutionRoot,
        bool hasPlatformServicesUsing,
        bool hasServiceConstantsUsing)
    {
        var fixes = new List<FileFix>();

        // Find RequireClaim calls
        var requireClaimInvocations = lambda.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(inv => inv.Expression.ToString().Contains("RequireClaim"))
            .ToList();

        foreach (var invocation in requireClaimInvocations)
        {
            var arguments = invocation.ArgumentList?.Arguments ?? new SeparatedSyntaxList<ArgumentSyntax>();
            if (arguments.Count < 2) continue;

            var secondArg = arguments[1].Expression;
            
            // Check for Permissions.X reference
            if (secondArg is MemberAccessExpressionSyntax memberAccess)
            {
                var expressionStr = memberAccess.ToString();
                
                if (memberAccess.Expression.ToString() == "Permissions" ||
                    memberAccess.Expression.ToString().EndsWith(".Permissions"))
                {
                    var permissionName = memberAccess.Name.ToString();
                    
                    // Determine correct namespace
                    var correctNamespace = DetermineCorrectPermissionNamespace(permissionName, existingPermissions, solutionRoot, filePath);
                    var currentNamespace = GetCurrentNamespace(memberAccess);

                    if (correctNamespace != null && currentNamespace != correctNamespace)
                    {
                        // Check if the "local" reference is actually correct given using statements
                        if (currentNamespace == "local")
                        {
                            var serviceName = ExtractServiceName(filePath, solutionRoot);
                            var serviceConstantsNamespace = $"KS.{serviceName}.Api.Constants";
                            
                            if ((correctNamespace == "KS.PlatformServices.Constants" && hasPlatformServicesUsing) ||
                                (correctNamespace == serviceConstantsNamespace && hasServiceConstantsUsing))
                            {
                                // Already correct - local reference with proper using statement
                                continue;
                            }
                        }
                        
                        var lineSpan = syntaxTree.GetLineSpan(invocation.Span);
                        var lineNumber = lineSpan.StartLinePosition.Line + 1;
                        
                        var newCode = BuildCorrectPermissionReference(permissionName, correctNamespace, hasPlatformServicesUsing || hasServiceConstantsUsing);
                        
                        // Only add fix if the new code is actually different
                        if (newCode != expressionStr)
                        {
                            fixes.Add(new FileFix
                            {
                                FilePath = filePath,
                                LineNumber = lineNumber,
                                Type = FixType.PolicyRegistration,
                                Description = $"Fix namespace for permission '{permissionName}' in RequireClaim",
                                OldCode = expressionStr,
                                NewCode = newCode,
                                SpanStart = invocation.Span.Start,
                                SpanLength = invocation.Span.Length
                            });
                        }
                    }
                }
            }
        }

        return fixes;
    }

    private static string? DetermineCorrectNamespace(
        string policyName,
        Dictionary<string, PolicyLocation> existingPolicies,
        string solutionRoot,
        string filePath)
    {
        if (!existingPolicies.TryGetValue(policyName, out var location))
        {
            return null; // Policy not found, can't determine
        }

        // Determine service from file path
        var serviceName = ExtractServiceName(filePath, solutionRoot);
        
        if (location.IsShared)
        {
            return "KS.PlatformServices.Constants";
        }
        else if (location.ServiceName != null && location.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase))
        {
            // Service-specific, and we're in that service
            return $"KS.{location.ServiceName}.Api.Constants";
        }
        else
        {
            // Service-specific but we're in a different service - should use PlatformServices or fully qualified
            return "KS.PlatformServices.Constants"; // Default to shared for cross-service
        }
    }

    private static string? DetermineCorrectPermissionNamespace(
        string permissionName,
        Dictionary<string, PermissionLocation> existingPermissions,
        string solutionRoot,
        string filePath)
    {
        if (!existingPermissions.TryGetValue(permissionName, out var location))
        {
            return null;
        }

        var serviceName = ExtractServiceName(filePath, solutionRoot);
        
        if (location.IsShared)
        {
            return "KS.PlatformServices.Constants";
        }
        else if (location.ServiceName != null && location.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase))
        {
            return $"KS.{location.ServiceName}.Api.Constants";
        }
        else
        {
            return "KS.PlatformServices.Constants";
        }
    }

    private static string GetCurrentNamespace(MemberAccessExpressionSyntax memberAccess)
    {
        var expression = memberAccess.Expression.ToString();
        
        if (expression == "AuthorizationPolicies" || expression == "Permissions")
        {
            return "local"; // Local reference
        }
        
        if (expression.Contains("."))
        {
            // Fully qualified
            return expression.Substring(0, expression.LastIndexOf('.'));
        }
        
        return "local";
    }

    private static string BuildCorrectPolicyReference(string policyName, string targetNamespace, bool hasPlatformServicesUsing)
    {
        if (targetNamespace == "KS.PlatformServices.Constants" && hasPlatformServicesUsing)
        {
            return $"AuthorizationPolicies.{policyName}";
        }
        else
        {
            return $"{targetNamespace}.AuthorizationPolicies.{policyName}";
        }
    }

    private static string BuildCorrectPermissionReference(string permissionName, string targetNamespace, bool hasPlatformServicesUsing)
    {
        if (targetNamespace == "KS.PlatformServices.Constants" && hasPlatformServicesUsing)
        {
            return $"Permissions.{permissionName}";
        }
        else
        {
            return $"{targetNamespace}.Permissions.{permissionName}";
        }
    }

    private static string ApplyFixesToContent(string content, List<FileFix> fixes)
    {
        if (!fixes.Any())
        {
            return content;
        }

        // Separate fixes into replacements and insertions
        var replacementFixes = fixes
            .Where(f => f.OldCode != null && f.NewCode != null && f.SpanLength > 0)
            .OrderByDescending(f => f.SpanStart)
            .ToList();
        
        var insertionFixes = fixes
            .Where(f => f.NewCode != null && f.SpanLength == 0)
            .OrderByDescending(f => f.SpanStart)
            .ToList();

        // Store original content for position calculations
        var originalContent = content;
        var sb = new StringBuilder(content);
        
        // Apply replacements first (from end to start to maintain positions)
        foreach (var fix in replacementFixes)
        {
            var startIndex = fix.SpanStart;
            var length = Math.Min(fix.SpanLength, originalContent.Length - startIndex);
            
            if (startIndex >= 0 && startIndex < originalContent.Length && length > 0)
            {
                var currentText = originalContent.Substring(startIndex, length);
                
                // Try to match the old code (handle whitespace differences)
                var normalizedOld = NormalizeWhitespace(fix.OldCode!);
                var normalizedCurrent = NormalizeWhitespace(currentText);
                
                if (normalizedCurrent.Contains(normalizedOld) || normalizedOld.Contains(normalizedCurrent))
                {
                    // Calculate position adjustment from replacements that happened after this one
                    // (since we're processing from end to start)
                    var positionAdjustment = 0;
                    foreach (var prevFix in replacementFixes.Where(f => f.SpanStart > startIndex))
                    {
                        var prevOldLength = prevFix.SpanLength;
                        var prevNewLength = prevFix.NewCode?.Length ?? 0;
                        positionAdjustment += (prevNewLength - prevOldLength);
                    }
                    
                    var adjustedStart = startIndex + positionAdjustment;
                    if (adjustedStart >= 0 && adjustedStart + length <= sb.Length)
                    {
                        // Replace the text
                        sb.Remove(adjustedStart, length);
                        sb.Insert(adjustedStart, fix.NewCode!);
                    }
                }
            }
        }
        
        // Update content after all replacements
        content = sb.ToString();
        
        // Apply insertions (from end to start to maintain positions)
        // Need to adjust positions based on all replacements
        foreach (var fix in insertionFixes.OrderByDescending(f => f.SpanStart))
        {
            var insertIndex = fix.SpanStart;
            
            // Adjust position for all replacements (they all happened before insertions)
            var positionAdjustment = 0;
            foreach (var replacement in replacementFixes)
            {
                if (replacement.SpanStart < insertIndex)
                {
                    var oldLength = replacement.SpanLength;
                    var newLength = replacement.NewCode?.Length ?? 0;
                    positionAdjustment += (newLength - oldLength);
                }
            }
            
            var adjustedIndex = insertIndex + positionAdjustment;
            
            if (adjustedIndex >= 0 && adjustedIndex <= sb.Length)
            {
                // Insert new line with proper line ending
                var newLine = fix.NewCode!;
                if (!newLine.EndsWith(Environment.NewLine) && !newLine.EndsWith("\n"))
                {
                    newLine += Environment.NewLine;
                }
                
                sb.Insert(adjustedIndex, newLine);
                content = sb.ToString(); // Update content for next iteration
            }
        }
        
        return sb.ToString();
    }

    private static string NormalizeWhitespace(string text)
    {
        return Regex.Replace(text, @"\s+", " ").Trim();
    }

    public static async Task<(Dictionary<string, PermissionLocation> Permissions, Dictionary<string, PolicyLocation> Policies)> 
        ReadExistingConstantsAsync(string solutionPath, string platformServicesPath)
    {
        var permissions = new Dictionary<string, PermissionLocation>();
        var policies = new Dictionary<string, PolicyLocation>();

        // Read PlatformServices constants
        var platformPermissionsPath = Path.Combine(platformServicesPath, "Constants", "Permissions.cs");
        var platformPoliciesPath = Path.Combine(platformServicesPath, "Constants", "AuthorizationPolicies.cs");

        if (File.Exists(platformPermissionsPath))
        {
            await ReadPermissionsFromFile(platformPermissionsPath, permissions, isShared: true, serviceName: null);
        }

        if (File.Exists(platformPoliciesPath))
        {
            await ReadPoliciesFromFile(platformPoliciesPath, policies, isShared: true, serviceName: null);
        }

        // Read service-specific constants
        var serviceDirs = Directory.GetDirectories(solutionPath)
            .Where(d => {
                var dirName = Path.GetFileName(d);
                // Match patterns like "Kronos.Sales.*Service" but exclude "kronos-services" and "PlatformServices"
                return dirName.Contains("Service", StringComparison.OrdinalIgnoreCase) &&
                       !dirName.Contains("PlatformServices", StringComparison.OrdinalIgnoreCase) &&
                       (dirName.StartsWith("Kronos.", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Contains(".Sales.", StringComparison.OrdinalIgnoreCase));
            })
            .ToList();

        foreach (var serviceDir in serviceDirs)
        {
            var constantsDir = Directory.GetDirectories(serviceDir, "Constants", SearchOption.AllDirectories)
                .FirstOrDefault();

            if (constantsDir != null)
            {
                // Extract service name from directory name (e.g., "Kronos.Sales.CommonService" -> "CommonService")
                var dirName = Path.GetFileName(serviceDir);
                var serviceName = ExtractServiceNameFromDirectoryName(dirName);
                
                var permissionsPath = Path.Combine(constantsDir, "Permissions.cs");
                var policiesPath = Path.Combine(constantsDir, "AuthorizationPolicies.cs");

                if (File.Exists(permissionsPath))
                {
                    await ReadPermissionsFromFile(permissionsPath, permissions, isShared: false, serviceName);
                }

                if (File.Exists(policiesPath))
                {
                    await ReadPoliciesFromFile(policiesPath, policies, isShared: false, serviceName);
                }
            }
        }

        return (permissions, policies);
    }

    private static async Task ReadPermissionsFromFile(
        string filePath,
        Dictionary<string, PermissionLocation> permissions,
        bool isShared,
        string? serviceName)
    {
        var content = await File.ReadAllTextAsync(filePath);
        
        // Extract public const string declarations
        var pattern = @"public\s+const\s+string\s+(\w+)\s*=";
        var matches = Regex.Matches(content, pattern);
        
        foreach (Match match in matches)
        {
            var constantName = match.Groups[1].Value;
            permissions[constantName] = new PermissionLocation
            {
                IsShared = isShared,
                ServiceName = serviceName
            };
        }
    }

    private static async Task ReadPoliciesFromFile(
        string filePath,
        Dictionary<string, PolicyLocation> policies,
        bool isShared,
        string? serviceName)
    {
        var content = await File.ReadAllTextAsync(filePath);
        
        // Extract public const string declarations
        var pattern = @"public\s+const\s+string\s+(\w+)\s*=";
        var matches = Regex.Matches(content, pattern);
        
        foreach (Match match in matches)
        {
            var constantName = match.Groups[1].Value;
            policies[constantName] = new PolicyLocation
            {
                IsShared = isShared,
                ServiceName = serviceName
            };
        }
    }

    private static List<string> ExtractUsingStatements(SyntaxNode root)
    {
        var usings = new List<string>();
        
        var usingDirectives = root.DescendantNodes()
            .OfType<UsingDirectiveSyntax>()
            .ToList();
        
        foreach (var usingDirective in usingDirectives)
        {
            var name = usingDirective.Name?.ToString() ?? "";
            usings.Add(name);
        }
        
        return usings;
    }

    private static string ExtractServiceName(string filePath, string solutionRoot)
    {
        var relativePath = Path.GetRelativePath(solutionRoot, filePath);
        var parts = relativePath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        
        foreach (var part in parts)
        {
            if (part.Contains("Service", StringComparison.OrdinalIgnoreCase) && 
                !part.Contains("PlatformServices", StringComparison.OrdinalIgnoreCase))
            {
                return ExtractServiceNameFromPath(part);
            }
        }
        
        return "Unknown";
    }

    /// <summary>
    /// Extracts service name from directory name (e.g., "Kronos.Sales.CommonService" -> "CommonService").
    /// </summary>
    private static string ExtractServiceNameFromDirectoryName(string directoryName)
    {
        // Handle patterns like "Kronos.Sales.CommonService"
        if (directoryName.Contains("."))
        {
            var dotParts = directoryName.Split('.');
            // Get the last part that contains "Service"
            var serviceName = dotParts.LastOrDefault(s => s.Contains("Service", StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(serviceName))
            {
                return serviceName;
            }
            // Fallback: get last part
            return dotParts.LastOrDefault() ?? directoryName;
        }
        
        // If no dots, return as-is if it contains "Service"
        if (directoryName.Contains("Service", StringComparison.OrdinalIgnoreCase))
        {
            return directoryName;
        }
        
        return "Unknown";
    }

    private static string ExtractServiceNameFromPath(string path)
    {
        var parts = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        
        // Look for patterns like "Kronos.Sales.*Service" (not just any part containing "Service")
        // This avoids matching "kronos-services" directory
        var servicePart = parts.FirstOrDefault(p => 
            p.Contains("Service", StringComparison.OrdinalIgnoreCase) &&
            (p.StartsWith("Kronos.", StringComparison.OrdinalIgnoreCase) || 
             p.Contains(".Sales.", StringComparison.OrdinalIgnoreCase)));
        
        if (servicePart != null)
        {
            return ExtractServiceNameFromDirectoryName(servicePart);
        }
        
        return "Unknown";
    }

    /// <summary>
    /// Finds the actual file path for an endpoint file given a relative path.
    /// </summary>
    private static string? FindEndpointFile(string solutionPath, string relativePath)
    {
        // Try direct path first
        var directPath = Path.Combine(solutionPath, relativePath);
        if (File.Exists(directPath))
            return directPath;

        // Try with normalized separators
        var normalizedPath = relativePath.Replace('/', Path.DirectorySeparatorChar);
        directPath = Path.Combine(solutionPath, normalizedPath);
        if (File.Exists(directPath))
            return directPath;

        return null;
    }

    /// <summary>
    /// Analyzes endpoint files for ApiConstants.Require* references and migrates them to PlatformServices constants.
    /// </summary>
    private static async Task<List<FileFix>> AnalyzeApiConstantsMigrationAsync(
        string filePath,
        string solutionRoot,
        string platformServicesPath)
    {
        var fixes = new List<FileFix>();

        var sourceCode = await File.ReadAllTextAsync(filePath);
        var syntaxTree = CSharpSyntaxTree.ParseText(sourceCode, path: filePath);
        var root = await syntaxTree.GetRootAsync();

        // Check if PlatformServices policies exist
        var platformPoliciesPath = Path.Combine(platformServicesPath, "Constants", "AuthorizationPolicies.cs");
        if (!File.Exists(platformPoliciesPath))
        {
            return fixes; // Can't migrate if PlatformServices policies don't exist
        }

        var platformPoliciesContent = await File.ReadAllTextAsync(platformPoliciesPath);
        
        // Known ApiConstants policies that should be migrated
        var apiConstantsPolicies = new Dictionary<string, string>
        {
            { "RequireProductAccess", "RequireProductAccess" },
            { "RequireAdminRole", "RequireAdminRole" }
        };

        // Check which policies exist in PlatformServices
        var existingPlatformPolicies = new HashSet<string>();
        foreach (var policy in apiConstantsPolicies.Values)
        {
            if (platformPoliciesContent.Contains($"public const string {policy}"))
            {
                existingPlatformPolicies.Add(policy);
            }
        }

        if (!existingPlatformPolicies.Any())
        {
            return fixes; // No matching policies in PlatformServices
        }

        // Extract using statements
        var usingStatements = ExtractUsingStatements(root);
        var hasPlatformServicesUsing = usingStatements.Any(u => 
            u.Contains("KS.PlatformServices.Constants", StringComparison.OrdinalIgnoreCase));
        var needsUsingStatement = !hasPlatformServicesUsing;

        // Find all MemberAccessExpression nodes (e.g., ApiConstants.RequireProductAccess)
        var memberAccesses = root.DescendantNodes()
            .OfType<MemberAccessExpressionSyntax>()
            .Where(ma => ma.Expression.ToString() == "ApiConstants")
            .ToList();

        foreach (var memberAccess in memberAccesses)
        {
            var constantName = memberAccess.Name.ToString();
            
            // Check if this is a policy we should migrate
            if (apiConstantsPolicies.TryGetValue(constantName, out var platformPolicyName) &&
                existingPlatformPolicies.Contains(platformPolicyName))
            {
                var lineSpan = syntaxTree.GetLineSpan(memberAccess.Span);
                var lineNumber = lineSpan.StartLinePosition.Line + 1;
                
                // Build replacement
                // Use short form if using statement exists OR will be added
                string newCode;
                if (hasPlatformServicesUsing || needsUsingStatement)
                {
                    // Can use short form - using statement exists or will be added
                    newCode = $"AuthorizationPolicies.{platformPolicyName}";
                }
                else
                {
                    // Need fully qualified name (shouldn't happen, but safe fallback)
                    newCode = $"KS.PlatformServices.Constants.AuthorizationPolicies.{platformPolicyName}";
                }

                fixes.Add(new FileFix
                {
                    FilePath = filePath,
                    LineNumber = lineNumber,
                    Type = FixType.Endpoint,
                    Description = $"Migrate ApiConstants.{constantName} to PlatformServices constant",
                    OldCode = memberAccess.ToString(),
                    NewCode = newCode,
                    SpanStart = memberAccess.Span.Start,
                    SpanLength = memberAccess.Span.Length
                });
            }
        }

        // Add using statement fix if needed
        if (needsUsingStatement && fixes.Any())
        {
            // Find the best place to insert the using statement (after other using statements)
            var usingDirectives = root.DescendantNodes()
                .OfType<UsingDirectiveSyntax>()
                .ToList();

            if (usingDirectives.Any())
            {
                var lastUsing = usingDirectives.Last();
                var lineSpan = syntaxTree.GetLineSpan(lastUsing.Span);
                var lineNumber = lineSpan.EndLinePosition.Line + 1;
                
                // Find the position after the last using statement (including semicolon and newline)
                var lastUsingEnd = lastUsing.Span.End;
                
                // Determine indentation from the last using statement
                var lastUsingText = lastUsing.ToString();
                var indent = lastUsingText.Substring(0, lastUsingText.Length - lastUsingText.TrimStart().Length);
                
                // Find the end of the line (after semicolon, after newline)
                // Look for newline after the last using statement
                var insertPosition = lastUsingEnd;
                if (lastUsingEnd < sourceCode.Length)
                {
                    // Find the next newline after the using statement
                    var remainingText = sourceCode.Substring(lastUsingEnd);
                    var newlineIndex = remainingText.IndexOf('\n');
                    if (newlineIndex >= 0)
                    {
                        insertPosition = lastUsingEnd + newlineIndex + 1; // After the newline
                    }
                    else
                    {
                        // No newline found, insert at end and add newline
                        insertPosition = sourceCode.Length;
                    }
                }
                
                fixes.Add(new FileFix
                {
                    FilePath = filePath,
                    LineNumber = lineNumber,
                    Type = FixType.Endpoint,
                    Description = "Add using statement for PlatformServices.Constants",
                    OldCode = "",
                    NewCode = $"{indent}using KS.PlatformServices.Constants;",
                    SpanStart = insertPosition,
                    SpanLength = 0 // Insert after
                });
            }
        }

        return fixes;
    }

    private static string GetRelativePath(string fullPath, string basePath)
    {
        try
        {
            // Normalize paths
            var normalizedFullPath = Path.GetFullPath(fullPath);
            var normalizedBasePath = Path.GetFullPath(basePath);
            
            // Check if fullPath is actually within basePath
            if (!normalizedFullPath.StartsWith(normalizedBasePath, StringComparison.OrdinalIgnoreCase))
            {
                // Return just the filename if not relative
                return Path.GetFileName(fullPath);
            }
            
            // Get relative path
            var relativePath = Path.GetRelativePath(normalizedBasePath, normalizedFullPath);
            return relativePath;
        }
        catch
        {
            // Fallback to just filename
            return Path.GetFileName(fullPath);
        }
    }

    private class FileFix
    {
        public string FilePath { get; set; } = "";
        public int LineNumber { get; set; }
        public FixType Type { get; set; }
        public string Description { get; set; } = "";
        public string? OldCode { get; set; }
        public string? NewCode { get; set; }
        public int SpanStart { get; set; }
        public int SpanLength { get; set; }
    }

    private enum FixType
    {
        Endpoint,
        PolicyRegistration,
        UsingStatementInsertion
    }

    public class PolicyLocation
    {
        public bool IsShared { get; set; }
        public string? ServiceName { get; set; }
    }

    public class PermissionLocation
    {
        public bool IsShared { get; set; }
        public string? ServiceName { get; set; }
    }
}
