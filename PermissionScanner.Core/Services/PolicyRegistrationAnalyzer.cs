using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Analyzes code to detect missing authorization policy registrations in Program.cs files.
/// </summary>
public class PolicyRegistrationAnalyzer
{
    /// <summary>
    /// Result of policy registration analysis.
    /// </summary>
    public class PolicyRegistrationAnalysisResult
    {
        /// <summary>
        /// Gets or sets the list of missing policy registrations.
        /// </summary>
        public List<MissingPolicyRegistration> MissingRegistrations { get; set; } = new();
        
        /// <summary>
        /// Gets or sets the dictionary of registered policies by service name.
        /// </summary>
        public Dictionary<string, List<string>> PoliciesByService { get; set; } = new();
    }

    /// <summary>
    /// Represents a missing policy registration.
    /// </summary>
    public class MissingPolicyRegistration
    {
        /// <summary>
        /// Gets or sets the name of the policy that is missing.
        /// </summary>
        public string PolicyName { get; set; } = string.Empty;
        
        /// <summary>
        /// Gets or sets the name of the service where the policy is missing.
        /// </summary>
        public string ServiceName { get; set; } = string.Empty;
        
        /// <summary>
        /// Gets or sets the path to the Program.cs file where the policy should be registered.
        /// </summary>
        public string ProgramCsPath { get; set; } = string.Empty;
        
        /// <summary>
        /// Gets or sets the permission name associated with the policy (if known).
        /// </summary>
        public string? PermissionName { get; set; }
        
        /// <summary>
        /// Gets or sets the list of endpoint files that use this policy.
        /// </summary>
        public List<string> EndpointFiles { get; set; } = new();
        
        /// <summary>
        /// Gets or sets the number of times this policy is used in endpoint files.
        /// </summary>
        public int UsageCount { get; set; }
    }

    /// <summary>
    /// Analyzes a solution to find missing policy registrations.
    /// </summary>
    public async Task<PolicyRegistrationAnalysisResult> AnalyzeAsync(string solutionPath)
    {
        var result = new PolicyRegistrationAnalysisResult();

        // Step 0: Build permission cache upfront (much faster than searching for each policy)
        var stopwatch = Stopwatch.StartNew();
        Console.WriteLine("  📂 Building permission cache from AuthorizationPolicies.cs files...");
        var permissionCache = await BuildPermissionCacheAsync(solutionPath);
        stopwatch.Stop();
        Console.WriteLine($"  ✅ Cached {permissionCache.Count} policy permission(s) ({stopwatch.ElapsedMilliseconds}ms)");

        // Step 1: Find all RequireAuthorization calls in endpoint files
        stopwatch.Restart();
        Console.WriteLine("  📂 Scanning endpoint files for policy usage...");
        var policyUsages = await FindPolicyUsagesAsync(solutionPath, permissionCache);
        stopwatch.Stop();
        Console.WriteLine($"  ✅ Found {policyUsages.Count} policy usage(s) across endpoint files ({stopwatch.ElapsedMilliseconds}ms)");

        // Step 2: Find all registered policies (from Program.cs and PlatformServices extensions)
        stopwatch.Restart();
        Console.WriteLine("  📂 Scanning Program.cs and extension files for registered policies...");
        var allRegisteredPolicies = await FindAllRegisteredPoliciesAsync(solutionPath);
        stopwatch.Stop();
        Console.WriteLine($"  ✅ Found {allRegisteredPolicies.Count} registered policy/policies ({stopwatch.ElapsedMilliseconds}ms)");

        // Step 3: Find all Program.cs files and check which policies are registered locally
        stopwatch.Restart();
        var programFiles = FindProgramFiles(solutionPath);
        Console.WriteLine($"  📂 Analyzing {programFiles.Count} Program.cs file(s) for missing registrations...");
        Console.WriteLine();
        
        var fileIndex = 0;
        foreach (var programFile in programFiles)
        {
            fileIndex++;
            var serviceName = ExtractServiceName(programFile, solutionPath);
            var fileStopwatch = Stopwatch.StartNew();
            Console.Write($"  [{fileIndex}/{programFiles.Count}] Analyzing {serviceName}... ");
            
            var localRegisteredPolicies = await ExtractRegisteredPoliciesAsync(programFile);

            // Find policies used in this service but not registered (locally or in PlatformServices)
            var servicePolicyUsages = policyUsages
                .Where(p => p.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase))
                .GroupBy(p => p.PolicyName)
                .ToList();

            var missingCount = 0;
            foreach (var policyGroup in servicePolicyUsages)
            {
                var policyName = policyGroup.Key;
                
                // Check if policy is registered locally OR in PlatformServices (shared policies)
                var isRegistered = localRegisteredPolicies.Contains(policyName, StringComparer.OrdinalIgnoreCase) ||
                                   allRegisteredPolicies.Contains(policyName, StringComparer.OrdinalIgnoreCase);
                
                if (!isRegistered)
                {
                    missingCount++;
                    var usage = policyGroup.First();
                    result.MissingRegistrations.Add(new MissingPolicyRegistration
                    {
                        PolicyName = policyName,
                        ServiceName = serviceName,
                        ProgramCsPath = programFile,
                        PermissionName = usage.PermissionName,
                        EndpointFiles = policyGroup.SelectMany(p => p.EndpointFiles).Distinct().ToList(),
                        UsageCount = policyGroup.Count()
                    });
                }
            }

            // Track all policies by service for reporting
            result.PoliciesByService[serviceName] = localRegisteredPolicies;
            
            fileStopwatch.Stop();
            Console.WriteLine($"{missingCount} missing ({fileStopwatch.ElapsedMilliseconds}ms)");
        }
        
        stopwatch.Stop();
        Console.WriteLine($"  ✅ Analysis complete ({stopwatch.ElapsedMilliseconds}ms total)");
        Console.WriteLine();

        return result;
    }

    /// <summary>
    /// Finds all registered policies from Program.cs files and PlatformServices extension files.
    /// </summary>
    private async Task<HashSet<string>> FindAllRegisteredPoliciesAsync(string solutionPath)
    {
        var allPolicies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Find all Program.cs files
        var programFiles = FindProgramFiles(solutionPath);
        var totalProgramFiles = programFiles.Count;
        var processedProgramFiles = 0;
        
        foreach (var programFile in programFiles)
        {
            processedProgramFiles++;
            if (processedProgramFiles % 5 == 0 || processedProgramFiles == totalProgramFiles)
            {
                Console.Write($"\r    Scanning Program.cs files: {processedProgramFiles}/{totalProgramFiles}");
            }
            
            var policies = await ExtractRegisteredPoliciesAsync(programFile);
            foreach (var policy in policies)
            {
                allPolicies.Add(policy);
            }
        }
        
        if (totalProgramFiles > 0)
        {
            Console.WriteLine(); // New line after progress
        }

        // Find PlatformServices extension files that register policies
        var platformServicesPath = Path.Combine(solutionPath, "Kronos.Sales.PlatformServices");
        if (Directory.Exists(platformServicesPath))
        {
            var extensionFiles = Directory.GetFiles(platformServicesPath, "*Extensions.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && 
                           !f.Contains("/Tests/") && !f.Contains("/tests/"))
                .ToList();

            if (extensionFiles.Any())
            {
                Console.Write($"    Scanning {extensionFiles.Count} PlatformServices extension file(s)...");
            }
            
            foreach (var extensionFile in extensionFiles)
            {
                var policies = await ExtractRegisteredPoliciesAsync(extensionFile);
                foreach (var policy in policies)
                {
                    allPolicies.Add(policy);
                }
            }
            
            if (extensionFiles.Any())
            {
                Console.WriteLine(" done");
            }
        }

        return allPolicies;
    }

    /// <summary>
    /// Builds a cache of policy name to permission name mappings from all AuthorizationPolicies.cs files.
    /// </summary>
    private async Task<Dictionary<string, string>> BuildPermissionCacheAsync(string solutionPath)
    {
        var cache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        
        var policyFiles = Directory.GetFiles(solutionPath, "AuthorizationPolicies.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/"))
            .ToList();

        foreach (var filePath in policyFiles)
        {
            try
            {
                var content = await File.ReadAllTextAsync(filePath);
                var lines = content.Split('\n');
                
                // Find all policy constants and their permissions
                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    
                    // Check if this line contains a constant definition
                    var constantMatch = Regex.Match(line, @"public\s+const\s+string\s+(\w+)\s*=\s*""[^""]+"";");
                    if (constantMatch.Success)
                    {
                        var policyName = constantMatch.Groups[1].Value;
                        
                        // Look backwards up to 25 lines for the permission comment
                        // Search from the line before the constant backwards
                        string? foundPermission = null;
                        for (int j = i - 1; j >= Math.Max(0, i - 25); j--)
                        {
                            var commentLine = lines[j];
                            
                            // Stop if we hit another constant definition (we've gone too far)
                            if (Regex.IsMatch(commentLine, @"public\s+const\s+string\s+\w+\s*="))
                            {
                                break;
                            }
                            
                            // Look for the Requires 'permission' pattern
                            var requiresMatch = Regex.Match(commentLine, @"Requires\s+'([^']+)'\s+permission", RegexOptions.IgnoreCase);
                            if (requiresMatch.Success && requiresMatch.Groups.Count > 1)
                            {
                                foundPermission = requiresMatch.Groups[1].Value;
                                break; // Found permission, stop searching
                            }
                        }
                        
                        // Only add if we found a permission and it's not already in cache
                        if (!string.IsNullOrEmpty(foundPermission) && !cache.ContainsKey(policyName))
                        {
                            cache[policyName] = foundPermission;
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
    /// Finds all RequireAuthorization calls and extracts policy names.
    /// </summary>
    private async Task<List<PolicyUsage>> FindPolicyUsagesAsync(string solutionPath, Dictionary<string, string> permissionCache)
    {
        var usages = new List<PolicyUsage>();
        
        var endpointFiles = Directory.GetFiles(solutionPath, "*Endpoints.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && 
                       !f.Contains("/Tests/") && !f.Contains("/tests/"))
            .ToList();

        var totalFiles = endpointFiles.Count;
        var processedFiles = 0;
        
        foreach (var filePath in endpointFiles)
        {
            processedFiles++;
            if (processedFiles % 10 == 0 || processedFiles == totalFiles)
            {
                Console.Write($"\r    Processing endpoint files: {processedFiles}/{totalFiles}");
            }
            
            try
            {
                var content = await File.ReadAllTextAsync(filePath);
                var syntaxTree = CSharpSyntaxTree.ParseText(content, path: filePath);
                var root = await syntaxTree.GetRootAsync();

                var serviceName = ExtractServiceName(filePath, solutionPath);

                // Find all RequireAuthorization calls
                var requireAuthCalls = root.DescendantNodes()
                    .OfType<InvocationExpressionSyntax>()
                    .Where(inv => inv.Expression is MemberAccessExpressionSyntax memberAccess &&
                                 memberAccess.Name.Identifier.ValueText == "RequireAuthorization")
                    .ToList();

                foreach (var call in requireAuthCalls)
                {
                    var policyName = ExtractPolicyName(call);
                    if (!string.IsNullOrEmpty(policyName))
                    {
                        // Look up permission from cache (much faster than searching files)
                        permissionCache.TryGetValue(policyName, out var permissionName);
                        
                        usages.Add(new PolicyUsage
                        {
                            PolicyName = policyName,
                            ServiceName = serviceName,
                            EndpointFiles = new List<string> { filePath },
                            PermissionName = permissionName
                        });
                    }
                }
            }
            catch
            {
                // Skip files that can't be parsed
                continue;
            }
        }
        
        if (totalFiles > 0)
        {
            Console.WriteLine(); // New line after progress
        }

        return usages;
    }

    /// <summary>
    /// Extracts policy name from RequireAuthorization call.
    /// </summary>
    private string? ExtractPolicyName(InvocationExpressionSyntax call)
    {
        if (call.ArgumentList.Arguments.Count == 0)
            return null;

        var arg = call.ArgumentList.Arguments[0].Expression;

        // Handle string literal: RequireAuthorization("PolicyName")
        if (arg is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
        {
            return literal.Token.ValueText;
        }

        // Handle constant reference: RequireAuthorization(AuthorizationPolicies.RequireProductCreate)
        // or fully qualified: RequireAuthorization(KS.PlatformServices.Constants.AuthorizationPolicies.RequireProductCreate)
        if (arg is MemberAccessExpressionSyntax memberAccess)
        {
            // Extract just the member name (e.g., "RequireProductCreate" from "AuthorizationPolicies.RequireProductCreate")
            // or from "KS.PlatformServices.Constants.AuthorizationPolicies.RequireProductCreate"
            var fullName = memberAccess.ToString();
            
            // Check if it contains "AuthorizationPolicies" to confirm it's a policy constant
            if (fullName.Contains("AuthorizationPolicies", StringComparison.OrdinalIgnoreCase))
            {
                // Extract the last part (the policy name)
                return memberAccess.Name.Identifier.ValueText;
            }
        }

        return null;
    }

    /// <summary>
    /// Finds Program.cs files in the solution.
    /// </summary>
    private List<string> FindProgramFiles(string solutionPath)
    {
        return Directory.GetFiles(solutionPath, "Program.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && 
                       !f.Contains("/Tests/") && !f.Contains("/tests/") &&
                       f.Contains("/Api/") || f.Contains(".Api/"))
            .ToList();
    }

    /// <summary>
    /// Extracts registered policies from a Program.cs file.
    /// </summary>
    private async Task<List<string>> ExtractRegisteredPoliciesAsync(string programFilePath)
    {
        var registeredPolicies = new List<string>();

        try
        {
            var content = await File.ReadAllTextAsync(programFilePath);
            var syntaxTree = CSharpSyntaxTree.ParseText(content, path: programFilePath);
            var root = await syntaxTree.GetRootAsync();

            // Find all AddPolicy calls
            var addPolicyCalls = root.DescendantNodes()
                .OfType<InvocationExpressionSyntax>()
                .Where(inv => inv.Expression is MemberAccessExpressionSyntax memberAccess &&
                             memberAccess.Name.Identifier.ValueText == "AddPolicy")
                .ToList();

            foreach (var call in addPolicyCalls)
            {
                if (call.ArgumentList.Arguments.Count > 0)
                {
                    var policyArg = call.ArgumentList.Arguments[0].Expression;
                    
                    // Handle string literal: AddPolicy("PolicyName", ...)
                    if (policyArg is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
                    {
                        registeredPolicies.Add(literal.Token.ValueText);
                    }
                    // Handle constant reference: AddPolicy(AuthorizationPolicies.RequireProductCreate, ...)
                    // or fully qualified: AddPolicy(KS.PlatformServices.Constants.AuthorizationPolicies.RequireProductCreate, ...)
                    else if (policyArg is MemberAccessExpressionSyntax memberAccess)
                    {
                        var fullName = memberAccess.ToString();
                        
                        // Check if it contains "AuthorizationPolicies" to confirm it's a policy constant
                        if (fullName.Contains("AuthorizationPolicies", StringComparison.OrdinalIgnoreCase))
                        {
                            // Extract the last part (the policy name)
                            registeredPolicies.Add(memberAccess.Name.Identifier.ValueText);
                        }
                        else
                        {
                            // Fallback: just use the member name
                            registeredPolicies.Add(memberAccess.Name.Identifier.ValueText);
                        }
                    }
                }
            }
        }
        catch
        {
            // Return empty list if file can't be parsed
        }

        return registeredPolicies;
    }


    /// <summary>
    /// Extracts service name from file path.
    /// </summary>
    private string ExtractServiceName(string filePath, string solutionRoot)
    {
        var relativePath = Path.GetRelativePath(solutionRoot, filePath).Replace('\\', '/');
        
        // Extract service name from path like: Kronos.Sales.InventoryService/KS.InventoryService.Api/Program.cs
        var match = Regex.Match(relativePath, @"Kronos\.Sales\.(\w+Service)");
        if (match.Success)
        {
            return match.Groups[1].Value;
        }

        // Fallback: try to extract from directory structure
        var parts = relativePath.Split('/');
        foreach (var part in parts)
        {
            if (part.EndsWith("Service", StringComparison.OrdinalIgnoreCase) && 
                part.Contains("."))
            {
                var serviceMatch = Regex.Match(part, @"\.(\w+Service)");
                if (serviceMatch.Success)
                {
                    return serviceMatch.Groups[1].Value;
                }
            }
        }

        return "Unknown";
    }

    /// <summary>
    /// Represents a policy usage in endpoint files.
    /// </summary>
    private class PolicyUsage
    {
        public string PolicyName { get; set; } = string.Empty;
        public string ServiceName { get; set; } = string.Empty;
        public List<string> EndpointFiles { get; set; } = new();
        public string? PermissionName { get; set; }
    }
}
