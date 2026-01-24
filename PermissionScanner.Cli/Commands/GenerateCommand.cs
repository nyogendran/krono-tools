using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Generators;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Cli.Commands;

/// <summary>
/// Command to generate permission and policy constants.
/// Supports hybrid generation: shared permissions to PlatformServices, service-specific to individual services.
/// </summary>
public class GenerateCommand
{
    public static async Task<int> ExecuteAsync(string solutionPath, string platformServicesPath, bool updateFiles, string scope, string? emitFrontendPath = null)
    {
        try
        {
            Console.WriteLine($"Scanning solution: {solutionPath}");
            
            // Scan for endpoints
            var endpointAnalyzer = new EndpointAnalyzer();
            var endpoints = await endpointAnalyzer.ScanSolutionAsync(solutionPath);
            Console.WriteLine($"Discovered {endpoints.Count} endpoints");

            // Scan for code-referenced constants (permissions/policies referenced in code but not from endpoints)
            var constantAnalyzer = new ConstantReferenceAnalyzer();
            var (codeReferencedPermissions, codeReferencedPolicies) = await constantAnalyzer.ScanForConstantReferencesAsync(solutionPath);
            Console.WriteLine($"Found {codeReferencedPermissions.Count} code-referenced permissions, {codeReferencedPolicies.Count} code-referenced policies");

            // Convert to permissions (merge endpoint-discovered + code-referenced)
            // Important: Code-referenced permissions with PlatformServices scope should be added to shared
            var allPermissions = PermissionConstantsGenerator.ConvertToPermissions(endpoints, codeReferencedPermissions);
            
            // Check for and warn about filtered "unknown" permissions
            // Exclude root endpoints (they're public redirects and correctly classified as "unknown")
            var exclusionMatcher = new EndpointExclusionMatcher();
            var unknownEndpoints = endpoints
                .Where(e => e.Resource.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                .Where(e => !exclusionMatcher.IsExcluded(e.RouteTemplate))  // Exclude public endpoints
                .ToList();
            if (unknownEndpoints.Any())
            {
                Console.WriteLine();
                Console.WriteLine($"⚠️  Warning: Found {unknownEndpoints.Count} endpoint(s) with 'unknown' resource (filtered out):");
                
                var endpointsWithSuggestions = new List<(DiscoveredEndpoint Endpoint, string SuggestedPermission, string SuggestedConstant)>();
                var endpointsWithoutSuggestions = new List<DiscoveredEndpoint>();
                
                foreach (var endpoint in unknownEndpoints)
                {
                    var suggestion = PermissionNameGenerator.SuggestPermissionForUnknown(
                        endpoint.HttpMethod, 
                        endpoint.RouteTemplate);
                    
                    if (suggestion.HasValue)
                    {
                        endpointsWithSuggestions.Add((
                            endpoint, 
                            suggestion.Value.PermissionName, 
                            suggestion.Value.ConstantName));
                    }
                    else
                    {
                        endpointsWithoutSuggestions.Add(endpoint);
                    }
                }
                
                // Show endpoints with suggestions
                if (endpointsWithSuggestions.Any())
                {
                    Console.WriteLine();
                    Console.WriteLine("   💡 Suggested permissions (review and add manually if correct):");
                    foreach (var (endpoint, suggestedPermission, suggestedConstant) in endpointsWithSuggestions.Take(10))
                    {
                        Console.WriteLine($"   - {endpoint.HttpMethod} {endpoint.RouteTemplate}");
                        Console.WriteLine($"     → Suggested: {suggestedPermission} ({suggestedConstant})");
                    }
                    if (endpointsWithSuggestions.Count > 10)
                    {
                        Console.WriteLine($"   ... and {endpointsWithSuggestions.Count - 10} more with suggestions");
                    }
                }
                
                // Show endpoints without suggestions
                if (endpointsWithoutSuggestions.Any())
                {
                    Console.WriteLine();
                    Console.WriteLine("   ⚠️  Endpoints without suggestions (may not need permissions):");
                    foreach (var endpoint in endpointsWithoutSuggestions.Take(5))
                    {
                        Console.WriteLine($"   - {endpoint.HttpMethod} {endpoint.RouteTemplate}");
                    }
                    if (endpointsWithoutSuggestions.Count > 5)
                    {
                        Console.WriteLine($"   ... and {endpointsWithoutSuggestions.Count - 5} more");
                    }
                }
                
                Console.WriteLine();
                Console.WriteLine("   📝 Next steps:");
                if (endpointsWithSuggestions.Any())
                {
                    Console.WriteLine("   1. Review suggested permissions above");
                    Console.WriteLine("   2. If correct, manually add them to Permissions.cs");
                    Console.WriteLine("   3. If incorrect, improve route template or extraction logic");
                }
                if (endpointsWithoutSuggestions.Any())
                {
                    Console.WriteLine("   • Endpoints without suggestions may be public (health checks, redirects)");
                }
            }
            
            // Ensure PlatformServices-scoped code-referenced permissions are marked as Shared
            foreach (var perm in allPermissions)
            {
                if (perm.Services.Contains("PlatformServices", StringComparer.OrdinalIgnoreCase))
                {
                    perm.Scope = "Shared";
                }
            }
            
            Console.WriteLine($"Generated {allPermissions.Count} unique permissions (including code-referenced)");

            // Filter permissions by scope
            var (sharedPermissions, serviceSpecificPermissions) = FilterPermissionsByScope(allPermissions, scope);
            
            Console.WriteLine();
            Console.WriteLine($"Classification Results:");
            Console.WriteLine($"  Shared permissions: {sharedPermissions.Count}");
            Console.WriteLine($"  Service-specific permissions: {serviceSpecificPermissions.Values.Sum(p => p.Count)}");

            // Convert to policies (for shared permissions only - service-specific policies handled separately)
            // Include any code-referenced policies whose required permission matches a shared permission
            var sharedCodePolicies = codeReferencedPolicies
                .Where(p => sharedPermissions.Any(sp =>
                    string.Equals(sp.PermissionName, p.RequiredPermission, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            var sharedPolicies = PolicyConstantsGenerator.ConvertToPolicies(sharedPermissions, sharedCodePolicies);
            Console.WriteLine($"Generated {sharedPolicies.Count} shared policy definitions");

            if (updateFiles)
            {
                // Generate shared permissions to PlatformServices
                await GenerateSharedPermissions(platformServicesPath, sharedPermissions, sharedPolicies);

                // Generate service-specific permissions to each service
                if (scope == "all" || scope == "shared")
                {
                    await GenerateServiceSpecificPermissions(solutionPath, serviceSpecificPermissions, codeReferencedPolicies);
                }

                Console.WriteLine();
                Console.WriteLine("✅ Constants generated successfully!");
            }
            else
            {
                // Dry-run mode: show what would be generated
                PrintClassificationReport(sharedPermissions, serviceSpecificPermissions, sharedPolicies);
            }

            // Emit frontend TypeScript (optional, uses same permission set as backend)
            if (!string.IsNullOrWhiteSpace(emitFrontendPath))
            {
                var allForFrontend = sharedPermissions.Concat(serviceSpecificPermissions.Values.SelectMany(x => x)).ToList();
                await EmitFrontendPermissionsAsync(emitFrontendPath.Trim(), allForFrontend);
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.Error.WriteLine($"  {ex.InnerException.Message}");
            }
            Console.Error.WriteLine(ex.StackTrace);
            return 1;
        }
    }

    /// <summary>
    /// Filters permissions by scope and returns shared and service-specific groups.
    /// </summary>
    private static (List<PermissionDefinition> Shared, Dictionary<string, List<PermissionDefinition>> ServiceSpecific) 
        FilterPermissionsByScope(List<PermissionDefinition> allPermissions, string scope)
    {
        var shared = new List<PermissionDefinition>();
        var serviceSpecific = new Dictionary<string, List<PermissionDefinition>>(StringComparer.OrdinalIgnoreCase);

        foreach (var permission in allPermissions)
        {
            if (permission.Scope == "Shared")
            {
                if (scope == "all" || scope == "shared")
                {
                    shared.Add(permission);
                }
            }
            else // ServiceSpecific
            {
                // Group by service
                foreach (var serviceName in permission.Services)
                {
                    if (scope == "all" || scope.Equals(serviceName, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!serviceSpecific.ContainsKey(serviceName))
                        {
                            serviceSpecific[serviceName] = new List<PermissionDefinition>();
                        }
                        // Only add if not already added for this service
                        if (!serviceSpecific[serviceName].Any(p => p.PermissionName == permission.PermissionName))
                        {
                            serviceSpecific[serviceName].Add(permission);
                        }
                    }
                }
            }
        }

        return (shared, serviceSpecific);
    }

    /// <summary>
    /// Generates shared permissions to PlatformServices Constants directory.
    /// </summary>
    private static async Task GenerateSharedPermissions(
        string platformServicesPath, 
        List<PermissionDefinition> sharedPermissions, 
        List<PolicyDefinition> sharedPolicies)
    {
        // Determine the Constants directory path
        var constantsDir = platformServicesPath.TrimEnd('/', '\\');
        if (!constantsDir.EndsWith("Constants", StringComparison.OrdinalIgnoreCase))
        {
            constantsDir = Path.Combine(constantsDir, "Constants");
        }
        
        Directory.CreateDirectory(constantsDir);

        // Read existing Permissions.cs to preserve manual additions
        var permissionsFilePath = Path.Combine(constantsDir, "Permissions.cs");
        var existingPermissions = File.Exists(permissionsFilePath) 
            ? await File.ReadAllTextAsync(permissionsFilePath) 
            : string.Empty;

        // Generate Permissions.cs (merge with existing)
        var permissionsContent = PermissionConstantsGenerator.GenerateFileContent(
            sharedPermissions, 
            existingPermissions, 
            namespaceName: "KS.PlatformServices.Constants");
        await File.WriteAllTextAsync(permissionsFilePath, permissionsContent);
        Console.WriteLine($"✅ Updated: {permissionsFilePath} ({sharedPermissions.Count} permissions)");

        // Read existing AuthorizationPolicies.cs to preserve manual policies
        var policiesFilePath = Path.Combine(constantsDir, "AuthorizationPolicies.cs");
        var existingPolicies = File.Exists(policiesFilePath) 
            ? await File.ReadAllTextAsync(policiesFilePath) 
            : string.Empty;

        // Generate AuthorizationPolicies.cs
        var policiesContent = PolicyConstantsGenerator.GenerateFileContent(sharedPolicies, existingPolicies);
        await File.WriteAllTextAsync(policiesFilePath, policiesContent);
        Console.WriteLine($"✅ Updated: {policiesFilePath} ({sharedPolicies.Count} policies)");
    }

    /// <summary>
    /// Generates service-specific permissions to each service's Constants directory.
    /// </summary>
    private static async Task GenerateServiceSpecificPermissions(
        string solutionPath,
        Dictionary<string, List<PermissionDefinition>> serviceSpecificPermissions,
        List<PolicyDefinition> codeReferencedPolicies)
    {
        foreach (var (serviceName, permissions) in serviceSpecificPermissions.OrderBy(kvp => kvp.Key))
        {
            // Find service's Constants directory
            var constantsDir = FindServiceConstantsDirectory(solutionPath, serviceName);
            if (constantsDir == null)
            {
                Console.WriteLine($"⚠️  Warning: Could not find Constants directory for {serviceName}, skipping");
                continue;
            }

            Directory.CreateDirectory(constantsDir);

            // Determine namespace from service name
            var namespaceName = GetServiceNamespace(serviceName);

            // Read existing Permissions.cs if it exists
            var permissionsFilePath = Path.Combine(constantsDir, "Permissions.cs");
            var existingPermissions = File.Exists(permissionsFilePath) 
                ? await File.ReadAllTextAsync(permissionsFilePath) 
                : string.Empty;

            // Generate Permissions.cs for this service
            var permissionsContent = PermissionConstantsGenerator.GenerateFileContent(
                permissions, 
                existingPermissions, 
                namespaceName: namespaceName);
            await File.WriteAllTextAsync(permissionsFilePath, permissionsContent);
            Console.WriteLine($"✅ Updated: {permissionsFilePath} ({permissions.Count} permissions for {serviceName})");

            // Generate policies for this service
            // Include any code-referenced policies whose required permission matches a permission in this service
            var serviceCodePolicies = codeReferencedPolicies
                .Where(p => permissions.Any(sp =>
                    string.Equals(sp.PermissionName, p.RequiredPermission, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            var policies = PolicyConstantsGenerator.ConvertToPolicies(permissions, serviceCodePolicies);
            var policiesFilePath = Path.Combine(constantsDir, "AuthorizationPolicies.cs");
            var existingPolicies = File.Exists(policiesFilePath) 
                ? await File.ReadAllTextAsync(policiesFilePath) 
                : string.Empty;

            var policiesContent = PolicyConstantsGenerator.GenerateFileContent(policies, existingPolicies, namespaceName: namespaceName);
            await File.WriteAllTextAsync(policiesFilePath, policiesContent);
            Console.WriteLine($"✅ Updated: {policiesFilePath} ({policies.Count} policies for {serviceName})");
        }
    }

    /// <summary>
    /// Finds the Constants directory for a given service.
    /// </summary>
    private static string? FindServiceConstantsDirectory(string solutionPath, string serviceName)
    {
        // Map service names to project directory patterns
        // e.g., "ProductService" -> "Kronos.Sales.ProductService/KS.ProductService.Api/Constants"
        var serviceDirPattern = $"*{serviceName}";
        var apiProjectPattern = $"KS.{serviceName}.Api";

        // Search for the service directory
        var serviceDirs = Directory.GetDirectories(solutionPath, serviceDirPattern, SearchOption.TopDirectoryOnly);
        if (serviceDirs.Length == 0)
        {
            return null;
        }

        var serviceDir = serviceDirs[0]; // Take first match

        // Find the API project directory
        var apiProjectDirs = Directory.GetDirectories(serviceDir, apiProjectPattern, SearchOption.AllDirectories);
        if (apiProjectDirs.Length == 0)
        {
            return null;
        }

        var apiProjectDir = apiProjectDirs[0];
        var constantsDir = Path.Combine(apiProjectDir, "Constants");

        return constantsDir;
    }

    /// <summary>
    /// Gets the namespace for a service's Constants class.
    /// </summary>
    private static string GetServiceNamespace(string serviceName)
    {
        // e.g., "ProductService" -> "KS.ProductService.Api.Constants"
        return $"KS.{serviceName}.Api.Constants";
    }

    /// <summary>
    /// Prints a classification report in dry-run mode.
    /// </summary>
    private static void PrintClassificationReport(
        List<PermissionDefinition> sharedPermissions,
        Dictionary<string, List<PermissionDefinition>> serviceSpecificPermissions,
        List<PolicyDefinition> sharedPolicies)
    {
        Console.WriteLine();
        Console.WriteLine("=== Classification Report ===");
        Console.WriteLine();
        
        Console.WriteLine($"PlatformServices (Shared): {sharedPermissions.Count} permissions");
        foreach (var perm in sharedPermissions.Take(10))
        {
            Console.WriteLine($"  - {perm.PermissionName} ({perm.ConstantName})");
        }
        if (sharedPermissions.Count > 10)
        {
            Console.WriteLine($"  ... and {sharedPermissions.Count - 10} more");
        }

        Console.WriteLine();
        foreach (var (serviceName, permissions) in serviceSpecificPermissions.OrderBy(kvp => kvp.Key))
        {
            Console.WriteLine($"{serviceName} (Service-specific): {permissions.Count} permissions");
            foreach (var perm in permissions.Take(5))
            {
                Console.WriteLine($"  - {perm.PermissionName} ({perm.ConstantName})");
            }
            if (permissions.Count > 5)
            {
                Console.WriteLine($"  ... and {permissions.Count - 5} more");
            }
            Console.WriteLine();
        }

        Console.WriteLine();
        Console.WriteLine("Use --update-files to write constants to files");
        Console.WriteLine("Use --scope <scope> to filter (options: 'shared', 'all', or service name)");
        Console.WriteLine("Use --emit-frontend <path> to write permissions.generated.ts to kronos-app");
    }

    /// <summary>
    /// Emits TypeScript BACKEND_PERMISSIONS to kronos-app/src/constants/permissions.generated.ts.
    /// </summary>
    private static async Task EmitFrontendPermissionsAsync(string kronosAppRoot, List<PermissionDefinition> permissions)
    {
        var dir = Path.Combine(kronosAppRoot, "src", "constants");
        Directory.CreateDirectory(dir);
        var filePath = Path.Combine(dir, "permissions.generated.ts");
        var content = FrontendPermissionConstantsGenerator.GenerateTypeScript(permissions);
        await File.WriteAllTextAsync(filePath, content);
        Console.WriteLine($"✅ Emitted frontend permissions: {filePath} ({permissions.Count} permissions)");
    }
}
