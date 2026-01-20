using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Generators;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Cli.Commands;

/// <summary>
/// Command to generate permission and policy constants.
/// </summary>
public class GenerateCommand
{
    public static async Task<int> ExecuteAsync(string solutionPath, string platformServicesPath, bool updateFiles)
    {
        try
        {
            Console.WriteLine($"Scanning solution: {solutionPath}");
            
            // Scan for endpoints
            var analyzer = new EndpointAnalyzer();
            var endpoints = await analyzer.ScanSolutionAsync(solutionPath);

            Console.WriteLine($"Discovered {endpoints.Count} endpoints");

            // Convert to permissions
            var permissions = PermissionConstantsGenerator.ConvertToPermissions(endpoints);
            Console.WriteLine($"Generated {permissions.Count} unique permissions");

            // Convert to policies
            var policies = PolicyConstantsGenerator.ConvertToPolicies(permissions);
            Console.WriteLine($"Generated {policies.Count} policy definitions");

            if (updateFiles)
            {
                // Determine the Constants directory path
                // Handle both cases:
                // 1. Path points to Constants directory: ../../.../KS.PlatformServices/Constants/
                // 2. Path points to project root: ../../.../KS.PlatformServices/
                var constantsDir = platformServicesPath.TrimEnd('/', '\\');
                if (!constantsDir.EndsWith("Constants", StringComparison.OrdinalIgnoreCase))
                {
                    // Path points to project root, append Constants
                    constantsDir = Path.Combine(constantsDir, "Constants");
                }
                
                // Ensure directory exists
                Directory.CreateDirectory(constantsDir);

                // Read existing Permissions.cs to preserve manual additions (if any)
                var permissionsFilePath = Path.Combine(constantsDir, "Permissions.cs");
                var existingPermissions = File.Exists(permissionsFilePath) 
                    ? await File.ReadAllTextAsync(permissionsFilePath) 
                    : string.Empty;

                // Generate Permissions.cs (merge with existing)
                var permissionsContent = PermissionConstantsGenerator.GenerateFileContent(permissions, existingPermissions);
                await File.WriteAllTextAsync(permissionsFilePath, permissionsContent);
                Console.WriteLine($"Updated: {permissionsFilePath}");

                // Read existing AuthorizationPolicies.cs to preserve manual policies
                var policiesFilePath = Path.Combine(constantsDir, "AuthorizationPolicies.cs");
                var existingPolicies = File.Exists(policiesFilePath) 
                    ? await File.ReadAllTextAsync(policiesFilePath) 
                    : string.Empty;

                // Generate AuthorizationPolicies.cs
                var policiesContent = PolicyConstantsGenerator.GenerateFileContent(policies, existingPolicies);
                await File.WriteAllTextAsync(policiesFilePath, policiesContent);
                Console.WriteLine($"Updated: {policiesFilePath}");

                Console.WriteLine();
                Console.WriteLine("✅ Constants generated successfully!");
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("=== Generated Permissions ===");
                foreach (var permission in permissions.Take(20))
                {
                    Console.WriteLine($"  {permission.PermissionName} -> {permission.ConstantName}");
                }
                if (permissions.Count > 20)
                {
                    Console.WriteLine($"  ... and {permissions.Count - 20} more");
                }

                Console.WriteLine();
                Console.WriteLine("=== Generated Policies ===");
                foreach (var policy in policies.Take(20))
                {
                    Console.WriteLine($"  {policy.PolicyName} -> {policy.RequiredPermission}");
                }
                if (policies.Count > 20)
                {
                    Console.WriteLine($"  ... and {policies.Count - 20} more");
                }

                Console.WriteLine();
                Console.WriteLine("Use --update-files to write to PlatformServices/Constants/");
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
}
