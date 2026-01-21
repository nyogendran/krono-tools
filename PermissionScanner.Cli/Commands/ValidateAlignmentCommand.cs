using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Generators;
using PermissionScanner.Core.Models;
using System.Text.RegularExpressions;

namespace PermissionScanner.Cli.Commands;

/// <summary>
/// Command to validate alignment between existing permissions/policies and generated ones.
/// Identifies misaligned constants that don't follow naming conventions.
/// </summary>
public class ValidateAlignmentCommand
{
    public static async Task<int> ExecuteAsync(string solutionPath, string platformServicesPath)
    {
        try
        {
            Console.WriteLine($"Validating alignment: {solutionPath}");
            Console.WriteLine();

            // Scan for endpoints and code references
            var endpointAnalyzer = new EndpointAnalyzer();
            var endpoints = await endpointAnalyzer.ScanSolutionAsync(solutionPath);
            
            var constantAnalyzer = new ConstantReferenceAnalyzer();
            var (codeReferencedPermissions, codeReferencedPolicies) = await constantAnalyzer.ScanForConstantReferencesAsync(solutionPath);

            // Generate expected permissions/policies
            var expectedPermissions = PermissionConstantsGenerator.ConvertToPermissions(endpoints, codeReferencedPermissions);
            var expectedPolicies = PolicyConstantsGenerator.ConvertToPolicies(expectedPermissions, codeReferencedPolicies);

            // Read existing constants files
            var existingPermissions = await ReadExistingConstantsAsync(platformServicesPath, solutionPath);
            var existingPolicies = await ReadExistingPoliciesAsync(platformServicesPath, solutionPath);

            // Compare and report misalignments
            var misalignments = FindMisalignments(expectedPermissions, expectedPolicies, existingPermissions, existingPolicies);

            if (misalignments.Count == 0)
            {
                Console.WriteLine("✅ All permissions and policies are aligned!");
                return 0;
            }

            Console.WriteLine($"⚠️  Found {misalignments.Count} misalignment(s):");
            Console.WriteLine();

            foreach (var misalignment in misalignments.OrderBy(m => m.Type).ThenBy(m => m.Name))
            {
                Console.WriteLine($"Type: {misalignment.Type}");
                Console.WriteLine($"  Name: {misalignment.Name}");
                Console.WriteLine($"  Location: {misalignment.Location}");
                Console.WriteLine($"  Issue: {misalignment.Issue}");
                if (!string.IsNullOrEmpty(misalignment.Suggestion))
                {
                    Console.WriteLine($"  Suggestion: {misalignment.Suggestion}");
                }
                Console.WriteLine();
            }

            return 1; // Exit code 1 = misalignments found
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

    private static async Task<Dictionary<string, (string Location, string Namespace)>> ReadExistingConstantsAsync(
        string platformServicesPath, string solutionPath)
    {
        var constants = new Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase);

        // Read PlatformServices constants
        var platformConstantsPath = Path.Combine(platformServicesPath.TrimEnd('/', '\\'), "Constants", "Permissions.cs");
        if (File.Exists(platformConstantsPath))
        {
            var content = await File.ReadAllTextAsync(platformConstantsPath);
            ExtractConstants(content, constants, "PlatformServices", platformConstantsPath);
        }

        // Read service-specific constants
        var serviceDirs = Directory.GetDirectories(solutionPath, "*Service", SearchOption.TopDirectoryOnly);
        foreach (var serviceDir in serviceDirs)
        {
            var apiDirs = Directory.GetDirectories(serviceDir, "*.Api", SearchOption.AllDirectories);
            foreach (var apiDir in apiDirs)
            {
                var constantsPath = Path.Combine(apiDir, "Constants", "Permissions.cs");
                if (File.Exists(constantsPath))
                {
                    var content = await File.ReadAllTextAsync(constantsPath);
                    var serviceName = Path.GetFileName(serviceDir).Replace("Kronos.Sales.", "").Replace("Service", "Service");
                    ExtractConstants(content, constants, serviceName, constantsPath);
                }
            }
        }

        return constants;
    }

    private static async Task<Dictionary<string, (string Location, string Namespace)>> ReadExistingPoliciesAsync(
        string platformServicesPath, string solutionPath)
    {
        var policies = new Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase);

        // Read PlatformServices policies
        var platformPoliciesPath = Path.Combine(platformServicesPath.TrimEnd('/', '\\'), "Constants", "AuthorizationPolicies.cs");
        if (File.Exists(platformPoliciesPath))
        {
            var content = await File.ReadAllTextAsync(platformPoliciesPath);
            ExtractPolicies(content, policies, "PlatformServices", platformPoliciesPath);
        }

        // Read service-specific policies
        var serviceDirs = Directory.GetDirectories(solutionPath, "*Service", SearchOption.TopDirectoryOnly);
        foreach (var serviceDir in serviceDirs)
        {
            var apiDirs = Directory.GetDirectories(serviceDir, "*.Api", SearchOption.AllDirectories);
            foreach (var apiDir in apiDirs)
            {
                var policiesPath = Path.Combine(apiDir, "Constants", "AuthorizationPolicies.cs");
                if (File.Exists(policiesPath))
                {
                    var content = await File.ReadAllTextAsync(policiesPath);
                    var serviceName = Path.GetFileName(serviceDir).Replace("Kronos.Sales.", "").Replace("Service", "Service");
                    ExtractPolicies(content, policies, serviceName, policiesPath);
                }
            }
        }

        return policies;
    }

    private static void ExtractConstants(string content, Dictionary<string, (string, string)> constants, string namespaceName, string filePath)
    {
        var pattern = @"public\s+const\s+string\s+(\w+)\s*=\s*""([^""]+)""";
        var matches = Regex.Matches(content, pattern);

        foreach (Match match in matches)
        {
            var constantName = match.Groups[1].Value;
            var permissionName = match.Groups[2].Value;
            constants[constantName] = (filePath, namespaceName);
        }
    }

    private static void ExtractPolicies(string content, Dictionary<string, (string, string)> policies, string namespaceName, string filePath)
    {
        var pattern = @"public\s+const\s+string\s+(\w+)\s*=\s*""([^""]+)""";
        var matches = Regex.Matches(content, pattern);

        foreach (Match match in matches)
        {
            var policyName = match.Groups[1].Value;
            var policyValue = match.Groups[2].Value;
            policies[policyName] = (filePath, namespaceName);
        }
    }

    private static List<Misalignment> FindMisalignments(
        List<PermissionDefinition> expectedPermissions,
        List<PolicyDefinition> expectedPolicies,
        Dictionary<string, (string Location, string Namespace)> existingPermissions,
        Dictionary<string, (string Location, string Namespace)> existingPolicies)
    {
        var misalignments = new List<Misalignment>();

        // Check permissions
        foreach (var expected in expectedPermissions)
        {
            if (!existingPermissions.ContainsKey(expected.ConstantName))
            {
                misalignments.Add(new Misalignment
                {
                    Type = "Permission",
                    Name = expected.ConstantName,
                    Location = "Not found",
                    Issue = $"Missing permission constant: {expected.ConstantName} (expected: {expected.PermissionName})",
                    Suggestion = $"Add: public const string {expected.ConstantName} = \"{expected.PermissionName}\";"
                });
            }
            else
            {
                var existing = existingPermissions[expected.ConstantName];
                // Check if permission name matches
                // (We'd need to read the actual value, but for now just check existence)
            }
        }

        // Check policies
        foreach (var expected in expectedPolicies)
        {
            if (!existingPolicies.ContainsKey(expected.PolicyName))
            {
                misalignments.Add(new Misalignment
                {
                    Type = "Policy",
                    Name = expected.PolicyName,
                    Location = "Not found",
                    Issue = $"Missing policy constant: {expected.PolicyName} (requires: {expected.RequiredPermission})",
                    Suggestion = $"Add: public const string {expected.PolicyName} = \"{expected.PolicyName}\";"
                });
            }
        }

        // Check for existing constants that don't match expected naming
        foreach (var existing in existingPermissions)
        {
            var expected = expectedPermissions.FirstOrDefault(p => 
                p.ConstantName.Equals(existing.Key, StringComparison.OrdinalIgnoreCase));
            
            if (expected == null)
            {
                // This is a manually added constant - check if it follows naming conventions
                var suggestedPermission = ConvertConstantNameToPermissionName(existing.Key);
                if (!string.IsNullOrEmpty(suggestedPermission))
                {
                    var suggestedConstant = PermissionNameGenerator.GenerateConstantName(suggestedPermission);
                    if (!suggestedConstant.Equals(existing.Key, StringComparison.OrdinalIgnoreCase))
                    {
                        misalignments.Add(new Misalignment
                        {
                            Type = "Permission",
                            Name = existing.Key,
                            Location = existing.Value.Location,
                            Issue = $"Constant name doesn't follow naming convention",
                            Suggestion = $"Consider renaming to: {suggestedConstant} (for permission: {suggestedPermission})"
                        });
                    }
                }
            }
        }

        return misalignments;
    }

    private static string ConvertConstantNameToPermissionName(string constantName)
    {
        // Simple conversion - split on capital letters and convert to kebab-case
        var words = Regex.Split(constantName, @"(?<!^)(?=[A-Z])");
        if (words.Length < 2) return string.Empty;

        var resource = words[0].ToLowerInvariant();
        var action = string.Join("-", words.Skip(1).Select(w => w.ToLowerInvariant()));
        return $"{resource}:{action}";
    }
}

internal class Misalignment
{
    public string Type { get; set; } = string.Empty; // "Permission" or "Policy"
    public string Name { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public string Issue { get; set; } = string.Empty;
    public string Suggestion { get; set; } = string.Empty;
}
