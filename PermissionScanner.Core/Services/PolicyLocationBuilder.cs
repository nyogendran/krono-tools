using PermissionScanner.Core.Analyzers;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Helper class to build policy location maps from existing constants files.
/// </summary>
public static class PolicyLocationBuilder
{
    /// <summary>
    /// Builds a policy location map from the ApplyCommand's policy dictionary.
    /// </summary>
    /// <param name="policies">Dictionary from ApplyCommand.ReadExistingConstantsAsync.</param>
    /// <returns>Dictionary mapping policy names to PolicyResolver.PolicyLocation objects.</returns>
    public static Dictionary<string, PolicyResolver.PolicyLocation> BuildPolicyLocationMap(
        Dictionary<string, ApplyCommandPolicyLocation> policies)
    {
        var result = new Dictionary<string, PolicyResolver.PolicyLocation>();

        foreach (var kvp in policies)
        {
            var policyName = kvp.Key;
            var location = kvp.Value;

            string namespacePath;
            if (location.IsShared)
            {
                namespacePath = "KS.PlatformServices.Constants.AuthorizationPolicies";
            }
            else
            {
                var serviceName = location.ServiceName ?? "UnknownService";
                namespacePath = $"KS.{serviceName}.Api.Constants.AuthorizationPolicies";
            }

            result[policyName] = new PolicyResolver.PolicyLocation
            {
                PolicyName = policyName,
                IsShared = location.IsShared,
                ServiceName = location.ServiceName,
                Namespace = namespacePath
            };
        }

        return result;
    }
}

/// <summary>
/// Policy location structure from ApplyCommand (simplified version for compatibility).
/// </summary>
public class ApplyCommandPolicyLocation
{
    /// <summary>
    /// Whether this is a shared policy (PlatformServices) or service-specific.
    /// </summary>
    public bool IsShared { get; set; }

    /// <summary>
    /// Service name if service-specific, null if shared.
    /// </summary>
    public string? ServiceName { get; set; }
}
