using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Analyzers;

/// <summary>
/// Resolves appropriate authorization policy for an endpoint based on route, HTTP method, and available policies.
/// </summary>
public class PolicyResolver
{
    private readonly Dictionary<string, PolicyLocation> _policyLocations;
    private readonly string? _defaultPolicy;
    private readonly string _serviceName;

    /// <summary>
    /// Represents the location of a policy constant.
    /// </summary>
    public class PolicyLocation
    {
        /// <summary>
        /// Policy constant name (e.g., "RequireProductCreate").
        /// </summary>
        public string PolicyName { get; set; } = string.Empty;

        /// <summary>
        /// Whether this is a shared policy (PlatformServices) or service-specific.
        /// </summary>
        public bool IsShared { get; set; }

        /// <summary>
        /// Service name if service-specific, null if shared.
        /// </summary>
        public string? ServiceName { get; set; }

        /// <summary>
        /// Full namespace path (e.g., "KS.PlatformServices.Constants.AuthorizationPolicies").
        /// </summary>
        public string Namespace { get; set; } = string.Empty;
    }

    /// <summary>
    /// Initializes a new instance of the PolicyResolver.
    /// </summary>
    /// <param name="policyLocations">Dictionary mapping policy names to their locations.</param>
    /// <param name="serviceName">Name of the service for the endpoint.</param>
    /// <param name="defaultPolicy">Optional default policy name to use when no specific policy is found.</param>
    public PolicyResolver(
        Dictionary<string, PolicyLocation> policyLocations,
        string serviceName,
        string? defaultPolicy = null)
    {
        _policyLocations = policyLocations ?? throw new ArgumentNullException(nameof(policyLocations));
        _serviceName = serviceName ?? throw new ArgumentNullException(nameof(serviceName));
        _defaultPolicy = defaultPolicy;
    }

    /// <summary>
    /// Resolves the appropriate policy for an endpoint.
    /// </summary>
    /// <param name="endpoint">The discovered endpoint.</param>
    /// <returns>Policy resolution result, or null if no policy should be applied.</returns>
    public PolicyResolution? ResolvePolicy(DiscoveredEndpoint endpoint)
    {
        if (endpoint == null)
            throw new ArgumentNullException(nameof(endpoint));

        // If endpoint already has a policy, don't suggest a new one
        if (endpoint.HasPolicy)
            return null;

        // Try to find matching policy based on suggested policy name
        var suggestedPolicy = endpoint.SuggestedPolicy;
        if (!string.IsNullOrEmpty(suggestedPolicy) && _policyLocations.TryGetValue(suggestedPolicy, out var location))
        {
            return new PolicyResolution
            {
                PolicyName = suggestedPolicy,
                Location = location,
                ResolutionStrategy = "GeneratedPolicy",
                IsExactMatch = true
            };
        }

        // Try alternative policy name variations
        var alternativePolicy = TryFindAlternativePolicy(endpoint);
        if (alternativePolicy != null)
        {
            return alternativePolicy;
        }

        // Use default policy if specified
        if (!string.IsNullOrEmpty(_defaultPolicy) && _policyLocations.TryGetValue(_defaultPolicy, out var defaultLocation))
        {
            return new PolicyResolution
            {
                PolicyName = _defaultPolicy,
                Location = defaultLocation,
                ResolutionStrategy = "DefaultPolicy",
                IsExactMatch = false
            };
        }

        // No policy found
        return null;
    }

    /// <summary>
    /// Tries to find an alternative policy based on resource and action.
    /// </summary>
    private PolicyResolution? TryFindAlternativePolicy(DiscoveredEndpoint endpoint)
    {
        // Try service-specific policies first
        var serviceSpecificPolicy = FindServiceSpecificPolicy(endpoint);
        if (serviceSpecificPolicy != null)
            return serviceSpecificPolicy;

        // Try shared policies
        var sharedPolicy = FindSharedPolicy(endpoint);
        if (sharedPolicy != null)
            return sharedPolicy;

        return null;
    }

    /// <summary>
    /// Finds a service-specific policy for the endpoint.
    /// </summary>
    private PolicyResolution? FindServiceSpecificPolicy(DiscoveredEndpoint endpoint)
    {
        // Look for policies in the service's namespace
        var servicePolicies = _policyLocations
            .Where(kvp => !kvp.Value.IsShared && 
                         string.Equals(kvp.Value.ServiceName, _serviceName, StringComparison.OrdinalIgnoreCase))
            .ToList();

        // Try to match based on resource and action
        var matchingPolicy = servicePolicies.FirstOrDefault(kvp =>
        {
            var policyName = kvp.Key;
            // Simple heuristic: check if policy name contains resource or action keywords
            var resourceMatch = endpoint.Resource.Split(':')
                .Any(r => policyName.Contains(r, StringComparison.OrdinalIgnoreCase));
            var actionMatch = endpoint.Action != null && 
                            policyName.Contains(endpoint.Action, StringComparison.OrdinalIgnoreCase);
            
            return resourceMatch || actionMatch;
        });

        if (matchingPolicy.Key != null)
        {
            return new PolicyResolution
            {
                PolicyName = matchingPolicy.Key,
                Location = matchingPolicy.Value,
                ResolutionStrategy = "ServiceSpecificPolicy",
                IsExactMatch = false
            };
        }

        return null;
    }

    /// <summary>
    /// Finds a shared policy for the endpoint.
    /// </summary>
    private PolicyResolution? FindSharedPolicy(DiscoveredEndpoint endpoint)
    {
        // Look for shared policies
        var sharedPolicies = _policyLocations
            .Where(kvp => kvp.Value.IsShared)
            .ToList();

        // Try common shared policies based on resource type
        var resource = endpoint.Resource.ToLowerInvariant();
        
        // Platform-level resources should use shared policies
        if (resource.StartsWith("platform") || 
            resource.StartsWith("rbac") || 
            resource.StartsWith("permissions") ||
            resource.StartsWith("roles") ||
            resource.StartsWith("tenant"))
        {
            // Look for matching shared policy
            var matchingPolicy = sharedPolicies.FirstOrDefault(kvp =>
            {
                var policyName = kvp.Key.ToLowerInvariant();
                return policyName.Contains(resource.Split(':').First(), StringComparison.OrdinalIgnoreCase);
            });

            if (matchingPolicy.Key != null)
            {
                return new PolicyResolution
                {
                    PolicyName = matchingPolicy.Key,
                    Location = matchingPolicy.Value,
                    ResolutionStrategy = "SharedPolicy",
                    IsExactMatch = false
                };
            }
        }

        // Try generic shared policies (e.g., RequireProductAccess for product-related endpoints)
        if (resource.Contains("product"))
        {
            var productAccessPolicy = sharedPolicies.FirstOrDefault(kvp =>
                kvp.Key.Contains("ProductAccess", StringComparison.OrdinalIgnoreCase));
            
            if (productAccessPolicy.Key != null)
            {
                return new PolicyResolution
                {
                    PolicyName = productAccessPolicy.Key,
                    Location = productAccessPolicy.Value,
                    ResolutionStrategy = "SharedPolicy",
                    IsExactMatch = false
                };
            }
        }

        return null;
    }

    /// <summary>
    /// Builds the full policy reference string for code generation.
    /// </summary>
    /// <param name="resolution">The policy resolution result.</param>
    /// <param name="hasUsingStatement">Whether a using statement for the namespace already exists.</param>
    /// <returns>The policy reference string (e.g., "AuthorizationPolicies.RequireProductCreate" or "KS.PlatformServices.Constants.AuthorizationPolicies.RequireProductCreate").</returns>
    public string BuildPolicyReference(PolicyResolution resolution, bool hasUsingStatement)
    {
        if (resolution == null)
            throw new ArgumentNullException(nameof(resolution));

        var policyName = resolution.PolicyName;
        
        if (hasUsingStatement)
        {
            // Use short form: AuthorizationPolicies.RequireProductCreate
            return $"AuthorizationPolicies.{policyName}";
        }
        else
        {
            // Use fully qualified: KS.PlatformServices.Constants.AuthorizationPolicies.RequireProductCreate
            return $"{resolution.Location.Namespace}.{policyName}";
        }
    }
}

/// <summary>
/// Represents the result of policy resolution for an endpoint.
/// </summary>
public class PolicyResolution
{
    /// <summary>
    /// The resolved policy name (e.g., "RequireProductCreate").
    /// </summary>
    public string PolicyName { get; set; } = string.Empty;

    /// <summary>
    /// The location of the policy constant.
    /// </summary>
    public PolicyResolver.PolicyLocation Location { get; set; } = null!;

    /// <summary>
    /// Strategy used to resolve the policy (e.g., "GeneratedPolicy", "ServiceSpecificPolicy", "SharedPolicy", "DefaultPolicy").
    /// </summary>
    public string ResolutionStrategy { get; set; } = string.Empty;

    /// <summary>
    /// Whether this is an exact match (true) or a fallback/alternative (false).
    /// </summary>
    public bool IsExactMatch { get; set; }
}
