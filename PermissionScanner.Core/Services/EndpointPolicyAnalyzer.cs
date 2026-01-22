using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Analyzes endpoints to identify those missing authorization policies and suggests appropriate policies.
/// </summary>
public class EndpointPolicyAnalyzer
{
    private readonly EndpointAnalyzer _endpointAnalyzer;
    private readonly EndpointExclusionMatcher _exclusionMatcher;
    private readonly PolicyResolver _policyResolver;

    /// <summary>
    /// Initializes a new instance of the EndpointPolicyAnalyzer.
    /// </summary>
    /// <param name="endpointAnalyzer">The endpoint analyzer to discover endpoints.</param>
    /// <param name="exclusionMatcher">The exclusion matcher to identify public endpoints.</param>
    /// <param name="policyResolver">The policy resolver to map endpoints to policies.</param>
    public EndpointPolicyAnalyzer(
        EndpointAnalyzer endpointAnalyzer,
        EndpointExclusionMatcher exclusionMatcher,
        PolicyResolver policyResolver)
    {
        _endpointAnalyzer = endpointAnalyzer ?? throw new ArgumentNullException(nameof(endpointAnalyzer));
        _exclusionMatcher = exclusionMatcher ?? throw new ArgumentNullException(nameof(exclusionMatcher));
        _policyResolver = policyResolver ?? throw new ArgumentNullException(nameof(policyResolver));
    }

    /// <summary>
    /// Analyzes all endpoints in a solution and identifies those missing authorization policies.
    /// </summary>
    /// <param name="solutionPath">Path to the solution directory.</param>
    /// <returns>Analysis result containing endpoints that need policies applied.</returns>
    public async Task<EndpointPolicyAnalysisResult> AnalyzeAsync(string solutionPath)
    {
        // Discover all endpoints
        var endpoints = await _endpointAnalyzer.ScanSolutionAsync(solutionPath);
        return AnalyzeEndpoints(endpoints);
    }

    /// <summary>
    /// Analyzes a specific list of endpoints and identifies those missing authorization policies.
    /// </summary>
    /// <param name="endpoints">List of endpoints to analyze.</param>
    /// <returns>Analysis result containing endpoints that need policies applied.</returns>
    public EndpointPolicyAnalysisResult AnalyzeEndpoints(List<DiscoveredEndpoint> endpoints)
    {
        var result = new EndpointPolicyAnalysisResult
        {
            TotalEndpoints = endpoints.Count
        };

        foreach (var endpoint in endpoints)
        {
            // Check if endpoint is excluded (public endpoints)
            if (_exclusionMatcher.IsExcluded(endpoint.RouteTemplate))
            {
                result.ExcludedEndpoints.Add(endpoint);
                continue;
            }

            // Check if endpoint already has authorization
            if (endpoint.HasPolicy)
            {
                result.EndpointsWithPolicy.Add(endpoint);
                continue;
            }

            // Try to resolve a policy for this endpoint
            var policyResolution = _policyResolver.ResolvePolicy(endpoint);
            
            if (policyResolution != null)
            {
                result.EndpointsNeedingPolicy.Add(new EndpointPolicySuggestion
                {
                    Endpoint = endpoint,
                    SuggestedPolicy = policyResolution,
                    RequiresUsingStatement = !HasUsingStatement(endpoint, policyResolution)
                });
            }
            else
            {
                result.EndpointsWithoutPolicy.Add(endpoint);
            }
        }

        return result;
    }

    /// <summary>
    /// Checks if the endpoint's file has the necessary using statement for the policy.
    /// This is a simplified check - in practice, we'd need to read the file
    /// and check for the using statement. For now, we'll assume it needs to be added
    /// if it's a fully qualified namespace.
    /// </summary>
    private bool HasUsingStatement(DiscoveredEndpoint endpoint, PolicyResolution policyResolution)
    {
        // For shared policies, check if PlatformServices using exists
        if (policyResolution.Location.IsShared)
        {
            // Assume using statement is needed unless we can verify it exists
            // This will be checked more accurately during code modification
            return false;
        }

        // For service-specific policies, check if service constants using exists
        if (!string.IsNullOrEmpty(policyResolution.Location.ServiceName))
        {
            // Assume using statement is needed unless we can verify it exists
            return false;
        }

        return false;
    }
}

/// <summary>
/// Result of endpoint policy analysis.
/// </summary>
public class EndpointPolicyAnalysisResult
{
    /// <summary>
    /// Total number of endpoints discovered.
    /// </summary>
    public int TotalEndpoints { get; set; }

    /// <summary>
    /// Endpoints that already have authorization policies.
    /// </summary>
    public List<DiscoveredEndpoint> EndpointsWithPolicy { get; set; } = new();

    /// <summary>
    /// Endpoints that need authorization policies (with suggested policies).
    /// </summary>
    public List<EndpointPolicySuggestion> EndpointsNeedingPolicy { get; set; } = new();

    /// <summary>
    /// Endpoints that are excluded (public endpoints like health checks).
    /// </summary>
    public List<DiscoveredEndpoint> ExcludedEndpoints { get; set; } = new();

    /// <summary>
    /// Endpoints that don't have policies and couldn't be mapped to any policy.
    /// </summary>
    public List<DiscoveredEndpoint> EndpointsWithoutPolicy { get; set; } = new();
}

/// <summary>
/// Suggestion for applying a policy to an endpoint.
/// </summary>
public class EndpointPolicySuggestion
{
    /// <summary>
    /// The endpoint that needs a policy.
    /// </summary>
    public DiscoveredEndpoint Endpoint { get; set; } = null!;

    /// <summary>
    /// The suggested policy resolution.
    /// </summary>
    public PolicyResolution SuggestedPolicy { get; set; } = null!;

    /// <summary>
    /// Whether a using statement needs to be added to the file.
    /// </summary>
    public bool RequiresUsingStatement { get; set; }
}
