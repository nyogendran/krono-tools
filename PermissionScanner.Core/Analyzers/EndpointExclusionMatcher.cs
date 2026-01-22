using System.Text.RegularExpressions;

namespace PermissionScanner.Core.Analyzers;

/// <summary>
/// Matches endpoint routes against exclusion patterns to identify public endpoints
/// that should not have authorization policies applied.
/// </summary>
public class EndpointExclusionMatcher
{
    private readonly List<string> _defaultExclusions = new()
    {
        // Root redirect endpoints (public, no permissions needed)
        "^/$",
        "/",
        
        // Health check endpoints (various patterns)
        "/health",
        "/health/*",
        "/healthz",
        "/ready",
        "/live",
        "/api/health",
        "/api/health/*",
        "/api/v*/health*",
        "/api/v*/health-test",
        "/api/v*/health/*",
        
        // Swagger endpoints
        "/swagger",
        "/swagger/*",
        "/swagger.json",
        "/swagger/v1/swagger.json",
        
        // Metrics endpoints
        "/metrics",
        "/metrics/*",
        
        // CSRF token generation (public)
        "/api/v1/auth/csrf/token",
        "/auth/csrf/token",
        
        // Logout (should work even with invalid session)
        "/api/v1/auth/logout",
        "/auth/logout"
    };

    private readonly List<string> _customExclusions;
    private readonly List<Regex> _compiledPatterns;

    /// <summary>
    /// Initializes a new instance of the EndpointExclusionMatcher.
    /// </summary>
    /// <param name="customExclusions">Optional custom exclusion patterns (supports wildcards).</param>
    public EndpointExclusionMatcher(List<string>? customExclusions = null)
    {
        _customExclusions = customExclusions ?? new List<string>();
        _compiledPatterns = CompilePatterns(_defaultExclusions.Concat(_customExclusions).ToList());
    }

    /// <summary>
    /// Checks if an endpoint route should be excluded from authorization policy application.
    /// </summary>
    /// <param name="routeTemplate">The route template (e.g., "/api/v1/products" or "/health").</param>
    /// <returns>True if the endpoint should be excluded, false otherwise.</returns>
    public bool IsExcluded(string routeTemplate)
    {
        if (string.IsNullOrWhiteSpace(routeTemplate))
            return false;

        // Normalize route (remove trailing slashes, ensure leading slash)
        var normalizedRoute = NormalizeRoute(routeTemplate);

        // Check against compiled patterns
        foreach (var pattern in _compiledPatterns)
        {
            if (pattern.IsMatch(normalizedRoute))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Normalizes a route template for matching.
    /// </summary>
    private string NormalizeRoute(string route)
    {
        // Ensure leading slash
        if (!route.StartsWith("/"))
            route = "/" + route;

        // Remove trailing slash (except for root)
        if (route.Length > 1 && route.EndsWith("/"))
            route = route.TrimEnd('/');

        return route;
    }

    /// <summary>
    /// Compiles exclusion patterns into regex patterns.
    /// Supports wildcards: * matches any sequence of characters.
    /// </summary>
    private List<Regex> CompilePatterns(List<string> patterns)
    {
        var compiled = new List<Regex>();

        foreach (var pattern in patterns)
        {
            if (string.IsNullOrWhiteSpace(pattern))
                continue;

            var normalized = NormalizeRoute(pattern);

            // Convert wildcard pattern to regex
            // * matches any sequence of characters (non-greedy)
            var regexPattern = "^" + Regex.Escape(normalized)
                .Replace("\\*", ".*") + "$";

            try
            {
                var regex = new Regex(regexPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
                compiled.Add(regex);
            }
            catch (Exception ex)
            {
                // Log warning but continue
                Console.WriteLine($"Warning: Invalid exclusion pattern '{pattern}': {ex.Message}");
            }
        }

        return compiled;
    }

    /// <summary>
    /// Gets the default exclusion patterns.
    /// </summary>
    public static List<string> GetDefaultExclusions()
    {
        return new List<string>
        {
            "/health",
            "/health/*",
            "/healthz",
            "/ready",
            "/live",
            "/swagger",
            "/swagger/*",
            "/swagger.json",
            "/swagger/v1/swagger.json",
            "/metrics",
            "/metrics/*",
            "/api/v1/auth/csrf/token",
            "/auth/csrf/token",
            "/api/v1/auth/logout",
            "/auth/logout"
        };
    }
}
