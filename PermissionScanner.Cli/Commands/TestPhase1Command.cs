using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Models;
using PermissionScanner.Core.Services;

namespace PermissionScanner.Cli.Commands;

/// <summary>
/// Test command for Phase 1 - Core Detection functionality.
/// </summary>
public class TestPhase1Command
{
    public static async Task<int> ExecuteAsync(
        string solutionPath,
        string platformServicesPath)
    {
        try
        {
            Console.WriteLine("🧪 Testing Phase 1 - Core Detection");
            Console.WriteLine("====================================");
            Console.WriteLine();

            // Step 1: Read existing policies
            Console.WriteLine("📖 Step 1: Reading existing policies...");
            var (permissions, policies) = await ApplyCommand.ReadExistingConstantsAsync(
                solutionPath,
                platformServicesPath);
            
            Console.WriteLine($"   ✅ Found {permissions.Count} permissions");
            Console.WriteLine($"   ✅ Found {policies.Count} policies");
            Console.WriteLine();

            // Step 2: Build policy location map
            Console.WriteLine("🔧 Step 2: Building policy location map...");
            
            // Convert ApplyCommand.PolicyLocation to ApplyCommandPolicyLocation
            var policyLocationDict = new Dictionary<string, ApplyCommandPolicyLocation>();
            foreach (var kvp in policies)
            {
                policyLocationDict[kvp.Key] = new ApplyCommandPolicyLocation
                {
                    IsShared = kvp.Value.IsShared,
                    ServiceName = kvp.Value.ServiceName
                };
            }
            
            var policyLocationMap = PolicyLocationBuilder.BuildPolicyLocationMap(policyLocationDict);
            Console.WriteLine($"   ✅ Built policy location map with {policyLocationMap.Count} policies");
            Console.WriteLine();

            // Step 3: Test exclusion matcher
            Console.WriteLine("🚫 Step 3: Testing exclusion matcher...");
            var exclusionMatcher = new EndpointExclusionMatcher();
            var testRoutes = new[]
            {
                "/health",
                "/swagger",
                "/api/v1/products",
                "/api/v1/products/{id}",
                "/metrics",
                "/healthz"
            };

            foreach (var route in testRoutes)
            {
                var isExcluded = exclusionMatcher.IsExcluded(route);
                var status = isExcluded ? "🚫 EXCLUDED" : "✅ NOT EXCLUDED";
                Console.WriteLine($"   {status}: {route}");
            }
            Console.WriteLine();

            // Step 4: Discover endpoints
            Console.WriteLine("🔍 Step 4: Discovering endpoints...");
            var endpointAnalyzer = new EndpointAnalyzer();
            var endpoints = await endpointAnalyzer.ScanSolutionAsync(solutionPath);
            Console.WriteLine($"   ✅ Discovered {endpoints.Count} endpoints");
            Console.WriteLine();

            // Step 5: Group endpoints by service
            Console.WriteLine("📊 Step 5: Analyzing endpoints by service...");
            var endpointsByService = endpoints.GroupBy(e => e.ServiceName).ToList();
            foreach (var group in endpointsByService.OrderBy(g => g.Key))
            {
                var withPolicy = group.Count(e => e.HasPolicy);
                var withoutPolicy = group.Count(e => !e.HasPolicy);
                Console.WriteLine($"   {group.Key}: {group.Count()} total ({withPolicy} with policy, {withoutPolicy} without)");
            }
            Console.WriteLine();

            // Step 6: Test policy resolution for a sample endpoint
            Console.WriteLine("🎯 Step 6: Testing policy resolution...");
            var sampleEndpoints = endpoints
                .Where(e => !e.HasPolicy && !exclusionMatcher.IsExcluded(e.RouteTemplate))
                .Take(5)
                .ToList();

            if (sampleEndpoints.Any())
            {
                foreach (var endpoint in sampleEndpoints)
                {
                    var serviceName = endpoint.ServiceName;
                    var policyResolver = new PolicyResolver(
                        policyLocationMap,
                        serviceName,
                        defaultPolicy: null // No default for testing
                    );

                    var resolution = policyResolver.ResolvePolicy(endpoint);
                    if (resolution != null)
                    {
                        Console.WriteLine($"   ✅ {endpoint.HttpMethod} {endpoint.RouteTemplate}");
                        Console.WriteLine($"      → Policy: {resolution.PolicyName}");
                        Console.WriteLine($"      → Strategy: {resolution.ResolutionStrategy}");
                        Console.WriteLine($"      → Location: {(resolution.Location.IsShared ? "Shared" : "Service-specific")}");
                    }
                    else
                    {
                        Console.WriteLine($"   ⚠️  {endpoint.HttpMethod} {endpoint.RouteTemplate}");
                        Console.WriteLine($"      → No policy found");
                    }
                }
            }
            else
            {
                Console.WriteLine("   ℹ️  No sample endpoints found (all have policies or are excluded)");
            }
            Console.WriteLine();

            // Step 7: Full analysis
            Console.WriteLine("📈 Step 7: Running full endpoint policy analysis...");
            var services = endpointsByService.Select(g => g.Key).Distinct().ToList();
            
            foreach (var serviceName in services)
            {
                var serviceEndpoints = endpoints.Where(e => e.ServiceName == serviceName).ToList();
                if (!serviceEndpoints.Any())
                    continue;

                var servicePolicyResolver = new PolicyResolver(
                    policyLocationMap,
                    serviceName,
                    defaultPolicy: null
                );

                var analyzer = new EndpointPolicyAnalyzer(
                    endpointAnalyzer,
                    exclusionMatcher,
                    servicePolicyResolver
                );

                // Analyze only this service's endpoints
                var result = analyzer.AnalyzeEndpoints(serviceEndpoints);

                Console.WriteLine($"   📦 {serviceName}:");
                Console.WriteLine($"      Total: {result.TotalEndpoints}");
                Console.WriteLine($"      ✅ With policy: {result.EndpointsWithPolicy.Count}");
                Console.WriteLine($"      🔧 Needing policy: {result.EndpointsNeedingPolicy.Count}");
                Console.WriteLine($"      🚫 Excluded: {result.ExcludedEndpoints.Count}");
                Console.WriteLine($"      ⚠️  Unmapped: {result.EndpointsWithoutPolicy.Count}");
            }
            Console.WriteLine();

            // Summary
            Console.WriteLine("✅ Phase 1 Test Complete!");
            Console.WriteLine();
            Console.WriteLine("Summary:");
            Console.WriteLine($"  • Total endpoints discovered: {endpoints.Count}");
            Console.WriteLine($"  • Endpoints with policies: {endpoints.Count(e => e.HasPolicy)}");
            Console.WriteLine($"  • Endpoints without policies: {endpoints.Count(e => !e.HasPolicy)}");
            Console.WriteLine($"  • Excluded endpoints: {endpoints.Count(e => exclusionMatcher.IsExcluded(e.RouteTemplate))}");
            Console.WriteLine($"  • Available policies: {policyLocationMap.Count}");

            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            return 1;
        }
    }
}
