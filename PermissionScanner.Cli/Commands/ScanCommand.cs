using System.Text.Json;
using PermissionScanner.Core.Analyzers;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Cli.Commands;

/// <summary>
/// Command to scan solution for API endpoints and generate permission suggestions.
/// </summary>
public class ScanCommand
{
    public static async Task<int> ExecuteAsync(string solutionPath, string? outputPath)
    {
        try
        {
            Console.WriteLine($"Scanning solution: {solutionPath}");
            
            var analyzer = new EndpointAnalyzer();
            var endpoints = await analyzer.ScanSolutionAsync(solutionPath);

            Console.WriteLine($"Discovered {endpoints.Count} endpoints");

            // Group results
            var endpointsWithMismatchedPolicies = endpoints
                .Where(e => e.HasPolicy && !string.IsNullOrEmpty(e.ExistingPolicy) && 
                           e.ExistingPolicy != e.SuggestedPolicy)
                .ToList();

            var summary = new
            {
                TotalEndpoints = endpoints.Count,
                EndpointsWithPolicies = endpoints.Count(e => e.HasPolicy),
                EndpointsWithoutPolicies = endpoints.Count(e => !e.HasPolicy),
                EndpointsWithMismatchedPolicies = endpointsWithMismatchedPolicies.Count,
                Services = endpoints.GroupBy(e => e.ServiceName).Select(g => new
                {
                    ServiceName = g.Key,
                    EndpointCount = g.Count()
                }).ToList(),
                DiscoveredEndpoints = endpoints.Select(e => new
                {
                    e.ServiceName,
                    e.FilePath,
                    e.LineNumber,
                    e.HttpMethod,
                    e.RouteTemplate,
                    e.ExistingPolicy,
                    e.SuggestedPermission,
                    e.SuggestedPolicy,
                    HasPolicy = e.HasPolicy,
                    PolicyMismatch = e.HasPolicy && !string.IsNullOrEmpty(e.ExistingPolicy) && 
                                    e.ExistingPolicy != e.SuggestedPolicy
                }).ToList(),
                MismatchedPolicies = endpointsWithMismatchedPolicies.Select(e => new
                {
                    e.ServiceName,
                    e.FilePath,
                    e.LineNumber,
                    e.HttpMethod,
                    e.RouteTemplate,
                    ExistingPolicy = e.ExistingPolicy,
                    SuggestedPolicy = e.SuggestedPolicy,
                    SuggestedPermission = e.SuggestedPermission
                }).ToList()
            };

            // Always generate report file (default if not specified)
            var reportPath = outputPath ?? $"permission-scan-report-{DateTime.Now:yyyyMMdd-HHmmss}.json";
            
            var json = JsonSerializer.Serialize(summary, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            await File.WriteAllTextAsync(reportPath, json);
            Console.WriteLine($"Report saved to: {reportPath}");
            
            // Also generate a human-readable text report
            var textReportPath = reportPath.Replace(".json", ".txt");
            await GenerateTextReportAsync(endpoints, textReportPath);
            Console.WriteLine($"Text report saved to: {textReportPath}");
            
            // Console output
            if (string.IsNullOrEmpty(outputPath))
            {
                // Print summary to console
                Console.WriteLine();
                Console.WriteLine("=== Scan Summary ===");
                Console.WriteLine($"Total Endpoints: {summary.TotalEndpoints}");
                Console.WriteLine($"With Policies: {summary.EndpointsWithPolicies}");
                Console.WriteLine($"Without Policies: {summary.EndpointsWithoutPolicies}");
                
                if (summary.EndpointsWithMismatchedPolicies > 0)
                {
                    Console.WriteLine($"⚠️  Policies with naming mismatches: {summary.EndpointsWithMismatchedPolicies}");
                }
                
                Console.WriteLine();
                
                var endpointsWithoutPolicies = endpoints.Where(e => !e.HasPolicy).ToList();
                if (endpointsWithoutPolicies.Any())
                {
                    Console.WriteLine("Endpoints without policies:");
                    foreach (var endpoint in endpointsWithoutPolicies.Take(10))
                    {
                        Console.WriteLine($"  {endpoint.HttpMethod} {endpoint.RouteTemplate} -> {endpoint.SuggestedPolicy}");
                    }
                    if (endpointsWithoutPolicies.Count > 10)
                    {
                        Console.WriteLine($"  ... and {endpointsWithoutPolicies.Count - 10} more");
                    }
                }
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
            return 1;
        }
    }

    private static async Task GenerateTextReportAsync(List<DiscoveredEndpoint> endpoints, string reportPath)
    {
        using var writer = new StreamWriter(reportPath);
        
        await writer.WriteLineAsync($"Permission Scanner Report");
        await writer.WriteLineAsync($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        await writer.WriteLineAsync($"Total Endpoints: {endpoints.Count}");
        await writer.WriteLineAsync($"With Policies: {endpoints.Count(e => e.HasPolicy)}");
        await writer.WriteLineAsync($"Without Policies: {endpoints.Count(e => !e.HasPolicy)}");
        await writer.WriteLineAsync();
        
        // Group by service
        var byService = endpoints.GroupBy(e => e.ServiceName).OrderBy(g => g.Key);
        
        foreach (var serviceGroup in byService)
        {
            await writer.WriteLineAsync($"=== {serviceGroup.Key} ({serviceGroup.Count()} endpoints) ===");
            await writer.WriteLineAsync();
            
            var withPolicies = serviceGroup.Where(e => e.HasPolicy).OrderBy(e => e.RouteTemplate).ToList();
            var withoutPolicies = serviceGroup.Where(e => !e.HasPolicy).OrderBy(e => e.RouteTemplate).ToList();
            
            if (withPolicies.Any())
            {
                await writer.WriteLineAsync("Endpoints WITH policies:");
                foreach (var endpoint in withPolicies)
                {
                    await writer.WriteLineAsync($"  [{endpoint.HttpMethod}] {endpoint.RouteTemplate}");
                    await writer.WriteLineAsync($"    Existing Policy: {endpoint.ExistingPolicy}");
                    
                    // Check if existing policy matches suggested naming convention
                    if (!string.IsNullOrEmpty(endpoint.ExistingPolicy) && 
                        endpoint.ExistingPolicy != endpoint.SuggestedPolicy)
                    {
                        await writer.WriteLineAsync($"    ⚠️  Suggested Policy: {endpoint.SuggestedPolicy} (naming mismatch)");
                        await writer.WriteLineAsync($"    Suggested Permission: {endpoint.SuggestedPermission}");
                    }
                    else
                    {
                        await writer.WriteLineAsync($"    ✅ Matches convention: {endpoint.SuggestedPolicy}");
                    }
                    
                    await writer.WriteLineAsync($"    File: {endpoint.FilePath}:{endpoint.LineNumber}");
                    await writer.WriteLineAsync();
                }
            }
            
            if (withoutPolicies.Any())
            {
                await writer.WriteLineAsync("Endpoints WITHOUT policies (need attention):");
                foreach (var endpoint in withoutPolicies)
                {
                    await writer.WriteLineAsync($"  [{endpoint.HttpMethod}] {endpoint.RouteTemplate}");
                    await writer.WriteLineAsync($"    Suggested Permission: {endpoint.SuggestedPermission}");
                    await writer.WriteLineAsync($"    Suggested Policy: {endpoint.SuggestedPolicy}");
                    await writer.WriteLineAsync($"    File: {endpoint.FilePath}:{endpoint.LineNumber}");
                    await writer.WriteLineAsync();
                }
            }
            
            await writer.WriteLineAsync();
        }
        
        // Policy naming convention analysis
        var mismatchedPolicies = endpoints
            .Where(e => e.HasPolicy && !string.IsNullOrEmpty(e.ExistingPolicy) && 
                       e.ExistingPolicy != e.SuggestedPolicy)
            .GroupBy(e => new { e.ExistingPolicy, e.SuggestedPolicy })
            .OrderBy(g => g.Key.ExistingPolicy)
            .ToList();
        
        if (mismatchedPolicies.Any())
        {
            await writer.WriteLineAsync("=== Policy Naming Convention Mismatches ===");
            await writer.WriteLineAsync();
            await writer.WriteLineAsync("The following existing policies do not match the suggested naming convention:");
            await writer.WriteLineAsync();
            
            foreach (var mismatchGroup in mismatchedPolicies)
            {
                await writer.WriteLineAsync($"Existing Policy: {mismatchGroup.Key.ExistingPolicy}");
                await writer.WriteLineAsync($"Suggested Policy: {mismatchGroup.Key.SuggestedPolicy}");
                await writer.WriteLineAsync($"Used by {mismatchGroup.Count()} endpoint(s):");
                foreach (var endpoint in mismatchGroup.Take(5))
                {
                    await writer.WriteLineAsync($"  - [{endpoint.HttpMethod}] {endpoint.RouteTemplate}");
                }
                if (mismatchGroup.Count() > 5)
                {
                    await writer.WriteLineAsync($"  ... and {mismatchGroup.Count() - 5} more");
                }
                await writer.WriteLineAsync();
            }
        }
        
        // Resource-based grouping (Feature/Resource organization)
        await writer.WriteLineAsync("=== Permissions Grouped by Resource/Feature ===");
        await writer.WriteLineAsync();
        
        var resourceGroups = endpoints
            .Select(e => new
            {
                Endpoint = e,
                Resource = ExtractResourceFromPermission(e.SuggestedPermission),
                SubResource = ExtractSubResourceFromPermission(e.SuggestedPermission)
            })
            .GroupBy(x => x.Resource)
            .OrderBy(g => g.Key)
            .ToList();
        
        foreach (var resourceGroup in resourceGroups)
        {
            await writer.WriteLineAsync($"## {resourceGroup.Key.ToUpperInvariant()} ({resourceGroup.Count()} endpoints)");
            await writer.WriteLineAsync();
            
            // Group by sub-resource if applicable
            var subResourceGroups = resourceGroup
                .GroupBy(x => x.SubResource ?? "")
                .OrderBy(g => g.Key)
                .ToList();
            
            foreach (var subResourceGroup in subResourceGroups)
            {
                if (!string.IsNullOrEmpty(subResourceGroup.Key))
                {
                    await writer.WriteLineAsync($"### {subResourceGroup.Key} ({subResourceGroup.Count()} endpoints)");
                    await writer.WriteLineAsync();
                }
                
                foreach (var item in subResourceGroup.OrderBy(x => x.Endpoint.SuggestedPermission))
                {
                    var e = item.Endpoint;
                    await writer.WriteLineAsync($"  [{e.HttpMethod}] {e.RouteTemplate}");
                    await writer.WriteLineAsync($"    Permission: {e.SuggestedPermission}");
                    await writer.WriteLineAsync($"    Policy: {e.SuggestedPolicy}");
                    
                    if (e.HasPolicy && !string.IsNullOrEmpty(e.ExistingPolicy))
                    {
                        if (e.ExistingPolicy != e.SuggestedPolicy)
                        {
                            await writer.WriteLineAsync($"    ⚠️  Existing Policy: {e.ExistingPolicy} (mismatch)");
                        }
                        else
                        {
                            await writer.WriteLineAsync($"    ✅ Existing Policy: {e.ExistingPolicy} (matches)");
                        }
                    }
                    
                    await writer.WriteLineAsync($"    Service: {e.ServiceName}");
                    await writer.WriteLineAsync();
                }
            }
        }
        
        // Summary of suggested permissions (flat list)
        await writer.WriteLineAsync("=== Suggested Permissions Summary (Flat List) ===");
        await writer.WriteLineAsync();
        
        var permissions = endpoints
            .GroupBy(e => e.SuggestedPermission)
            .OrderBy(g => g.Key)
            .ToList();
        
        foreach (var permGroup in permissions)
        {
            await writer.WriteLineAsync($"{permGroup.Key} (used by {permGroup.Count()} endpoints)");
            await writer.WriteLineAsync($"  Policy: {permGroup.First().SuggestedPolicy}");
            
            // Show if any endpoints using this permission have existing policies
            var withExistingPolicies = permGroup.Where(e => e.HasPolicy && !string.IsNullOrEmpty(e.ExistingPolicy)).ToList();
            if (withExistingPolicies.Any())
            {
                var existingPolicies = withExistingPolicies.Select(e => e.ExistingPolicy).Distinct().ToList();
                await writer.WriteLineAsync($"  Existing Policies: {string.Join(", ", existingPolicies)}");
            }
            
            await writer.WriteLineAsync();
        }
    }
    
    private static string ExtractResourceFromPermission(string permission)
    {
        if (string.IsNullOrEmpty(permission))
            return "unknown";
        
        // Extract primary resource (first part before :)
        var colonIndex = permission.IndexOf(':');
        if (colonIndex < 0)
            return permission;
        
        var resource = permission.Substring(0, colonIndex);
        
        // Handle nested resources (e.g., "products:variants:read" -> "products")
        // Check if there's a second colon for sub-resources
        var remaining = permission.Substring(colonIndex + 1);
        var secondColonIndex = remaining.IndexOf(':');
        
        if (secondColonIndex > 0)
        {
            // This is a nested resource, but we want to group by the top-level resource
            // e.g., "products:variants:read" -> group under "products"
            // "organizations:approval-levels:read" -> group under "organizations"
            return resource;
        }
        
        return resource;
    }
    
    private static string? ExtractSubResourceFromPermission(string permission)
    {
        if (string.IsNullOrEmpty(permission))
            return null;
        
        var parts = permission.Split(':');
        if (parts.Length >= 3)
        {
            // e.g., "products:variants:read" -> "variants"
            // e.g., "organizations:approval-levels:read" -> "approval-levels"
            return parts[1];
        }
        
        return null;
    }
}
