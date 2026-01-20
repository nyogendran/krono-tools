using PermissionScanner.Core.Analyzers;

namespace PermissionScanner.Cli.Commands;

/// <summary>
/// Command to validate that all endpoints have authorization policies.
/// </summary>
public class ValidateCommand
{
    public static async Task<int> ExecuteAsync(string solutionPath)
    {
        try
        {
            Console.WriteLine($"Validating solution: {solutionPath}");
            
            var analyzer = new EndpointAnalyzer();
            var endpoints = await analyzer.ScanSolutionAsync(solutionPath);

            var endpointsWithoutPolicies = endpoints.Where(e => !e.HasPolicy).ToList();

            Console.WriteLine($"Total Endpoints: {endpoints.Count}");
            Console.WriteLine($"With Policies: {endpoints.Count - endpointsWithoutPolicies.Count}");
            Console.WriteLine($"Without Policies: {endpointsWithoutPolicies.Count}");

            if (endpointsWithoutPolicies.Any())
            {
                Console.WriteLine();
                Console.WriteLine("⚠️  Endpoints without authorization policies:");
                foreach (var endpoint in endpointsWithoutPolicies)
                {
                    Console.WriteLine($"  {endpoint.HttpMethod} {endpoint.RouteTemplate}");
                    Console.WriteLine($"    File: {endpoint.FilePath}:{endpoint.LineNumber}");
                    Console.WriteLine($"    Suggested: {endpoint.SuggestedPolicy}");
                    Console.WriteLine();
                }
                return 1; // Exit code 1 = validation failed
            }

            Console.WriteLine();
            Console.WriteLine("✅ All endpoints have authorization policies!");
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
}
