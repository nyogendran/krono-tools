# Permission Scanner Tool

Automated tool to discover API endpoints, generate permission names, and maintain permission/policy constants in the Intelligent Krono Application.

## Purpose

As the application grows, identifying and maintaining all required permissions becomes increasingly challenging. This tool:

1. **Discovers** API endpoints across all microservices
2. **Generates** permission names following the `{resource}:{action}` convention
3. **Suggests** authorization policy names
4. **Generates** permission and policy constants for PlatformServices
5. **Validates** that all endpoints have proper authorization

## Installation

```bash
cd tools/permission-scanner
dotnet tool install --global --add-source ./PermissionScanner.Cli/bin/Release PermissionScanner.Cli
```

Or run directly:
```bash
dotnet run --project PermissionScanner.Cli
```

## Usage

### Scan Endpoints

```bash
dotnet tool run permission-scanner scan \
  --solution ../../kronos-services \
  --output ./permissions-report.json
```

### Generate Constants

```bash
dotnet tool run permission-scanner generate \
  --solution ../../kronos-services \
  --platform-services ../../kronos-services/Kronos.Sales.PlatformServices \
  --update-files
```

### Validate

```bash
dotnet tool run permission-scanner validate \
  --solution ../../kronos-services
```

## Architecture

- **PermissionScanner.Core**: Core scanning logic, Roslyn-based endpoint parsing, code generation
- **PermissionScanner.Cli**: CLI interface using System.CommandLine

## Output

The tool generates/updates:
- `KS.PlatformServices/Constants/Permissions.cs` - Permission name constants
- `KS.PlatformServices/Constants/AuthorizationPolicies.cs` - Policy name constants
- Policy registration snippets for each service

## See Also

- `docs/technical/authorization/permission-scanner-tool-design.md` - Full design specification
- `docs/technical/authorization/permission-discovery-and-management-strategy.md` - Overall strategy
