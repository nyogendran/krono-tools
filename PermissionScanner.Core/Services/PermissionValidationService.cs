using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Validates permissions by comparing constants, migrations, and database.
/// </summary>
public class PermissionValidationService
{
    /// <summary>
    /// Validates permissions across all sources (constants, migrations, database).
    /// </summary>
    public PermissionValidationResult Validate(
        List<PermissionDefinition> constantsPermissions,
        List<MigrationPermission> migrationPermissions,
        List<DatabasePermission> databasePermissions)
    {
        var result = new PermissionValidationResult();

        // Convert to hash sets for efficient lookup
        result.ConstantsPermissions = constantsPermissions
            .Select(p => p.PermissionName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        result.MigrationPermissions = migrationPermissions
            .Select(p => p.PermissionName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        result.DatabasePermissions = databasePermissions
            .Select(p => p.PermissionName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Find matches (in all three sources)
        result.Matches = result.ConstantsPermissions
            .Intersect(result.MigrationPermissions)
            .Intersect(result.DatabasePermissions)
            .ToList();

        // Find missing in database (in constants but not in DB)
        result.MissingInDatabase = result.ConstantsPermissions
            .Except(result.DatabasePermissions)
            .ToList();

        // Find missing in constants (in DB but not in constants)
        result.MissingInConstants = result.DatabasePermissions
            .Except(result.ConstantsPermissions)
            .ToList();

        // Find missing in database from migrations (in migrations but not in DB)
        result.MissingInDatabaseFromMigrations = result.MigrationPermissions
            .Except(result.DatabasePermissions)
            .ToList();

        // Find missing in migrations (in DB but not in migrations)
        result.MissingInMigrations = result.DatabasePermissions
            .Except(result.MigrationPermissions)
            .ToList();

        // Find orphaned (in DB but not in constants or migrations)
        result.OrphanedInDatabase = result.DatabasePermissions
            .Except(result.ConstantsPermissions)
            .Except(result.MigrationPermissions)
            .ToList();

        // Build summary
        result.Summary = new ValidationSummary
        {
            ConstantsCount = result.ConstantsPermissions.Count,
            MigrationsCount = result.MigrationPermissions.Count,
            DatabaseCount = result.DatabasePermissions.Count,
            MatchesCount = result.Matches.Count,
            DiscrepanciesCount = result.MissingInDatabase.Count +
                                 result.MissingInConstants.Count +
                                 result.MissingInDatabaseFromMigrations.Count +
                                 result.MissingInMigrations.Count +
                                 result.OrphanedInDatabase.Count
        };

        return result;
    }
}
