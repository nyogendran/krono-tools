namespace PermissionScanner.Core.Models;

/// <summary>
/// Result of permission validation comparing constants, migrations, and database.
/// </summary>
public class PermissionValidationResult
{
    /// <summary>
    /// Permissions found in constants files.
    /// </summary>
    public HashSet<string> ConstantsPermissions { get; set; } = new();

    /// <summary>
    /// Permissions found in migration files.
    /// </summary>
    public HashSet<string> MigrationPermissions { get; set; } = new();

    /// <summary>
    /// Permissions found in database.
    /// </summary>
    public HashSet<string> DatabasePermissions { get; set; } = new();

    /// <summary>
    /// Permissions in constants but not in database (missing from DB).
    /// </summary>
    public List<string> MissingInDatabase { get; set; } = new();

    /// <summary>
    /// Permissions in database but not in constants (orphaned or manually added).
    /// </summary>
    public List<string> MissingInConstants { get; set; } = new();

    /// <summary>
    /// Permissions in migrations but not in database (migrations not run).
    /// </summary>
    public List<string> MissingInDatabaseFromMigrations { get; set; } = new();

    /// <summary>
    /// Permissions in database but not in migrations (manually added to DB).
    /// </summary>
    public List<string> MissingInMigrations { get; set; } = new();

    /// <summary>
    /// Permissions in database but not in constants or migrations (orphaned).
    /// </summary>
    public List<string> OrphanedInDatabase { get; set; } = new();

    /// <summary>
    /// Permissions that exist in all three sources (constants, migrations, database).
    /// </summary>
    public List<string> Matches { get; set; } = new();

    /// <summary>
    /// Validation summary statistics.
    /// </summary>
    public ValidationSummary Summary { get; set; } = new();
}

/// <summary>
/// Summary statistics for validation results.
/// </summary>
public class ValidationSummary
{
    /// <summary>
    /// Number of permissions in constants files.
    /// </summary>
    public int ConstantsCount { get; set; }

    /// <summary>
    /// Number of permissions in migration files.
    /// </summary>
    public int MigrationsCount { get; set; }

    /// <summary>
    /// Number of permissions in database.
    /// </summary>
    public int DatabaseCount { get; set; }

    /// <summary>
    /// Number of permissions that match across all sources.
    /// </summary>
    public int MatchesCount { get; set; }

    /// <summary>
    /// Total number of discrepancies found.
    /// </summary>
    public int DiscrepanciesCount { get; set; }
}
