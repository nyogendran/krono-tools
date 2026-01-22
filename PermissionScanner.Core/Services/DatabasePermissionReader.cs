using Npgsql;
using PermissionScanner.Core.Models;

namespace PermissionScanner.Core.Services;

/// <summary>
/// Reads permissions from PostgreSQL database.
/// </summary>
public class DatabasePermissionReader
{
    /// <summary>
    /// Tests database connection.
    /// </summary>
    public async Task<bool> TestConnectionAsync(string connectionString)
    {
        try
        {
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            return true;
        }
        catch (Exception ex)
        {
            // Log the error for debugging (without exposing full connection string)
            Console.WriteLine($"   Connection error: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.WriteLine($"   Inner exception: {ex.InnerException.Message}");
            }
            return false;
        }
    }

    /// <summary>
    /// Reads all system permissions from the database.
    /// </summary>
    /// <param name="connectionString">PostgreSQL connection string</param>
    /// <param name="schemaName">Schema name (e.g., "app_schema")</param>
    /// <returns>List of permissions from database</returns>
    public async Task<List<DatabasePermission>> ReadPermissionsAsync(string connectionString, string schemaName)
    {
        var permissions = new List<DatabasePermission>();

        try
        {
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();

            var query = $@"
                SELECT 
                    permission_name,
                    permission_description,
                    resource,
                    action,
                    is_system_permission,
                    is_active,
                    display_order,
                    created_at
                FROM {schemaName}.permissions
                WHERE is_system_permission = true
                  AND is_deleted = false
                ORDER BY permission_name;
            ";

            await using var command = new NpgsqlCommand(query, connection);
            await using var reader = await command.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                permissions.Add(new DatabasePermission
                {
                    PermissionName = reader.GetString(0),
                    Description = reader.IsDBNull(1) ? null : reader.GetString(1),
                    Resource = reader.GetString(2),
                    Action = reader.GetString(3),
                    IsSystemPermission = reader.GetBoolean(4),
                    IsActive = reader.GetBoolean(5),
                    DisplayOrder = reader.GetInt32(6),
                    CreatedAt = reader.GetFieldValue<DateTimeOffset>(7)
                });
            }
        }
        catch (PostgresException ex) when (ex.SqlState == "42P01") // Table doesn't exist
        {
            throw new InvalidOperationException(
                $"Permissions table not found in schema '{schemaName}'. " +
                "Ensure migrations have been run and the schema name is correct.", ex);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Failed to read permissions from database: {ex.Message}", ex);
        }

        return permissions;
    }

    /// <summary>
    /// Extracts schema name from connection string or uses default.
    /// </summary>
    public static string ExtractSchemaFromConnectionString(string connectionString, string defaultSchema = "app_schema")
    {
        // Try to extract SearchPath from connection string
        var searchPathMatch = System.Text.RegularExpressions.Regex.Match(
            connectionString, 
            @"SearchPath=([^;]+)", 
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        
        if (searchPathMatch.Success)
        {
            return searchPathMatch.Groups[1].Value.Trim();
        }

        return defaultSchema;
    }
}
