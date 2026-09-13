using FileGuard.Core;
using Microsoft.Data.Sqlite;
using Xunit;

namespace FileGuard.Tests;

public sealed class StoreTests
{
    [Fact]
    public void UnsupportedFutureDatabaseIsRejectedBeforeChangingJournalOrContents()
    {
        using var fixture = new ScanFixture();
        using (var connection = fixture.Store.OpenConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "PRAGMA journal_mode=DELETE; CREATE TABLE future_schema(secret TEXT); INSERT INTO future_schema VALUES('preserve'); PRAGMA user_version=99;";
            command.ExecuteNonQuery();
        }
        var before = File.ReadAllBytes(fixture.Store.DatabasePath);
        Assert.Throws<GuardException>(() => new FileGuardStore(fixture.Store.DataDirectory).Initialize());
        Assert.Equal(before, File.ReadAllBytes(fixture.Store.DatabasePath));
        using var verify = fixture.Store.OpenConnection(); using var query = verify.CreateCommand();
        query.CommandText = "PRAGMA journal_mode"; Assert.Equal("delete", query.ExecuteScalar());
        query.CommandText = "PRAGMA user_version"; Assert.Equal(99L, query.ExecuteScalar());
        query.CommandText = "SELECT secret FROM future_schema"; Assert.Equal("preserve", query.ExecuteScalar());
    }

    [Fact]
    public void VersionZeroDatabaseUpgradesIdempotentlyWithoutRemovingExistingData()
    {
        using var fixture = new ScanFixture();
        var data = Path.Combine(fixture.Base, "version-zero"); Directory.CreateDirectory(data);
        var path = Path.Combine(data, "fileguard.db");
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
        {
            connection.Open(); using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE legacy_marker(value TEXT); INSERT INTO legacy_marker VALUES('keep'); PRAGMA user_version=0;";
            command.ExecuteNonQuery();
        }
        var upgraded = new FileGuardStore(data); upgraded.Initialize(); upgraded.Initialize();
        var scan = new ScanRecord { State = ScanState.Completed }; upgraded.SaveScan(scan);
        Assert.Equal(scan.Id, upgraded.GetScan(scan.Id).Id);
        using var verify = upgraded.OpenConnection(); using var query = verify.CreateCommand();
        query.CommandText = "PRAGMA user_version"; Assert.Equal(1L, query.ExecuteScalar());
        query.CommandText = "PRAGMA journal_mode"; Assert.Equal("wal", query.ExecuteScalar());
        query.CommandText = "SELECT value FROM legacy_marker"; Assert.Equal("keep", query.ExecuteScalar());
    }
}
