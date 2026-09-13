[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $projectRoot
try {
    & dotnet restore FileGuard.slnx
    if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed ($LASTEXITCODE)." }
    & dotnet build FileGuard.slnx --no-restore --configuration $Configuration
    if ($LASTEXITCODE -ne 0) { throw "dotnet build failed ($LASTEXITCODE)." }
    & dotnet test tests/FileGuard.Tests/FileGuard.Tests.csproj --no-build --no-restore --configuration $Configuration
    if ($LASTEXITCODE -ne 0) { throw "dotnet test failed ($LASTEXITCODE)." }
}
finally { Pop-Location }
