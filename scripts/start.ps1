[CmdletBinding()]
param(
    [string]$Config,
    [string[]]$AllowedRoot = @(),
    [string]$DataDirectory,
    [string]$QuarantineDirectory,
    [string]$Url = 'http://localhost:5187',
    [switch]$Published
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $projectRoot
try {
    $serverArgs = @('serve', '--urls', $Url)
    if ($Config) { $serverArgs += @('--config', $Config) }
    if ($DataDirectory) { $serverArgs += @('--data', $DataDirectory) }
    elseif (-not $Config) { $serverArgs += @('--data', '.local/state') }
    foreach ($scanRoot in $AllowedRoot) { $serverArgs += @('--allow-root', $scanRoot) }
    if ($QuarantineDirectory) { $serverArgs += @('--quarantine', $QuarantineDirectory) }
    if ($Published) {
        $executable = Join-Path $projectRoot 'artifacts/publish/win-x64/cli/fileguard.exe'
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Published CLI missing. Run scripts/publish.ps1 first.' }
        & $executable @serverArgs
    }
    else {
        & dotnet build FileGuard.slnx --configuration Debug
        if ($LASTEXITCODE -ne 0) { throw "Build failed ($LASTEXITCODE)." }
        & dotnet run --project src/FileGuard.Cli --configuration Debug --no-build -- @serverArgs
    }
    if ($LASTEXITCODE -notin @(0, 130)) { throw "Server stopped with code $LASTEXITCODE." }
}
finally { Pop-Location }
