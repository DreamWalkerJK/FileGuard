[CmdletBinding()]
param(
    [ValidateSet('win-x64')][string]$Runtime = 'win-x64',
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot 'artifacts'))
$publishRoot = [IO.Path]::GetFullPath((Join-Path $artifactRoot "publish/$Runtime"))

function Assert-GeneratedArtifactPath([string]$Candidate) {
    $resolved = [IO.Path]::GetFullPath($Candidate)
    $relative = [IO.Path]::GetRelativePath($artifactRoot, $resolved)
    if ([IO.Path]::IsPathRooted($relative) -or $relative -eq '.' -or $relative -eq '..' -or $relative.StartsWith('..' + [IO.Path]::DirectorySeparatorChar)) {
        throw 'Refusing to modify a path outside the generated artifacts directory.'
    }
    return $resolved
}

Push-Location -LiteralPath $projectRoot
try {
    if (-not $SkipTests) { & (Join-Path $PSScriptRoot 'build.ps1') -Configuration Release }
    $verifiedPublishRoot = Assert-GeneratedArtifactPath $publishRoot
    if (Test-Path -LiteralPath $verifiedPublishRoot) {
        Remove-Item -LiteralPath $verifiedPublishRoot -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $verifiedPublishRoot -Force
    & dotnet publish src/FileGuard.Cli/FileGuard.Cli.csproj --configuration Release --runtime $Runtime --self-contained true --output (Join-Path $verifiedPublishRoot 'cli')
    if ($LASTEXITCODE -ne 0) { throw "CLI publish failed ($LASTEXITCODE)." }
    & dotnet publish src/FileGuard.Web/FileGuard.Web.csproj --configuration Release --runtime $Runtime --self-contained true --output (Join-Path $verifiedPublishRoot 'web')
    if ($LASTEXITCODE -ne 0) { throw "Web publish failed ($LASTEXITCODE)." }
    Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md') -Destination $verifiedPublishRoot
    Copy-Item -LiteralPath (Join-Path $projectRoot 'docs') -Destination (Join-Path $verifiedPublishRoot 'docs') -Recurse
    if (Test-Path -LiteralPath (Join-Path $projectRoot 'LICENSE')) { Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination $verifiedPublishRoot }
    Copy-Item -LiteralPath (Join-Path $projectRoot 'fileguard.example.json') -Destination $verifiedPublishRoot
    $archive = Assert-GeneratedArtifactPath (Join-Path $artifactRoot "FileGuard-$Runtime.zip")
    Compress-Archive -Path (Join-Path $verifiedPublishRoot '*') -DestinationPath $archive -Force
    Write-Host "Published CLI and Web: artifacts/publish/$Runtime"
    Write-Host "Archive: artifacts/FileGuard-$Runtime.zip"
}
finally { Pop-Location }
