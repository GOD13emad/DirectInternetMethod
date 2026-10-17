[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Only GitHub-hosted disposable Windows. This guard runs BEFORE dotnet starts.
# The typed .NET 10 fixture itself independently repeats this host check.
if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    $env:RUNNER_OS -cne 'Windows' -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_WORKSPACE) -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_SHA) -or
    $env:COMPUTERNAME -match '(?i)EMAD-PC') {
    throw 'R062_ONLY_DISPOSABLE_GITHUB_WINDOWS_RUNNER'
}

$project = Join-Path $env:GITHUB_WORKSPACE 'tests/service_curl_native/ServiceCurlNative.csproj'
if (!(Test-Path -LiteralPath $project -PathType Leaf)) {
    throw 'R062_TYPED_NATIVE_DOTNET_PROJECT_MISSING'
}
# Avoid PowerShell Reflection.Invoke and its PSObject/CLR parameter wrapping.
# Native CLR strings + CancellationToken are handled inside a net10.0-windows executable.
& dotnet run --project $project -c Release --no-launch-profile
if ($LASTEXITCODE -ne 0) {
    throw 'R062_NATIVE_SERVICE_CURL_LOOPBACK_TEST_FAILED'
}
