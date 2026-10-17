[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# R062 exercises ONLY the compiled private downloader on a disposable GitHub Windows runner.
# Never run against the owner's workstation, installed service, production installer or VPN.
if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    $env:RUNNER_OS -cne 'Windows' -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_WORKSPACE) -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_SHA) -or
    $env:COMPUTERNAME -match '(?i)EMAD-PC') {
    throw 'R062_ONLY_DISPOSABLE_GITHUB_WINDOWS_RUNNER'
}

$service = Join-Path $env:GITHUB_WORKSPACE 'windows/service/bin/Release/net10.0-windows/DirectInternetMethod.Service.dll'
if (!(Test-Path -LiteralPath $service -PathType Leaf)) {
    throw 'R062_EXACT_COMPILED_SERVICE_ASSEMBLY_MISSING'
}
$root = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
$work = Join-Path $root ('R062_native_curl_' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $work) { throw 'R062_TEMP_PATH_ALREADY_EXISTS' }
[IO.Directory]::CreateDirectory($work) | Out-Null

$listener = $null
$client = $null
$cancel = $null
$oldPath = [Environment]::GetEnvironmentVariable('PATH', 'Process')
$oldNoProxy = [Environment]::GetEnvironmentVariable('NO_PROXY', 'Process')
try {
    $fake = Join-Path $work 'untrusted-PATH-first'
    [IO.Directory]::CreateDirectory($fake) | Out-Null
    # Deliberately invalid Windows executable. If PATH selected it, the test MUST fail.
    [IO.File]::WriteAllBytes((Join-Path $fake 'curl.exe'), [byte[]]@(0x4D, 0x5A, 0x90, 0x00))

    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start(1)
    $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    $uri = 'http://127.0.0.1:' + $port + '/r062-exact-service-fixture'
    $destination = Join-Path $work 'pinned-loopback-fixture.txt'
    $body = [Text.Encoding]::UTF8.GetBytes('R062_NATIVE_SYSTEM_CURL_' + $env:GITHUB_SHA + [Environment]::NewLine)
    $expectedSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($body))
    $incoming = $listener.AcceptTcpClientAsync()

    [Environment]::SetEnvironmentVariable('PATH', ($fake + ';' + $oldPath), 'Process')
    [Environment]::SetEnvironmentVariable('NO_PROXY', '127.0.0.1,localhost', 'Process')

    $assembly = [Reflection.Assembly]::LoadFile([IO.Path]::GetFullPath($service))
    $type = $assembly.GetType('DirectInternetMethod.Service.Program', $true)
    $binding = [Reflection.BindingFlags]'Static,NonPublic'
    $download = $type.GetMethod('DownloadWithSystemCurlAsync', $binding)
    if ($null -eq $download) { throw 'R062_EXACT_PRIVATE_DOWNLOADER_MISSING' }

    $cancel = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(25))
    # The service main entrypoint / Windows SCM are NOT invoked.
    $task = $download.Invoke($null, [object[]]@($uri, $destination, $cancel.Token))
    if ($task -isnot [Threading.Tasks.Task]) { throw 'R062_DOWNLOADER_NOT_ASYNC_TASK' }

    $client = $incoming.WaitAsync([TimeSpan]::FromSeconds(15)).GetAwaiter().GetResult()
    $client.ReceiveTimeout = 12000
    $stream = $client.GetStream()
    $buffer = [byte[]]::new(4096)
    $count = $stream.Read($buffer, 0, $buffer.Length)
    if ($count -le 0) { throw 'R062_LOOPBACK_EMPTY_HTTP_REQUEST' }
    $request = [Text.Encoding]::ASCII.GetString($buffer, 0, $count)
    if (!$request.StartsWith('GET /r062-exact-service-fixture HTTP/1.1')) {
        throw 'R062_UNEXPECTED_HTTP_METHOD_OR_PATH'
    }

    $crlf = [string][char]13 + [string][char]10
    $headers = [Text.Encoding]::ASCII.GetBytes(
        'HTTP/1.1 200 OK' + $crlf +
        'Content-Type: text/plain' + $crlf +
        ('Content-Length: ' + $body.Length) + $crlf +
        'Connection: close' + $crlf + $crlf)
    $stream.Write($headers, 0, $headers.Length)
    $stream.Write($body, 0, $body.Length)
    $stream.Flush()
    $client.Close()
    $client = $null

    $task.WaitAsync([TimeSpan]::FromSeconds(25)).GetAwaiter().GetResult()
    if (!(Test-Path -LiteralPath $destination -PathType Leaf)) {
        throw 'R062_SERVICE_CURL_DID_NOT_WRITE_FIXTURE'
    }
    $actualSha = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
    if ($actualSha -cne $expectedSha) { throw 'R062_FIXTURE_DIGEST_MISMATCH' }
    if (!(Test-Path -LiteralPath (Join-Path [Environment]::SystemDirectory 'curl.exe') -PathType Leaf)) {
        throw 'R062_WINDOWS_SYSTEM_CURL_UNAVAILABLE'
    }
    $receipt = [ordered]@{
        State = 'PASS_R062_GITHUB_HOSTED_NATIVE_DOWNLOADER'
        ExactCheckedOutSha = $env:GITHUB_SHA
        NativeServiceDownloaderInvoked = $true
        WindowsServiceInstalledOrStarted = $false
        CurlChosenFromUntrustedPATH = $false
        LoopbackOnlyTransport = $true
        PinnedFixtureSha256Matched = $true
        DownloadedBytes = $body.Length
        PhysicalNetworkOrVPNModified = $false
        ProductionInstallerExecuted = $false
    }
    $receipt | ConvertTo-Json -Compress
}
finally {
    if ($null -ne $cancel) { try { $cancel.Cancel() } catch {} ; $cancel.Dispose() }
    if ($null -ne $client) { try { $client.Close() } catch {} }
    if ($null -ne $listener) { try { $listener.Stop() } catch {} }
    [Environment]::SetEnvironmentVariable('PATH', $oldPath, 'Process')
    [Environment]::SetEnvironmentVariable('NO_PROXY', $oldNoProxy, 'Process')
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}
