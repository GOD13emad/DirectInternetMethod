using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// An exact-source, real native downloader regression. It runs ONLY on disposable
// GitHub-hosted Windows runners. No service is registered and no installer is run.
if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
    Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
    Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows" ||
    string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("RUNNER_TEMP")) ||
    string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("GITHUB_WORKSPACE")) ||
    string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("GITHUB_SHA")) ||
    (Environment.GetEnvironmentVariable("COMPUTERNAME") ?? "")
        .Contains("EMAD-PC", StringComparison.OrdinalIgnoreCase))
    throw new InvalidOperationException("R062_ONLY_DISPOSABLE_GITHUB_WINDOWS_RUNNER");

var root = Environment.GetEnvironmentVariable("GITHUB_WORKSPACE")!;
var service = Path.Combine(root, "windows", "service", "bin", "Release",
    "net10.0-windows", "DirectInternetMethod.Service.dll");
if (!File.Exists(service))
    throw new InvalidOperationException("R062_COMPILED_SERVICE_MISSING");

var tempRoot = Path.GetFullPath(Environment.GetEnvironmentVariable("RUNNER_TEMP")!);
var sandbox = Path.Combine(tempRoot, "R062_" + Guid.NewGuid().ToString("N"));
if (Directory.Exists(sandbox))
    throw new InvalidOperationException("R062_UNEXPECTED_SANDBOX_COLLISION");
Directory.CreateDirectory(sandbox);
var oldPath = Environment.GetEnvironmentVariable("PATH");
var oldNoProxy = Environment.GetEnvironmentVariable("NO_PROXY");
var listener = new TcpListener(IPAddress.Loopback, 0);
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25));
try
{
    var decoy = Path.Combine(sandbox, "untrusted-PATH-first");
    Directory.CreateDirectory(decoy);
    // This is deliberately NOT a runnable Windows executable.
    // Any command search via PATH must cause the test to fail.
    File.WriteAllBytes(Path.Combine(decoy, "curl.exe"),
        new byte[] { 0x4D, 0x5A, 0x90, 0x00 });

    listener.Start(1);
    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
    var uri = "http://127.0.0.1:" + port + "/r062-exact-service-fixture";
    var download = Path.Combine(sandbox, "immutable-fixture.txt");
    var expectedBytes = Encoding.UTF8.GetBytes(
        "R062_NATIVE_SERVICE_CURL_" + Environment.GetEnvironmentVariable("GITHUB_SHA") + "\n");
    var expectedSha = Convert.ToHexString(SHA256.HashData(expectedBytes));

    Environment.SetEnvironmentVariable("PATH", decoy + Path.PathSeparator + oldPath);
    Environment.SetEnvironmentVariable("NO_PROXY", "127.0.0.1,localhost");

    var assembly = Assembly.LoadFrom(Path.GetFullPath(service));
    var type = assembly.GetType("DirectInternetMethod.Service.Program", throwOnError: true)
        ?? throw new InvalidOperationException("R062_SERVICE_TYPE_NOT_FOUND");
    var method = type.GetMethod("DownloadWithSystemCurlAsync",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("R062_DOWNLOADER_METHOD_NOT_FOUND");

    // Native CLR arguments: no PowerShell/PSObject reflection conversions.
    var task = method.Invoke(null, new object?[] { uri, download, deadline.Token }) as Task
        ?? throw new InvalidOperationException("R062_PRIVATE_METHOD_NOT_TASK");
    using (var client = await listener.AcceptTcpClientAsync(deadline.Token))
    {
        await using var stream = client.GetStream();
        var buffer = new byte[4096];
        var received = await stream.ReadAsync(buffer.AsMemory(), deadline.Token);
        if (received <= 0)
            throw new InvalidOperationException("R062_EMPTY_LOOPBACK_REQUEST");
        var requestLine = Encoding.ASCII.GetString(buffer, 0, received);
        if (!requestLine.StartsWith("GET /r062-exact-service-fixture HTTP/1.1",
                StringComparison.Ordinal))
            throw new InvalidOperationException("R062_UNEXPECTED_HTTP_REQUEST");

        const string crlf = "\r\n";
        var headers = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK" + crlf +
            "Content-Type: text/plain" + crlf +
            "Content-Length: " + expectedBytes.Length + crlf +
            "Connection: close" + crlf + crlf);
        await stream.WriteAsync(headers.AsMemory(), deadline.Token);
        await stream.WriteAsync(expectedBytes.AsMemory(), deadline.Token);
        await stream.FlushAsync(deadline.Token);
    }

    await task.WaitAsync(TimeSpan.FromSeconds(25));
    if (!File.Exists(download))
        throw new InvalidOperationException("R062_DOWNLOADED_FIXTURE_MISSING");
    var actualSha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(download)));
    if (!string.Equals(expectedSha, actualSha, StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("R062_EXACT_DOWNLOAD_DIGEST_MISMATCH");
    if (!File.Exists(Path.Combine(Environment.SystemDirectory, "curl.exe")))
        throw new InvalidOperationException("R062_OS_SYSTEM_CURL_MISSING");

    Console.WriteLine(JsonSerializer.Serialize(new
    {
        State = "PASS_R062_HOSTED_NATIVE_SERVICE_DOWNLOADER",
        SourceSha = Environment.GetEnvironmentVariable("GITHUB_SHA"),
        TrustedExecutableUsedDespiteFakePATH = true,
        LoopbackHttpOnly = true,
        DownloadSha256Matched = true,
        DownloadedBytes = expectedBytes.Length,
        WindowsServiceStarted = false,
        InstallerExecuted = false,
        VPNOrSystemNetworkChanged = false
    }));
}
finally
{
    deadline.Cancel();
    listener.Stop();
    Environment.SetEnvironmentVariable("PATH", oldPath);
    Environment.SetEnvironmentVariable("NO_PROXY", oldNoProxy);
    if (Directory.Exists(sandbox))
        Directory.Delete(sandbox, recursive: true);
}
