using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DirectInternetMethod.Service;

internal static class Program
{
    const string ServiceName = "DirectInternetMethodSvc";
    const uint SERVICE_WIN32_OWN_PROCESS = 0x10;
    const uint SERVICE_START_PENDING = 0x2;
    const uint SERVICE_STOP_PENDING = 0x3;
    const uint SERVICE_RUNNING = 0x4;
    const uint SERVICE_STOPPED = 0x1;
    const uint SERVICE_ACCEPT_STOP = 0x1;
    const uint SERVICE_ACCEPT_SHUTDOWN = 0x4;
    const uint SERVICE_CONTROL_STOP = 0x1;
    const uint SERVICE_CONTROL_SHUTDOWN = 0x5;
    const uint CTRL_START = 128;
    const uint CTRL_STOP = 129;
    const uint CTRL_RECOVERY = 130;
    const uint CTRL_UPDATE = 131;
    const string LatestReleaseApi = "https://api.github.com/repos/GOD13emad/DirectInternetMethod/releases/latest";

    static IntPtr _statusHandle;
    static readonly ManualResetEventSlim StopEvent = new(false);
    static readonly SemaphoreSlim ActionGate = new(1, 1);
    static ServiceMainDelegate? _serviceMain;
    static HandlerExDelegate? _handler;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct SERVICE_TABLE_ENTRY
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? lpServiceName;
        public ServiceMainDelegate? lpServiceProc;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    delegate void ServiceMainDelegate(int argc, IntPtr argv);
    delegate uint HandlerExDelegate(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool StartServiceCtrlDispatcher([In] SERVICE_TABLE_ENTRY[] table);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr RegisterServiceCtrlHandlerEx(string serviceName, HandlerExDelegate handler, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetServiceStatus(IntPtr serviceStatusHandle, ref SERVICE_STATUS status);

    static int Main(string[] args)
    {
        if (args.Length == 1 && args[0].Equals("--console-selftest", StringComparison.OrdinalIgnoreCase))
        {
            return SelfTest() == "PASS" ? 0 : 20;
        }

        _serviceMain = ServiceMain;
        _handler = Handler;
        var table = new[]
        {
            new SERVICE_TABLE_ENTRY { lpServiceName = ServiceName, lpServiceProc = _serviceMain },
            new SERVICE_TABLE_ENTRY { lpServiceName = null, lpServiceProc = null }
        };
        return StartServiceCtrlDispatcher(table) ? 0 : Marshal.GetLastWin32Error();
    }

    static void ServiceMain(int argc, IntPtr argv)
    {
        _statusHandle = RegisterServiceCtrlHandlerEx(ServiceName, _handler!, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero) return;

        SetState(SERVICE_START_PENDING, 0, 3000);
        Directory.CreateDirectory(RuntimeDir);
        Log("service-start");
        SetState(SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, 0);
        StopEvent.Wait();
        SetState(SERVICE_STOP_PENDING, 0, 3000);
        Log("service-stop");
        SetState(SERVICE_STOPPED, 0, 0);
    }

    static uint Handler(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        switch (control)
        {
            case SERVICE_CONTROL_STOP:
            case SERVICE_CONTROL_SHUTDOWN:
                StopEvent.Set();
                return 0;
            case CTRL_START:
                _ = Task.Run(() => RunActionAsync("Start-Direct.ps1", "start"));
                return 0;
            case CTRL_STOP:
                _ = Task.Run(() => RunActionAsync("Stop-Direct.ps1", "stop"));
                return 0;
            case CTRL_RECOVERY:
                _ = Task.Run(() => RunActionAsync("Recovery.ps1", "recovery"));
                return 0;
            case CTRL_UPDATE:
                _ = Task.Run(RunUpdateAsync);
                return 0;
            default:
                return 0;
        }
    }

    static string RuntimeDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "DirectInternetMethod");

    static string LogPath => Path.Combine(RuntimeDir, "service.log");
    static string ActionStatusPath => Path.Combine(RuntimeDir, "action-status.json");

    static string PwshPath =>
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "runtime", "pwsh", "pwsh.exe"));


    static string UpdatesDir => Path.Combine(RuntimeDir, "updates");
    static string PendingUpdatePath => Path.Combine(RuntimeDir, "pending-update.json");
    static string NetworkStatePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "DirectDnsDpiHarness", "state.json");

    static readonly HttpClient UpdateHttp = CreateUpdateHttp();

    sealed record UpdatePackage(
        Version Version,
        string Tag,
        string InstallerName,
        string InstallerUrl,
        string ChecksumsUrl,
        string ApiSha256);

    static HttpClient CreateUpdateHttp()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(45) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("DirectInternetMethod.Service/1.2");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return client;
    }

    static Version CurrentVersion =>
        Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0, 0);

    static async Task<UpdatePackage?> GetLatestUpdateAsync(CancellationToken ct)
    {
        using var response = await UpdateHttp.GetAsync(LatestReleaseApi, ct);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var root = doc.RootElement;
        if (root.TryGetProperty("draft", out var draft) && draft.GetBoolean())
            throw new InvalidOperationException("Latest GitHub release is a draft.");
        if (root.TryGetProperty("prerelease", out var pre) && pre.GetBoolean())
            throw new InvalidOperationException("Latest GitHub release is a prerelease.");

        var tag = root.GetProperty("tag_name").GetString() ?? "";
        var clean = tag.Trim().TrimStart('v', 'V');
        if (!Version.TryParse(clean, out var latest))
            throw new InvalidOperationException("Latest GitHub release has an invalid version tag.");
        if (latest <= CurrentVersion) return null;

        var installers = new List<(string Name, string Url, string Digest)>();
        var sums = new List<string>();
        foreach (var asset in root.GetProperty("assets").EnumerateArray())
        {
            var name = asset.GetProperty("name").GetString() ?? "";
            var url = asset.GetProperty("browser_download_url").GetString() ?? "";
            if (name.EndsWith("_Windows_Setup.exe", StringComparison.OrdinalIgnoreCase))
            {
                var digest = asset.TryGetProperty("digest", out var de) ? de.GetString() ?? "" : "";
                installers.Add((name, url, digest));
            }
            else if (name.Equals("SHA256SUMS.txt", StringComparison.OrdinalIgnoreCase))
                sums.Add(url);
        }

        if (installers.Count != 1 || sums.Count != 1)
            throw new InvalidOperationException("Release must contain exactly one Windows installer and one SHA256SUMS.txt.");

        var apiDigest = installers[0].Digest;
        if (!apiDigest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) || apiDigest.Length != 71)
            throw new InvalidOperationException("GitHub release asset is missing a valid SHA-256 digest.");

        return new UpdatePackage(latest, tag, installers[0].Name, installers[0].Url, sums[0], apiDigest[7..]);
    }

    static string ParseExpectedSha256(string sumsText, string installerName)
    {
        var matches = new List<string>();
        foreach (var raw in sumsText.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length < 64) continue;
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 &&
                parts[^1].TrimStart('*').Equals(installerName, StringComparison.OrdinalIgnoreCase))
                matches.Add(parts[0].Trim());
        }
        if (matches.Count != 1 || matches[0].Length != 64 || matches[0].Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidOperationException("SHA256SUMS.txt must contain exactly one valid checksum for the Windows installer.");
        return matches[0].ToUpperInvariant();
    }

    static async Task<string> Sha256FileAsync(string path, CancellationToken ct)
    {
        await using var stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, ct));
    }

    static void WriteJsonAtomic(string path, object payload)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(payload), new UTF8Encoding(false));
        File.Move(temp, path, true);
    }


    static string GetRegisteredInstallDirectory()
    {
        const string keyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}_is1";
        using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false)
            ?? throw new InvalidOperationException("Registered all-users installation was not found.");
        var raw = key.GetValue("InstallLocation") as string;
        if (string.IsNullOrWhiteSpace(raw))
            throw new InvalidOperationException("Registered installation directory is missing.");

        var full = Path.GetFullPath(raw.Trim());
        if (!Path.IsPathFullyQualified(full))
            throw new InvalidOperationException("Registered installation directory is not absolute.");
        var appExe = Path.Combine(full, "app", "DirectInternetMethod.exe");
        var manifest = Path.Combine(full, "manifest.json");
        if (!File.Exists(appExe) || !File.Exists(manifest))
            throw new InvalidOperationException("Registered installation directory does not contain the expected application payload.");
        return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    static async Task DownloadWithSystemCurlAsync(string url, string destination, CancellationToken ct)
    {
        var curl = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "curl.exe");
        if (!File.Exists(curl))
            throw new FileNotFoundException("Windows curl.exe is unavailable.", curl);

        var psi = new ProcessStartInfo(curl)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };
        foreach (var arg in new[]
        {
            "-L", "--fail", "--silent", "--show-error",
            "--connect-timeout", "15", "--max-time", "210",
            "--retry", "2", "--retry-delay", "1",
            "-o", destination, url
        })
            psi.ArgumentList.Add(arg);

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Unable to start Windows curl.exe.");
        using var reg = ct.Register(() =>
        {
            try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }
        });
        await p.WaitForExitAsync(ct);
        if (p.ExitCode != 0)
            throw new HttpRequestException($"curl.exe failed downloading release asset with exit code {p.ExitCode}.");
        if (!File.Exists(destination) || new FileInfo(destination).Length == 0)
            throw new IOException("Downloaded release asset is empty.");
    }

    static async Task RunUpdateAsync()
    {
        const string action = "update";
        if (!await ActionGate.WaitAsync(0))
        {
            Log("action-busy:update");
            WriteActionStatus(action, "busy", -1, "Another action is already running.");
            return;
        }

        try
        {
            if (File.Exists(NetworkStatePath))
            {
                WriteActionStatus(action, "error", -10, "Direct Method must be OFF before update.");
                return;
            }

            Log("action-begin:update");
            WriteActionStatus(action, "running", null, "Checking official GitHub release.");
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(4));
            var package = await GetLatestUpdateAsync(timeout.Token);
            if (package is null)
            {
                Log("action-end:update:already-current");
                WriteActionStatus(action, "done", 0, "Already up to date.");
                return;
            }

            Directory.CreateDirectory(UpdatesDir);
            var sumsText = await UpdateHttp.GetStringAsync(package.ChecksumsUrl, timeout.Token);
            var expected = ParseExpectedSha256(sumsText, package.InstallerName);
            if (!expected.Equals(package.ApiSha256, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("GitHub asset digest does not match SHA256SUMS.txt.");

            var finalPath = Path.Combine(UpdatesDir, package.InstallerName);
            var partPath = finalPath + ".part";
            File.Delete(partPath);

            await DownloadWithSystemCurlAsync(package.InstallerUrl, partPath, timeout.Token);

            var actual = await Sha256FileAsync(partPath, timeout.Token);
            if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(partPath);
                throw new CryptographicException("Downloaded installer failed SHA-256 verification.");
            }
            File.Move(partPath, finalPath, true);

            var installDir = GetRegisteredInstallDirectory();

            WriteJsonAtomic(PendingUpdatePath, new
            {
                schema = 1,
                targetVersion = package.Version.ToString(3),
                tag = package.Tag,
                installer = finalPath,
                sha256 = actual,
                installDir,
                preparedUtc = DateTimeOffset.UtcNow.ToString("O")
            });

            var logPath = Path.Combine(UpdatesDir, "install-" + package.Version.ToString(3) + ".log");
            var psi = new ProcessStartInfo(finalPath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = UpdatesDir
            };
            psi.ArgumentList.Add("/VERYSILENT");
            psi.ArgumentList.Add("/SUPPRESSMSGBOXES");
            psi.ArgumentList.Add("/NORESTART");
            psi.ArgumentList.Add("/NORESTARTAPPLICATIONS");
            psi.ArgumentList.Add("/CLOSEAPPLICATIONS");
            psi.ArgumentList.Add("/SP-");
            psi.ArgumentList.Add("/DIR=" + installDir);
            psi.ArgumentList.Add("/LOG=" + logPath);

            var installer = Process.Start(psi);
            if (installer is null)
                throw new InvalidOperationException("Unable to launch the verified installer.");

            Log($"update-handoff:{package.Tag}:pid={installer.Id}:sha256={actual}");
            WriteActionStatus(action, "handoff", 0, $"Verified {package.Tag}; installing directly without UAC.");
        }
        catch (Exception ex)
        {
            Log($"action-exception:update:{ex.GetType().Name}:{Compact(ex.Message)}");
            WriteActionStatus(action, "error", -1, ex.GetType().Name + ": " + ex.Message);
        }
        finally
        {
            ActionGate.Release();
        }
    }

    static void FinalizePendingUpdate()
    {
        try
        {
            if (!File.Exists(PendingUpdatePath)) return;
            using var doc = JsonDocument.Parse(File.ReadAllText(PendingUpdatePath));
            var targetText = doc.RootElement.GetProperty("targetVersion").GetString() ?? "";
            if (!Version.TryParse(targetText, out var target)) return;
            var installed = CurrentVersion;
            if (installed >= target)
            {
                WriteActionStatus("update", "done", 0, $"Updated to v{installed.ToString(3)}.");
                Log($"update-complete:{installed.ToString(3)}");
                File.Delete(PendingUpdatePath);
            }
            else
            {
                WriteActionStatus("update", "error", -3, $"Update target v{target.ToString(3)} was not installed.");
                Log($"update-incomplete:target={target.ToString(3)}:current={installed.ToString(3)}");
                File.Delete(PendingUpdatePath);
            }
        }
        catch (Exception ex)
        {
            Log($"update-finalize-failed:{ex.GetType().Name}:{Compact(ex.Message)}");
        }
    }

    static async Task RunActionAsync(string scriptName, string actionName)
    {
        if (!await ActionGate.WaitAsync(0))
        {
            Log($"action-busy:{actionName}");
            WriteActionStatus(actionName, "busy", -1, "Another action is already running.");
            return;
        }

        try
        {
            var script = Path.Combine(AppContext.BaseDirectory, scriptName);
            if (!File.Exists(script))
            {
                Log($"action-missing:{actionName}:{script}");
                WriteActionStatus(actionName, "error", -1, "Privileged lifecycle script is missing.");
                return;
            }
            if (!File.Exists(PwshPath))
            {
                Log($"runtime-missing:{actionName}:{PwshPath}");
                WriteActionStatus(actionName, "error", -1, "Bundled PowerShell runtime is missing.");
                return;
            }

            var psi = new ProcessStartInfo(
                PwshPath,
                $"-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{script}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = AppContext.BaseDirectory
            };

            Log($"action-begin:{actionName}");
            WriteActionStatus(actionName, "running", null, "");
            using var p = Process.Start(psi);
            if (p is null)
            {
                Log($"action-start-failed:{actionName}");
                WriteActionStatus(actionName, "error", -1, "Unable to start PowerShell backend.");
                return;
            }

            if (!p.WaitForExit(120000))
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                try { p.WaitForExit(5000); } catch { }
                Log($"action-timeout:{actionName}");
                WriteActionStatus(actionName, "error", -2, "Privileged action exceeded the 120 second safety timeout and was terminated.");
                return;
            }
            Log($"action-end:{actionName}:exit={p.ExitCode}");
            var message = p.ExitCode == 0
                ? "Action completed."
                : $"Privileged action failed with exit code {p.ExitCode}. See lifecycle evidence/service log.";
            WriteActionStatus(actionName, p.ExitCode == 0 ? "done" : "error", p.ExitCode, message);
        }
        catch (Exception ex)
        {
            Log($"action-exception:{actionName}:{ex.GetType().Name}:{Compact(ex.Message)}");
            WriteActionStatus(actionName, "error", -1, ex.GetType().Name + ": " + ex.Message);
        }
        finally
        {
            ActionGate.Release();
        }
    }

    static void WriteActionStatus(string action, string phase, int? exitCode, string message)
    {
        try
        {
            Directory.CreateDirectory(RuntimeDir);
            var payload = System.Text.Json.JsonSerializer.Serialize(new
            {
                schema = 1,
                action,
                phase,
                exitCode,
                message = Compact(message),
                updatedUtc = DateTimeOffset.UtcNow.ToString("O")
            });
            var temp = ActionStatusPath + ".tmp";
            File.WriteAllText(temp, payload, new UTF8Encoding(false));
            File.Move(temp, ActionStatusPath, true);
        }
        catch (Exception ex)
        {
            Log($"action-status-write-failed:{action}:{ex.GetType().Name}:{Compact(ex.Message)}");
        }
    }

    static string Compact(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "-";
        var s = value.Replace("\r", " ").Replace("\n", " ");
        return s.Length <= 600 ? s : s[..600];
    }

    static void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(RuntimeDir);
            File.AppendAllText(LogPath, $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}", Encoding.UTF8);
        }
        catch { }
    }

    static void SetState(uint state, uint accepted, uint waitHint)
    {
        var s = new SERVICE_STATUS
        {
            dwServiceType = SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState = state,
            dwControlsAccepted = accepted,
            dwWin32ExitCode = 0,
            dwServiceSpecificExitCode = 0,
            dwCheckPoint = 0,
            dwWaitHint = waitHint
        };
        SetServiceStatus(_statusHandle, ref s);
    }

    static string SelfTest()
    {
        var required = new[] { "Start-Direct.ps1", "Stop-Direct.ps1", "Recovery.ps1" };
        var missing = required.Where(x => !File.Exists(Path.Combine(AppContext.BaseDirectory, x))).ToArray();
        return missing.Length == 0 ? "PASS" : "MISSING:" + string.Join(",", missing);
    }
}
