using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

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
                WorkingDirectory = AppContext.BaseDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true
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

            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(120));
            try
            {
                await p.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                try { await p.WaitForExitAsync(); } catch { }
                var timedOutOut = (await stdoutTask).Trim();
                var timedOutErr = (await stderrTask).Trim();
                Log($"action-timeout:{actionName}:out={Compact(timedOutOut)}:err={Compact(timedOutErr)}");
                WriteActionStatus(actionName, "error", -2, "Privileged action exceeded the 120 second safety timeout and was terminated.");
                return;
            }
            var stdout = (await stdoutTask).Trim();
            var stderr = (await stderrTask).Trim();
            Log($"action-end:{actionName}:exit={p.ExitCode}:out={Compact(stdout)}:err={Compact(stderr)}");
            WriteActionStatus(actionName, p.ExitCode == 0 ? "done" : "error", p.ExitCode, string.IsNullOrWhiteSpace(stderr) ? stdout : stderr);
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
