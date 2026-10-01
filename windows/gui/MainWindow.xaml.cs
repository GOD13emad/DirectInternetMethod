using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;

namespace DirectInternetMethod;

public partial class MainWindow : Window
{
    readonly string appDir = AppContext.BaseDirectory;
    readonly string statePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DirectDnsDpiHarness", "state.json");
    readonly string actionStatusPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DirectInternetMethod", "action-status.json");
    readonly string bundledPwshPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DirectInternetMethod", "Privileged", "runtime", "pwsh", "pwsh.exe");
    readonly Brush ok = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#68E8A6"));
    readonly Brush warn = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFD166"));
    readonly Brush bad = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF7A85"));
    readonly Brush neutral = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#9FB1C3"));
    UpdateInfo? availableUpdate;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            await RefreshStatusAsync();
            _ = CheckForUpdatesAsync(false);
        };
    }

    Version CurrentVersion => Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 1, 0, 0);

    async Task<string> RunPwshCaptureAsync(string script, string args = "")
    {
        if (!File.Exists(bundledPwshPath))
            throw new FileNotFoundException("Bundled PowerShell runtime is missing.", bundledPwshPath);
        var psi = new ProcessStartInfo(bundledPwshPath,
            $"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{Path.Combine(appDir, script)}\" {args}")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = appDir
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Unable to start PowerShell 7.");
        var output = await p.StandardOutput.ReadToEndAsync();
        var error = await p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        if (p.ExitCode != 0) throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? $"Status backend exited {p.ExitCode}." : error.Trim());
        return output;
    }

    static string ReadStringList(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var v)) return "—";
        if (v.ValueKind == JsonValueKind.String) return v.GetString() ?? "—";
        if (v.ValueKind == JsonValueKind.Array)
        {
            var items = v.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() : x.ToString())
                .Where(x => !string.IsNullOrWhiteSpace(x));
            var text = string.Join(", ", items!);
            return string.IsNullOrWhiteSpace(text) ? "—" : text;
        }
        return "—";
    }

    sealed record ProbeResult(bool Ok, string Code, string RemoteIp, long Ms);

    async Task<ProbeResult> ProbeAsync(string url, string localIp, string[] allowed)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var psi = new ProcessStartInfo("curl.exe",
                $"-4 --interface {localIp} --noproxy * -sS -o NUL -w \"%{{http_code}}|%{{remote_ip}}|%{{time_total}}\" --max-time 5 \"{url}\"")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using var p = Process.Start(psi)!;
            var stdout = await p.StandardOutput.ReadToEndAsync();
            await p.WaitForExitAsync();
            sw.Stop();
            var parts = stdout.Trim().Split('|');
            var code = parts.Length > 0 ? parts[0] : "";
            var remote = parts.Length > 1 ? parts[1] : "";
            return new ProbeResult(p.ExitCode == 0 && allowed.Contains(code), code, remote, sw.ElapsedMilliseconds);
        }
        catch
        {
            sw.Stop();
            return new ProbeResult(false, "", "", sw.ElapsedMilliseconds);
        }
    }

    static string FmtHttp(ProbeResult p) =>
        p.Ok ? $"PASS · HTTP {p.Code} · {p.Ms} ms" : $"FAIL{(string.IsNullOrWhiteSpace(p.Code) ? "" : $" · HTTP {p.Code}")}";

    async Task RefreshStatusAsync()
    {
        try
        {
            HealthText.Text = "Checking…";
            var raw = await RunPwshCaptureAsync("Status.ps1", "-Json");
            using var d = JsonDocument.Parse(raw);
            var r = d.RootElement;
            var mode = r.TryGetProperty("mode", out var me) ? me.GetString() ?? "UNKNOWN" : "UNKNOWN";
            var reason = r.TryGetProperty("reason", out var re) ? re.GetString() ?? "" : "";

            StatusBadge.Text = mode;
            StatusBadge.Foreground = mode switch
            {
                "ACTIVE" => ok,
                "OFF" => neutral,
                "CONFLICT" => warn,
                "BLOCKED" => warn,
                _ => bad
            };

            InterfaceText.Text = r.TryGetProperty("interface", out var i) ? i.GetString() ?? "—" : "—";
            IpText.Text = r.TryGetProperty("localIp", out var ip) ? ip.GetString() ?? "—" : "—";
            DnsText.Text = ReadStringList(r, "adapterDns");

            int ula = r.TryGetProperty("ula", out var ue) && ue.ValueKind == JsonValueKind.Array ? ue.GetArrayLength() : 0;
            int nrpt = r.TryGetProperty("nrpt", out var ne) && ne.ValueKind == JsonValueKind.Array ? ne.GetArrayLength() : 0;
            int wd = r.TryGetProperty("winDivertCount", out var we) && we.TryGetInt32(out var wdv) ? wdv : 0;
            int broad = r.TryGetProperty("broadRouteCount", out var be) && be.TryGetInt32(out var bv) ? bv : 0;

            OwnedText.Text = $"ULA {ula} · NRPT {nrpt} · DPI {wd}";
            if (broad > 0 && r.TryGetProperty("broadRoutes", out var routes) && routes.ValueKind == JsonValueKind.Array)
            {
                var owners = routes.EnumerateArray()
                    .Select(x =>
                    {
                        if (x.TryGetProperty("description", out var de) && !string.IsNullOrWhiteSpace(de.GetString())) return de.GetString();
                        return x.TryGetProperty("interface", out var ie) ? ie.GetString() : null;
                    })
                    .Where(x => !string.IsNullOrWhiteSpace(x)).Distinct();
                var suffix = string.Join(", ", owners!);
                RouteText.Text = string.IsNullOrWhiteSpace(suffix) ? $"External tunnel routes: {broad}" : $"External tunnel routes: {broad} · {suffix}";
            }
            else RouteText.Text = "External tunnel routes: 0";

            bool ownedHealthy = r.TryGetProperty("ownedResourcesHealthy", out var oh) && oh.GetBoolean();
            YoutubeText.Text = OpenAiText.Text = GithubText.Text = mode == "CONFLICT" ? "Suspended by external tunnel" : ownedHealthy ? "Checking…" : "Available when Direct Method is healthy";
            if (ownedHealthy && mode == "ACTIVE" && !string.IsNullOrWhiteSpace(IpText.Text) && IpText.Text != "—")
            {
                var ytTask = ProbeAsync("https://www.youtube.com/generate_204", IpText.Text, new[] { "200", "204" });
                var oaTask = ProbeAsync("https://api.openai.com/v1/models", IpText.Text, new[] { "200", "401", "403" });
                var ghTask = ProbeAsync("https://github.com/", IpText.Text, new[] { "200", "301", "302" });
                await Task.WhenAll(ytTask, oaTask, ghTask);
                YoutubeText.Text = FmtHttp(await ytTask);
                OpenAiText.Text = FmtHttp(await oaTask);
                GithubText.Text = FmtHttp(await ghTask);
            }

            HealthText.Text = mode switch
            {
                "ACTIVE" => "Direct path healthy",
                "CONFLICT" => "External VPN/tunnel conflict",
                "BLOCKED" => "Disconnect external VPN/tunnel to Start",
                "DEGRADED" => "Recovery required",
                "OFF" => "Ready",
                _ => "Unknown state"
            };
            if (!string.IsNullOrWhiteSpace(reason)) ToolTip = reason;

            StartButton.IsEnabled = mode == "OFF";
            StopButton.IsEnabled = mode is "ACTIVE" or "CONFLICT" or "DEGRADED";
            RecoveryButton.IsEnabled = mode is "DEGRADED" or "CONFLICT";
            RefreshButton.IsEnabled = true;
        }
        catch (Exception ex)
        {
            HealthText.Text = "Status error";
            StatusBadge.Text = "ERROR";
            StatusBadge.Foreground = bad;
            YoutubeText.Text = OpenAiText.Text = GithubText.Text = ex.Message;
            StartButton.IsEnabled = false;
            StopButton.IsEnabled = false;
            RecoveryButton.IsEnabled = true;
            RefreshButton.IsEnabled = true;
        }
    }

    sealed record ActionResult(string Phase, int? ExitCode, string Message);

    async Task<ActionResult> WaitForActionAsync(string action, DateTime previousWriteUtc, int timeoutMs = 130000)
    {
        var until = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < until)
        {
            try
            {
                if (File.Exists(actionStatusPath) && File.GetLastWriteTimeUtc(actionStatusPath) > previousWriteUtc)
                {
                    using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(actionStatusPath));
                    var root = doc.RootElement;
                    var actual = root.TryGetProperty("action", out var ae) ? ae.GetString() ?? "" : "";
                    var phase = root.TryGetProperty("phase", out var pe) ? pe.GetString() ?? "" : "";
                    if (actual.Equals(action, StringComparison.OrdinalIgnoreCase) &&
                        phase is "done" or "error" or "busy" or "handoff")
                    {
                        int? exit = root.TryGetProperty("exitCode", out var ee) && ee.ValueKind == JsonValueKind.Number ? ee.GetInt32() : null;
                        var message = root.TryGetProperty("message", out var me) ? me.GetString() ?? "" : "";
                        return new ActionResult(phase, exit, message);
                    }
                }
            }
            catch (IOException) { }
            catch (JsonException) { }
            await Task.Delay(200);
        }
        throw new TimeoutException($"{action} did not complete within {timeoutMs / 1000} seconds.");
    }

    async Task RunActionAsync(string action, string label)
    {
        SetBusy(true, label + "…");
        try
        {
            var previousWriteUtc = File.Exists(actionStatusPath) ? File.GetLastWriteTimeUtc(actionStatusPath) : DateTime.MinValue;
            ServiceClient.Send(action);
            var result = await WaitForActionAsync(action, previousWriteUtc);
            if (result.Phase != "done" || result.ExitCode != 0)
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(result.Message)
                    ? $"{label} failed ({result.ExitCode?.ToString() ?? result.Phase})."
                    : result.Message);
        }
        catch (Exception ex)
        {
            HealthText.Text = ex.Message;
        }
        finally
        {
            await RefreshStatusAsync();
            SetBusy(false, "");
        }
    }

    void SetBusy(bool busy, string message)
    {
        if (busy)
        {
            StartButton.IsEnabled = StopButton.IsEnabled = RefreshButton.IsEnabled = RecoveryButton.IsEnabled = UpdateButton.IsEnabled = false;
            HealthText.Text = message;
        }
        else
        {
            UpdateButton.IsEnabled = true;
        }
    }

    async Task CheckForUpdatesAsync(bool userInitiated)
    {
        try
        {
            UpdateButton.IsEnabled = false;
            UpdateButton.Content = "Checking…";
            availableUpdate = await UpdateClient.CheckAsync(CurrentVersion);
            if (availableUpdate is null)
            {
                UpdateButton.Content = "Up to date";
                if (userInitiated) HealthText.Text = "No newer release is available";
            }
            else
            {
                UpdateButton.Content = $"Update v{availableUpdate.Version}";
                ToolTip = $"Verified update available: {availableUpdate.Tag}";
            }
        }
        catch (Exception ex)
        {
            UpdateButton.Content = "Check Update";
            if (userInitiated) HealthText.Text = "Update check failed: " + ex.Message;
        }
        finally
        {
            UpdateButton.IsEnabled = true;
        }
    }

    async void Update_Click(object sender, RoutedEventArgs e)
    {
        if (availableUpdate is null)
        {
            await CheckForUpdatesAsync(true);
            if (availableUpdate is null) return;
        }

        try
        {
            SetBusy(true, $"Preparing direct update to v{availableUpdate.Version}…");

            var recoveryWrite = File.Exists(actionStatusPath) ? File.GetLastWriteTimeUtc(actionStatusPath) : DateTime.MinValue;
            ServiceClient.Send("recovery");
            var recovery = await WaitForActionAsync("recovery", recoveryWrite);
            if (recovery.Phase != "done" || recovery.ExitCode != 0)
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(recovery.Message)
                    ? "Unable to prepare a clean OFF state for update."
                    : recovery.Message);

            HealthText.Text = $"Downloading and verifying v{availableUpdate.Version}…";
            var updateWrite = File.Exists(actionStatusPath) ? File.GetLastWriteTimeUtc(actionStatusPath) : DateTime.MinValue;
            ServiceClient.Send("update");
            var result = await WaitForActionAsync("update", updateWrite, 300000);

            if (result.Phase == "handoff" && result.ExitCode == 0)
            {
                HealthText.Text = result.Message;
                await Task.Delay(600);
                Close();
                return;
            }

            if (result.Phase == "done" && result.ExitCode == 0)
            {
                availableUpdate = null;
                HealthText.Text = result.Message;
                UpdateButton.Content = "Up to date";
                SetBusy(false, "");
                return;
            }

            throw new InvalidOperationException(string.IsNullOrWhiteSpace(result.Message)
                ? $"Direct update failed ({result.ExitCode?.ToString() ?? result.Phase})."
                : result.Message);
        }
        catch (Exception ex)
        {
            HealthText.Text = "Update failed: " + ex.Message;
            SetBusy(false, "");
        }
    }

    void RouterGateway_Click(object sender, RoutedEventArgs e)
    {
        var w = new RouterGatewayWindow { Owner = this };
        w.ShowDialog();
    }

    async void Start_Click(object sender, RoutedEventArgs e) => await RunActionAsync("start", "Start");
    async void Stop_Click(object sender, RoutedEventArgs e) => await RunActionAsync("stop", "Stop");
    async void Recovery_Click(object sender, RoutedEventArgs e) => await RunActionAsync("recovery", "Recovery");
    async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshStatusAsync();
}
