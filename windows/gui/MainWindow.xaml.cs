using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
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
    readonly string settingsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DirectInternetMethod", "settings.json");
    readonly string customHostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DirectInternetMethod", "UserConfig", "custom-hosts.txt");
    readonly string strategyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DirectInternetMethod", "UserConfig", "strategy.txt");
    readonly string scopePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DirectInternetMethod", "UserConfig", "scope.txt");
    UpdateInfo? availableUpdate;
    bool adultCheckEnabled;

    public MainWindow()
    {
        InitializeComponent();
        adultCheckEnabled = LoadAdultSiteCheckSetting();
        AdultSiteCheckToggle.IsChecked = adultCheckEnabled;
        AdultSiteCheckToggle.Checked += AdultSiteCheckToggle_Changed;
        AdultSiteCheckToggle.Unchecked += AdultSiteCheckToggle_Changed;
        Loaded += async (_, _) =>
        {
            await RefreshStatusAsync();
            _ = CheckForUpdatesAsync(false);
        };
    }

    Version CurrentVersion => Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 1, 0, 0);

    bool LoadAdultSiteCheckSetting()
    {
        try
        {
            if (!File.Exists(settingsPath)) return false;
            using var doc = JsonDocument.Parse(File.ReadAllText(settingsPath));
            return doc.RootElement.TryGetProperty("adultSiteLiveCheck", out var value) && value.ValueKind == JsonValueKind.True;
        }
        catch { return false; }
    }

    void SaveAdultSiteCheckSetting()
    {
        var dir = Path.GetDirectoryName(settingsPath)!;
        Directory.CreateDirectory(dir);
        var temp = settingsPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(new { adultSiteLiveCheck = adultCheckEnabled }));
        File.Move(temp, settingsPath, true);
    }

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

    sealed record ProbeResult(bool Ok, bool Reached, string Code, string RemoteIp, long Ms);

    async Task<ProbeResult> ProbeAsync(string url, string localIp, string[] allowed)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var psi = new ProcessStartInfo("curl.exe",
                $"-4 --interface {localIp} --noproxy * -A \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36\" -sS -o NUL -w \"%{{http_code}}|%{{remote_ip}}|%{{time_total}}\" --connect-timeout 5 --max-time 8 \"{url}\"")
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
            var reached = p.ExitCode == 0 && !string.IsNullOrWhiteSpace(code) && code != "000";
            return new ProbeResult(reached && allowed.Contains(code), reached, code, remote, sw.ElapsedMilliseconds);
        }
        catch
        {
            sw.Stop();
            return new ProbeResult(false, false, "", "", sw.ElapsedMilliseconds);
        }
    }

    static string FmtHttp(ProbeResult p) =>
        p.Ok ? $"PASS · HTTP {p.Code} · {p.Ms} ms" :
        p.Reached ? $"REACHABLE · HTTP {p.Code} · {p.Ms} ms" :
        "FAIL · transport";

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
            YoutubeText.Text = OpenAiText.Text = GithubText.Text = GeminiText.Text = mode == "CONFLICT" ? "Suspended by external tunnel" : ownedHealthy ? "Checking…" : "Available when Direct Method is healthy";
            AdultSiteText.Text = adultCheckEnabled ? (mode == "CONFLICT" ? "Suspended by external tunnel" : ownedHealthy ? "Checking…" : "Available when Direct Method is healthy") : "Disabled";
            if (ownedHealthy && mode == "ACTIVE" && !string.IsNullOrWhiteSpace(IpText.Text) && IpText.Text != "—")
            {
                var ytTask = ProbeAsync("https://www.youtube.com/generate_204", IpText.Text, new[] { "200", "204" });
                var oaTask = ProbeAsync("https://api.openai.com/v1/models", IpText.Text, new[] { "200", "401", "403" });
                var ghTask = ProbeAsync("https://github.com/", IpText.Text, new[] { "200", "301", "302" });
                var geminiTask = ProbeAsync("https://gemini.google.com/", IpText.Text, new[] { "200", "301", "302", "303", "307", "308" });
                Task<ProbeResult>? adultTask = adultCheckEnabled
                    ? ProbeAsync("https://www.pornhub.com/", IpText.Text, new[] { "200", "301", "302", "303", "307", "308" })
                    : null;
                var tasks = new List<Task> { ytTask, oaTask, ghTask, geminiTask };
                if (adultTask is not null) tasks.Add(adultTask);
                await Task.WhenAll(tasks);
                YoutubeText.Text = FmtHttp(await ytTask);
                OpenAiText.Text = FmtHttp(await oaTask);
                GithubText.Text = FmtHttp(await ghTask);
                GeminiText.Text = FmtHttp(await geminiTask);
                AdultSiteText.Text = adultTask is null ? "Disabled" : FmtHttp(await adultTask);
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
            YoutubeText.Text = OpenAiText.Text = GithubText.Text = GeminiText.Text = ex.Message;
            AdultSiteText.Text = adultCheckEnabled ? ex.Message : "Disabled";
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

    async void AdultSiteCheckToggle_Changed(object sender, RoutedEventArgs e)
    {
        adultCheckEnabled = AdultSiteCheckToggle.IsChecked == true;
        try { SaveAdultSiteCheckSetting(); }
        catch (Exception ex) { AdultSiteText.Text = "Settings error: " + ex.Message; return; }
        await RefreshStatusAsync();
    }

    static string? NormalizeCustomSite(string raw)
    {
        var value = (raw ?? "").Trim();
        if (string.IsNullOrWhiteSpace(value) || value.StartsWith('#')) return null;
        var exact = value.StartsWith('^');
        if (exact) value = value[1..].Trim();
        string host;
        if (Uri.TryCreate(value, UriKind.Absolute, out var absolute) && !string.IsNullOrWhiteSpace(absolute.Host))
            host = absolute.Host;
        else if (Uri.TryCreate("https://" + value, UriKind.Absolute, out var implied) && !string.IsNullOrWhiteSpace(implied.Host))
            host = implied.Host;
        else
            return null;
        host = host.Trim('.').ToLowerInvariant();
        if (host.Length is < 3 or > 253 || !host.Contains('.')) return null;
        var label = new Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.CultureInvariant);
        if (host.Split('.').Any(x => !label.IsMatch(x))) return null;
        return exact ? "^" + host : host;
    }

    void CustomSites_Click(object sender, RoutedEventArgs e)
    {
        var editor = new Window
        {
            Title = "Custom Sites", Owner = this, Width = 570, Height = 470, MinWidth = 470, MinHeight = 360,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#091725"))
        };
        var root = new DockPanel { Margin = new Thickness(18) };
        var note = new TextBlock
        {
            Text = "One site or URL per line. The saved domain and its subdomains use the existing Direct Method on the next Start. Prefix ^ for exact-host only. Maximum 256 entries.",
            TextWrapping = TextWrapping.Wrap, Foreground = Brushes.White, Margin = new Thickness(0,0,0,12)
        };
        DockPanel.SetDock(note, Dock.Top); root.Children.Add(note);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0,12,0,0) };
        DockPanel.SetDock(buttons, Dock.Bottom);
        var save = new Button { Content = "Save", MinWidth = 90, Margin = new Thickness(8,0,0,0), IsDefault = true };
        var cancel = new Button { Content = "Cancel", MinWidth = 90, Margin = new Thickness(8,0,0,0), IsCancel = true };
        buttons.Children.Add(save); buttons.Children.Add(cancel); root.Children.Add(buttons);
        var box = new TextBox
        {
            AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, FontFamily = new FontFamily("Consolas")
        };
        try { if (File.Exists(customHostsPath)) box.Text = File.ReadAllText(customHostsPath); } catch { }
        root.Children.Add(box); editor.Content = root;
        save.Click += (_, _) =>
        {
            try
            {
                var values = box.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)
                    .Select(NormalizeCustomSite).Where(x => !string.IsNullOrWhiteSpace(x))
                    .Distinct(StringComparer.OrdinalIgnoreCase).Take(256).ToArray();
                var dir = Path.GetDirectoryName(customHostsPath)!; Directory.CreateDirectory(dir);
                var tmp = customHostsPath + ".tmp";
                File.WriteAllText(tmp, string.Join(Environment.NewLine, values!) + (values.Length > 0 ? Environment.NewLine : ""), new System.Text.UTF8Encoding(false));
                File.Move(tmp, customHostsPath, true);
                editor.DialogResult = true; HealthText.Text = $"Custom sites saved: {values.Length}. Stop/Start to apply."; editor.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(editor, "Unable to save custom sites: " + ex.Message, "Direct Internet Method", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        };
        editor.ShowDialog();
    }
    void Strategy_Click(object sender, RoutedEventArgs e)
    {
        var current = "balanced";
        var allSites = false;
        try
        {
            if (File.Exists(strategyPath))
            {
                var raw = File.ReadAllText(strategyPath).Trim().ToLowerInvariant();
                if (raw is "balanced" or "compatibility" or "strong") current = raw;
            }
        }
        catch { }
        try
        {
            if (File.Exists(scopePath)) allSites = File.ReadAllText(scopePath).Trim().Equals("all-sites", StringComparison.OrdinalIgnoreCase);
        }
        catch { }

        var editor = new Window
        {
            Title = "Direct Strategy", Owner = this, Width = 540, Height = 390, ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#091725"))
        };
        var root = new StackPanel { Margin = new Thickness(20) };
        root.Children.Add(new TextBlock
        {
            Text = "Choose the packet strategy used for built-in and Custom Sites. Balanced is the default. Compatibility uses split-only TCP handling. Strong is more aggressive and should be used only when Balanced still fails.",
            TextWrapping = TextWrapping.Wrap, Foreground = Brushes.White, Margin = new Thickness(0,0,0,14)
        });
        var combo = new ComboBox { MinWidth = 230, HorizontalAlignment = HorizontalAlignment.Left };
        combo.Items.Add("Balanced"); combo.Items.Add("Compatibility"); combo.Items.Add("Strong");
        combo.SelectedIndex = current switch { "compatibility" => 1, "strong" => 2, _ => 0 };
        root.Children.Add(combo);
        var allSitesCheck = new CheckBox
        {
            Content = "Apply DPI strategy to all web sites (experimental)",
            IsChecked = allSites, Foreground = Brushes.White, Margin = new Thickness(0,14,0,0)
        };
        root.Children.Add(allSitesCheck);
        root.Children.Add(new TextBlock
        {
            Text = "Targeted mode affects only built-in and Custom Sites. All Sites mode can help unknown blocked domains, but may reduce compatibility or speed on some sites. Neither mode creates a VPN, proxy, or default-route tunnel.",
            TextWrapping = TextWrapping.Wrap, Foreground = neutral, Margin = new Thickness(0,12,0,16)
        });
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var cancel = new Button { Content = "Cancel", MinWidth = 90, Margin = new Thickness(8,0,0,0), IsCancel = true };
        var save = new Button { Content = "Save", MinWidth = 90, Margin = new Thickness(8,0,0,0), IsDefault = true };
        buttons.Children.Add(cancel); buttons.Children.Add(save); root.Children.Add(buttons); editor.Content = root;
        save.Click += (_, _) =>
        {
            try
            {
                var value = combo.SelectedIndex switch { 1 => "compatibility", 2 => "strong", _ => "balanced" };
                var dir = Path.GetDirectoryName(strategyPath)!; Directory.CreateDirectory(dir);
                var tmp = strategyPath + ".tmp";
                File.WriteAllText(tmp, value + Environment.NewLine, new System.Text.UTF8Encoding(false));
                File.Move(tmp, strategyPath, true);
                var scopeValue = allSitesCheck.IsChecked == true ? "all-sites" : "targeted";
                var scopeTmp = scopePath + ".tmp";
                File.WriteAllText(scopeTmp, scopeValue + Environment.NewLine, new System.Text.UTF8Encoding(false));
                File.Move(scopeTmp, scopePath, true);
                HealthText.Text = $"Strategy saved: {value}; scope: {scopeValue}. Stop/Start to apply.";
                editor.DialogResult = true; editor.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(editor, "Unable to save strategy: " + ex.Message, "Direct Internet Method", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        };
        editor.ShowDialog();
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
