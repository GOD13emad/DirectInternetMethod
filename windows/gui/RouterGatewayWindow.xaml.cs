using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;

namespace DirectInternetMethod;

public partial class RouterGatewayWindow : Window
{
    readonly ObservableCollection<RouterProfile> visible = [];
    RouterGatewayData data = new();

    public RouterGatewayWindow()
    {
        InitializeComponent();
        ProfilesGrid.ItemsSource = visible;
        Loaded += (_, _) => LoadData();
    }

    void LoadData()
    {
        try
        {
            data = RouterGatewayClient.LoadBest();
            RouterBox.ItemsSource = data.RouterGuides;
            RouterBox.SelectedItem = data.RouterGuides.FirstOrDefault(x => x.Id == "generic") ?? data.RouterGuides.FirstOrDefault();
            DataStatus.Text = $"{data.Origin} · {data.GeneratedUtc:yyyy-MM-dd HH:mm} UTC";
            HintText.Text = "Use numeric IP if the .opengw.net hostname is filtered. Select a row to get copy-ready modem/router fields.";
            ApplyFilter();
        }
        catch (Exception ex)
        {
            ResultText.Text = "Router Gateway data error: " + ex.Message;
        }
    }

    void ApplyFilter()
    {
        var protocol = (ProtocolBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All";
        visible.Clear();
        foreach (var p in data.Profiles.Where(x => protocol == "All" || x.Protocol.Equals(protocol, StringComparison.OrdinalIgnoreCase))
                     .OrderBy(x => x.Protocol.StartsWith("PPTP") ? 1 : 0).ThenBy(x => x.ObservedPingMs ?? int.MaxValue))
            visible.Add(p);
        if (visible.Count > 0) ProfilesGrid.SelectedIndex = 0;
        UpdateConfig();
    }

    void UpdateConfig()
    {
        if (ProfilesGrid.SelectedItem is not RouterProfile p || RouterBox.SelectedItem is not RouterGuide guide)
        {
            ConfigText.Text = "";
            return;
        }
        ConfigText.Text = RouterGatewayClient.BuildConfig(p, guide);
    }

    async void RefreshData_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ResultText.Text = "Refreshing repository snapshot and rotating credentials…";
            var refreshed = await RouterGatewayClient.RefreshAsync();
            data = refreshed;
            RouterBox.ItemsSource = data.RouterGuides;
            RouterBox.SelectedItem = data.RouterGuides.FirstOrDefault(x => x.Id == "generic") ?? data.RouterGuides.FirstOrDefault();
            DataStatus.Text = $"{data.Origin} · {data.GeneratedUtc:yyyy-MM-dd HH:mm} UTC";
            ApplyFilter();
            ResultText.Text = "Refresh completed. If an upstream provider was blocked, the verified repository snapshot was retained.";
        }
        catch (Exception ex)
        {
            ResultText.Text = "Refresh unavailable; current snapshot retained. " + ex.Message;
        }
    }

    async void TestAll_Click(object sender, RoutedEventArgs e)
    {
        ResultText.Text = "Testing visible endpoints without changing routes or VPN state…";
        var list = visible.ToList();
        foreach (var p in list)
        {
            p.TestStatus = "Testing…";
            ProfilesGrid.Items.Refresh();
            var r = await RouterGatewayClient.TestAsync(p);
            p.TestLatencyMs = r.ms;
            p.TestStatus = r.ok ? "Reachable · " + r.detail : "Unverified · " + r.detail;
            ProfilesGrid.Items.Refresh();
        }
        ResultText.Text = $"Endpoint health test completed for {list.Count} profile(s). This is a reachability heuristic, not a full VPN handshake.";
        UpdateConfig();
    }

    void CopySelected_Click(object sender, RoutedEventArgs e)
    {
        UpdateConfig();
        if (!string.IsNullOrWhiteSpace(ConfigText.Text))
        {
            Clipboard.SetText(ConfigText.Text);
            ResultText.Text = "Selected router profile copied.";
        }
    }

    void FilterChanged(object sender, SelectionChangedEventArgs e) { if (IsLoaded) ApplyFilter(); }
    void RouterChanged(object sender, SelectionChangedEventArgs e) { if (IsLoaded) UpdateConfig(); }
    void ProfileChanged(object sender, SelectionChangedEventArgs e) { if (IsLoaded) UpdateConfig(); }
}
