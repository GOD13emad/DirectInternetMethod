using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace DirectInternetMethod;

internal sealed class RouterProfile
{
    public string Id { get; set; } = "";
    public string Provider { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string Country { get; set; } = "";
    public string Host { get; set; } = "";
    public string Ip { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string PreSharedKey { get; set; } = "";
    public string Security { get; set; } = "";
    public int? ObservedPingMs { get; set; }
    public DateTime SourceObservedUtc { get; set; }
    public string CredentialStatus { get; set; } = "";
    public string TestStatus { get; set; } = "Not tested";
    public long? TestLatencyMs { get; set; }
    public string DisplayServer => string.IsNullOrWhiteSpace(Ip) ? Host : $"{Ip} ({Host})";
    public string DisplayLatency => TestLatencyMs is long ms ? $"{ms} ms" :
        ObservedPingMs is int observed ? $"source {observed} ms" : "—";
}

internal sealed class RouterGuide
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string L2tp { get; set; } = "";
    public string Pptp { get; set; } = "";
}

internal sealed class RouterGatewayData
{
    public DateTime GeneratedUtc { get; set; }
    public List<RouterProfile> Profiles { get; set; } = [];
    public List<RouterGuide> RouterGuides { get; set; } = [];
    public string Origin { get; set; } = "bundled";
}

internal static class RouterGatewayClient
{
    const string RawManifest = "https://raw.githubusercontent.com/GOD13emad/DirectInternetMethod/main/router_gateway/providers.json";
    const string VpnBook = "https://www.vpnbook.com/freevpn/pptp-vpn";
    static readonly HttpClient Http = CreateClient();

    static HttpClient CreateClient()
    {
        var h = new HttpClient { Timeout = TimeSpan.FromSeconds(9) };
        h.DefaultRequestHeaders.UserAgent.ParseAdd("DirectInternetMethod/1.3");
        return h;
    }

    static string BundledPath => Path.Combine(AppContext.BaseDirectory, "router_gateway", "providers.json");
    static string CachePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DirectInternetMethod", "router_gateway", "providers.json");

    static RouterGatewayData Parse(string json, string origin)
    {
        using var d = JsonDocument.Parse(json);
        var r = d.RootElement;
        if (!r.TryGetProperty("schema", out var schema) || schema.GetInt32() != 1)
            throw new InvalidDataException("Unsupported Router Gateway manifest schema.");
        var data = new RouterGatewayData { Origin = origin };
        if (r.TryGetProperty("generatedUtc", out var gu) && DateTime.TryParse(gu.GetString(), out var gd))
            data.GeneratedUtc = gd.ToUniversalTime();
        foreach (var p in r.GetProperty("profiles").EnumerateArray())
        {
            int? observed = null;
            if (p.TryGetProperty("observedPingMs", out var op) && op.ValueKind == JsonValueKind.Number)
                observed = op.GetInt32();
            DateTime seen = DateTime.MinValue;
            if (p.TryGetProperty("sourceObservedUtc", out var so))
                DateTime.TryParse(so.GetString(), out seen);
            data.Profiles.Add(new RouterProfile
            {
                Id = S(p,"id"), Provider = S(p,"provider"), Protocol = S(p,"protocol"),
                Country = S(p,"country"), Host = S(p,"host"), Ip = S(p,"ip"),
                Username = S(p,"username"), Password = S(p,"password"),
                PreSharedKey = S(p,"preSharedKey"), Security = S(p,"security"),
                ObservedPingMs = observed, SourceObservedUtc = seen.ToUniversalTime(),
                CredentialStatus = S(p,"credentialStatus")
            });
        }
        if (r.TryGetProperty("routerGuides", out var guides))
            foreach (var g in guides.EnumerateArray())
                data.RouterGuides.Add(new RouterGuide { Id=S(g,"id"), Name=S(g,"name"), L2tp=S(g,"l2tp"), Pptp=S(g,"pptp") });
        if (data.Profiles.Count == 0) throw new InvalidDataException("Router Gateway manifest contains no profiles.");
        return data;
    }

    static string S(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    internal static RouterGatewayData LoadBest()
    {
        var candidates = new List<RouterGatewayData>();
        foreach (var item in new[] { (CachePath, "cache"), (BundledPath, "bundled") })
        {
            try { if (File.Exists(item.Item1)) candidates.Add(Parse(File.ReadAllText(item.Item1), item.Item2)); }
            catch { }
        }
        if (candidates.Count == 0) throw new FileNotFoundException("No valid Router Gateway data is available.");
        return candidates.OrderByDescending(x => x.GeneratedUtc).First();
    }

    internal static async Task<RouterGatewayData> RefreshAsync(CancellationToken ct = default)
    {
        string json;
        using (var response = await Http.GetAsync(RawManifest, ct))
        {
            response.EnsureSuccessStatusCode();
            json = await response.Content.ReadAsStringAsync(ct);
        }
        var data = Parse(json, "github");
        try
        {
            var html = await Http.GetStringAsync(VpnBook, ct);
            var m = Regex.Match(html, @"(?is)Password.{0,1200}?(?:<code[^>]*>|>)([A-Za-z0-9]{6,16})(?:</code>|<)");
            if (m.Success)
            {
                var password = m.Groups[1].Value;
                foreach (var p in data.Profiles.Where(x => x.Provider.Equals("VPNBook", StringComparison.OrdinalIgnoreCase)))
                {
                    p.Password = password;
                    p.CredentialStatus = "LIVE_REFRESHED_ROTATING";
                    p.SourceObservedUtc = DateTime.UtcNow;
                }
                json = PatchVpnBookPassword(json, password);
            }
        }
        catch { /* GitHub manifest remains usable when upstream is blocked. */ }

        Directory.CreateDirectory(Path.GetDirectoryName(CachePath)!);
        var tmp = CachePath + ".tmp";
        await File.WriteAllTextAsync(tmp, json, ct);
        File.Move(tmp, CachePath, true);
        return Parse(json, "refreshed-cache");
    }

    static string PatchVpnBookPassword(string json, string password)
    {
        var root = JsonNode.Parse(json)?.AsObject() ?? throw new InvalidDataException("Invalid Router Gateway JSON.");
        if (root["profiles"] is JsonArray profiles)
        {
            foreach (var node in profiles)
            {
                if (node is not JsonObject profile) continue;
                if (!string.Equals((string?)profile["provider"], "VPNBook", StringComparison.OrdinalIgnoreCase)) continue;
                profile["password"] = password;
                profile["credentialStatus"] = "LIVE_REFRESHED_ROTATING";
                profile["sourceObservedUtc"] = DateTime.UtcNow.ToString("O");
            }
        }
        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    static bool IsPublicEndpointAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return false;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            if (b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
            return true;
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return !address.IsIPv6LinkLocal && !address.IsIPv6SiteLocal && !address.IsIPv6Multicast;
        return false;
    }

    internal static async Task<(bool ok,long? ms,string detail)> TestAsync(RouterProfile p, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(string.IsNullOrWhiteSpace(p.Ip) ? p.Host : p.Ip, ct);
            var address = addresses.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault();
            if (address is null) return (false, null, "DNS failed");
            if (!IsPublicEndpointAddress(address))
                return (false, null, $"DNS intercepted/private address {address}");
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(address, TimeSpan.FromMilliseconds(1400), Array.Empty<byte>(), new PingOptions(64, true), ct);
                if (reply.Status == IPStatus.Success) return (true, reply.RoundtripTime, $"ICMP {address}");
            }
            catch { }

            var port = p.Protocol.StartsWith("PPTP", StringComparison.OrdinalIgnoreCase) ? 1723 : 443;
            using var tcp = new TcpClient(address.AddressFamily);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(1800);
            await tcp.ConnectAsync(address, port, timeout.Token);
            sw.Stop();
            return (true, sw.ElapsedMilliseconds, $"TCP/{port} health heuristic {address}");
        }
        catch (Exception ex)
        {
            return (false, null, ex is OperationCanceledException ? "Timeout" : ex.Message);
        }
    }

    internal static string BuildConfig(RouterProfile p, RouterGuide guide)
    {
        var server = string.IsNullOrWhiteSpace(p.Ip) ? p.Host : p.Ip;
        var useIp = !string.IsNullOrWhiteSpace(p.Ip);
        var lines = new List<string>
        {
            "Direct Internet Method — Router Gateway",
            $"Provider: {p.Provider}",
            $"Protocol: {p.Protocol}",
            $"Country: {p.Country}",
            $"Server: {server}",
            useIp ? $"Hostname (reference): {p.Host}" : "",
            $"Username: {p.Username}",
            $"Password: {p.Password}",
            p.Protocol.StartsWith("L2TP", StringComparison.OrdinalIgnoreCase) ? $"IPsec PSK / Secret: {p.PreSharedKey}" : "",
            $"Security: {p.Security}",
            $"Credential status: {p.CredentialStatus}",
            $"Source observed UTC: {p.SourceObservedUtc:yyyy-MM-dd HH:mm}",
            "",
            $"Router: {guide.Name}",
            p.Protocol.StartsWith("L2TP", StringComparison.OrdinalIgnoreCase) ? guide.L2tp : guide.Pptp,
            "",
            p.Protocol.StartsWith("PPTP", StringComparison.OrdinalIgnoreCase)
                ? "WARNING: PPTP is a legacy compatibility fallback. Prefer L2TP/IPsec or OpenVPN when your router supports them."
                : "Tip: If DDNS is filtered, use the numeric server IP."
        };
        return string.Join(Environment.NewLine, lines.Where(x => x is not null));
    }
}
