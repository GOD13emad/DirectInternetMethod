using System.IO;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;

namespace DirectInternetMethod;

internal sealed record UpdateInfo(Version Version, string Tag, string InstallerName, string InstallerUrl, string ChecksumsUrl);

internal static class UpdateClient
{
    const string LatestApi = "https://api.github.com/repos/GOD13emad/DirectInternetMethod/releases/latest";
    static readonly HttpClient Http = CreateClient();

    static HttpClient CreateClient()
    {
        var h = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        h.DefaultRequestHeaders.UserAgent.ParseAdd("DirectInternetMethod/1.1");
        h.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return h;
    }

    internal static async Task<UpdateInfo?> CheckAsync(Version current, CancellationToken ct = default)
    {
        using var response = await Http.GetAsync(LatestApi, ct);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var root = doc.RootElement;
        var tag = root.GetProperty("tag_name").GetString() ?? "";
        var clean = tag.Trim().TrimStart('v', 'V');
        if (!Version.TryParse(clean, out var latest) || latest <= current) return null;

        string? installerName = null, installerUrl = null, sumsUrl = null;
        foreach (var a in root.GetProperty("assets").EnumerateArray())
        {
            var name = a.GetProperty("name").GetString() ?? "";
            var url = a.GetProperty("browser_download_url").GetString() ?? "";
            if (name.EndsWith("_Windows_Setup.exe", StringComparison.OrdinalIgnoreCase))
            {
                installerName = name; installerUrl = url;
            }
            else if (name.Equals("SHA256SUMS.txt", StringComparison.OrdinalIgnoreCase))
                sumsUrl = url;
        }

        if (installerName is null || installerUrl is null || sumsUrl is null)
            throw new InvalidOperationException("Latest release is missing the Windows installer or SHA256SUMS.txt.");

        return new UpdateInfo(latest, tag, installerName, installerUrl, sumsUrl);
    }

    internal static async Task<string> DownloadVerifiedAsync(UpdateInfo info, CancellationToken ct = default)
    {
        var sums = await Http.GetStringAsync(info.ChecksumsUrl, ct);
        string? expected = null;
        foreach (var raw in sums.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length < 64) continue;
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && parts[^1].TrimStart('*').Equals(info.InstallerName, StringComparison.OrdinalIgnoreCase))
            {
                expected = parts[0].Trim();
                break;
            }
        }
        if (expected is null || expected.Length != 64)
            throw new InvalidOperationException("No checksum found for the Windows installer.");

        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DirectInternetMethod", "updates");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, info.InstallerName);
        await using (var input = await Http.GetStreamAsync(info.InstallerUrl, ct))
        await using (var output = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
            await input.CopyToAsync(output, ct);

        await using var verify = File.OpenRead(path);
        var actual = Convert.ToHexString(await SHA256.HashDataAsync(verify, ct));
        if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
        {
            File.Delete(path);
            throw new InvalidOperationException("Downloaded update failed SHA-256 verification.");
        }
        return path;
    }

    internal static void LaunchInstaller(string path)
    {
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }
}
