using System.Net.Http;
using System.Text.Json;

namespace DirectInternetMethod;

internal sealed record UpdateInfo(Version Version, string Tag, string InstallerName, string InstallerUrl, string InstallerDigest, string ChecksumsUrl);

internal static class UpdateClient
{
    const string LatestApi = "https://api.github.com/repos/GOD13emad/DirectInternetMethod/releases/latest";
    static readonly HttpClient Http = CreateClient();

    static HttpClient CreateClient()
    {
        var h = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        h.DefaultRequestHeaders.UserAgent.ParseAdd("DirectInternetMethod/1.3");
        h.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return h;
    }

    internal static async Task<UpdateInfo?> CheckAsync(Version current, CancellationToken ct = default)
    {
        using var response = await Http.GetAsync(LatestApi, ct);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var root = doc.RootElement;
        if (root.TryGetProperty("draft", out var draft) && draft.GetBoolean())
            throw new InvalidOperationException("Latest release is a draft.");
        if (root.TryGetProperty("prerelease", out var pre) && pre.GetBoolean())
            throw new InvalidOperationException("Latest release is a prerelease.");

        var tag = root.GetProperty("tag_name").GetString() ?? "";
        var clean = tag.Trim().TrimStart('v', 'V');
        if (!Version.TryParse(clean, out var latest) || latest <= current) return null;

        var installers = new List<(string Name, string Url, string Digest)>();
        var sums = new List<string>();
        foreach (var a in root.GetProperty("assets").EnumerateArray())
        {
            var name = a.GetProperty("name").GetString() ?? "";
            var url = a.GetProperty("browser_download_url").GetString() ?? "";
            if (name.EndsWith("_Windows_Setup.exe", StringComparison.OrdinalIgnoreCase))
            {
                var digest = a.TryGetProperty("digest", out var de) ? de.GetString() ?? "" : "";
                installers.Add((name, url, digest));
            }
            else if (name.Equals("SHA256SUMS.txt", StringComparison.OrdinalIgnoreCase))
                sums.Add(url);
        }

        if (installers.Count != 1 || sums.Count != 1)
            throw new InvalidOperationException("Latest release must contain exactly one Windows installer and one SHA256SUMS.txt.");
        if (!installers[0].Digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) || installers[0].Digest.Length != 71)
            throw new InvalidOperationException("Latest Windows asset is missing its GitHub SHA-256 digest.");

        return new UpdateInfo(latest, tag, installers[0].Name, installers[0].Url, installers[0].Digest, sums[0]);
    }
}
