using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace DirectInternetMethod;

// This is a pure process-creation plan: it never launches curl or changes host routes.
// Restrict executable discovery to the OS protected system directory, not PATH/CWD.
internal static class ProbeProcessBuilder
{
    private static readonly HashSet<string> ProbeHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "www.youtube.com", "api.openai.com", "github.com", "gemini.google.com",
        "www.pornhub.com", "www.xvideos.com", "www.xnxx.com", "xhamster.com"
    };

    internal static ProcessStartInfo Create(string url, string localIp)
    {
        var ipText = localIp?.Trim();
        if (string.IsNullOrEmpty(ipText) ||
            !IPAddress.TryParse(ipText, out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork ||
            !string.Equals(ip.ToString(), ipText, StringComparison.Ordinal))
            throw new ArgumentException("Probe requires one canonical physical IPv4 address.", nameof(localIp));

        if (!Uri.TryCreate(url, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttps ||
            endpoint.Port != 443 ||
            !string.IsNullOrEmpty(endpoint.UserInfo) ||
            !string.IsNullOrEmpty(endpoint.Fragment) ||
            !string.IsNullOrEmpty(endpoint.Query) ||
            !ProbeHosts.Contains(endpoint.IdnHost))
            throw new ArgumentException("Probe endpoint is not an allowed HTTPS destination.", nameof(url));

        var systemFolder = Environment.SystemDirectory;
        if (string.IsNullOrEmpty(systemFolder) || !Path.IsPathFullyQualified(systemFolder))
            throw new InvalidOperationException("Trusted Windows system directory unavailable.");
        var curl = Path.GetFullPath(Path.Combine(systemFolder, "curl.exe"));
        if (!File.Exists(curl))
            throw new FileNotFoundException("Protected Windows curl.exe unavailable.", curl);

        var psi = new ProcessStartInfo(curl)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };
        // ArgumentList prevents endpoint/interface data from being reparsed as extra curl flags.
        foreach (var argument in new[]
        {
            "-4", "--interface", ip.ToString(), "--noproxy", "*",
            "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
            "-sS", "-o", "NUL", "-w", "%{http_code}|%{remote_ip}|%{time_total}",
            "--connect-timeout", "5", "--max-time", "8", endpoint.AbsoluteUri
        })
            psi.ArgumentList.Add(argument);
        return psi;
    }
}
