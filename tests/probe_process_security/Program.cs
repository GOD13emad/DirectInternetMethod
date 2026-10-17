using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using DirectInternetMethod;

var passed = 0;
void Check(string name, Action test)
{
    test();
    passed++;
    Console.WriteLine("PASS " + name);
}
void Need(bool value, string reason)
{
    if (!value) throw new InvalidOperationException("R057_SECURITY_REGRESSION:" + reason);
}
void Reject(string label, string url, string ip)
{
    Check(label, () =>
    {
        try
        {
            _ = ProbeProcessBuilder.Create(url, ip);
            throw new InvalidOperationException("R057_UNSAFE_ARGUMENT_ACCEPTED:" + label);
        }
        catch (ArgumentException) { }
    });
}

const string valid = "https://www.youtube.com/generate_204";
const string physical = "192.168.8.42";

Check("fixed_system32_curl_not_path_or_cwd", () =>
{
    var plan = ProbeProcessBuilder.Create(valid, physical);
    var expected = Path.GetFullPath(Path.Combine(
        Environment.SystemDirectory, "curl.exe"));
    Need(string.Equals(plan.FileName, expected, StringComparison.OrdinalIgnoreCase),
        "Executable is not the OS system curl");
    Need(Path.IsPathFullyQualified(plan.FileName), "Executable path not absolute");
    Need(!plan.UseShellExecute && plan.CreateNoWindow &&
         plan.RedirectStandardOutput && plan.RedirectStandardError, "Unsafe process shell IO");
});
Check("atomic_seventeen_curl_arguments", () =>
{
    var args = ProbeProcessBuilder.Create(valid, physical).ArgumentList.ToArray();
    Need(args.Length == 17, "Unexpected argv count");
    Need(args[0] == "-4" && args[1] == "--interface" && args[2] == physical,
        "Interface not a single argv token");
    Need(args[3] == "--noproxy" && args[4] == "*", "Proxy bypass drift");
    Need(args[8] == "-o" && args[9] == "NUL", "No-output behavior drift");
    Need(args[10] == "-w" && args[11] == "%{http_code}|%{remote_ip}|%{time_total}",
        "Live metrics parser contract drift");
    Need(args[16] == valid, "Endpoint changed");
});
Check("path_poisoning_does_not_change_executable", () =>
{
    var old = Environment.GetEnvironmentVariable("PATH");
    try
    {
        Environment.SetEnvironmentVariable("PATH", Path.Combine(Path.GetTempPath(), "R057-untrusted-bin"));
        var plan = ProbeProcessBuilder.Create(valid, physical);
        Need(plan.FileName.EndsWith("curl.exe", StringComparison.OrdinalIgnoreCase) &&
             !plan.FileName.Contains("R057-untrusted-bin", StringComparison.OrdinalIgnoreCase),
            "User-controlled PATH influenced process filename");
    }
    finally { Environment.SetEnvironmentVariable("PATH", old); }
});
Check("approved_https_hosts_remain_usable", () =>
{
    foreach (var host in new[] {
        "www.youtube.com", "api.openai.com", "github.com", "gemini.google.com",
        "www.pornhub.com", "www.xvideos.com", "www.xnxx.com", "xhamster.com"
    })
        Need(ProbeProcessBuilder.Create("https://" + host + "/", physical)
                .ArgumentList.Last() == "https://" + host + "/",
            "Approved origin silently blocked: " + host);
});
foreach (var (label, url, ip) in new (string, string, string)[] {
    ("injected_interface_flags", valid, "192.168.8.42 --output C:\\evil.txt"),
    ("injected_interface_newline", valid, "192.168.8.42\n--data-binary @C:\\s"),
    ("injected_interface_quotes", valid, "192.168.8.42\" -K cfg"),
    ("ipv6_rejected", valid, "::1"),
    ("invalid_octet_rejected", valid, "999.168.8.42"),
    ("leading_dash_rejected", valid, "--config"),
    ("noncanonical_ipv4_rejected", valid, "127.1"),
    ("scheme_http_rejected", "http://github.com/", physical),
    ("host_spoof_rejected", "https://github.com.evil.example/", physical),
    ("userinfo_rejected", "https://user:pass@github.com/", physical),
    ("unapproved_host_rejected", "https://attacker.example/", physical),
    ("custom_port_rejected", "https://github.com:8443/", physical),
    ("fragment_rejected", "https://github.com/#data", physical),
    ("query_rejected", "https://github.com/?test=1", physical),
}) Reject(label, url, ip);
Console.WriteLine(JsonSerializer.Serialize(new { Status = "PASS", Version = "R057",
    Checks = passed, ActualProcessSpawned = false, NetworkChanged = false }));
