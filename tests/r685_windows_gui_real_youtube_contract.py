#!/usr/bin/env python3
"""Negative-first native Windows WPF GUI core-site health acceptance.

The service intentionally allows a two-of-three transport quorum to keep the
engine available with PARTIAL health. This test ensures the GUI cannot display
HEALTHY when generate_204 succeeds but the real YouTube page does not.

No installed services, registry, DNS, routes, browser profiles or network are
modified. Compile just the actual production C# predicate in a local temp dir.
"""
from __future__ import annotations
import pathlib
import re
import subprocess
import tempfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
GUI=(ROOT/"windows/gui/MainWindow.xaml.cs").read_text("utf-8-sig")
START=(ROOT/"windows/app/Start-Direct.ps1").read_text("utf-8-sig")

def need(cond,label):
    if not cond:raise SystemExit("R685_FAIL_"+label)

need('StatusBadge.Text = "PARTIAL";' in GUI,"PRESERVE_PARTIAL_STATUS")
need("function Get-CoreSiteHealth($ytPage,$yt204,$oa,$gh)" in START and
     "$httpsProbePassCount -lt 2" in START,"PRESERVE_TWO_OF_THREE_START")
need('var ytTask = ProbeAsync("https://www.youtube.com/", IpText.Text, new[] { "200" });' in GUI,
     "REAL_YOUTUBE_PAGE_PROBE_MISSING")
need('var yt204Task = ProbeAsync("https://www.youtube.com/generate_204", IpText.Text, new[] { "204" });' in GUI,
     "LIGHTWEIGHT_YOUTUBE_PROBE_MISSING")
need('var tasks = new List<Task> { ytTask, yt204Task, oaTask, ghTask, geminiTask };' in GUI,
     "SINGLE_REFRESH_ASYNCHRONOUS_TASK_GATHER")
need('var youtubeProbe = await ytTask;' in GUI and
     'var youtube204Probe = await yt204Task;' in GUI,"BOTH_PROBES_NOT_AWAITED")
need("coreReachabilityProven = FullCoreReachability(youtubeProbe, youtube204Probe, openAiProbe, githubProbe);" in GUI,
     "COMPLETE_REACHABILITY_NOT_USED")
need('YoutubeText.Text = $"Page {FmtHttp(youtubeProbe)} | 204 {FmtHttp(youtube204Probe)}";' in GUI,
     "SITE_SPECIFIC_GUI_EVIDENCE_MISSING")
need('mode == "ACTIVE" && (!ownedHealthy || !coreReachabilityProven)' in GUI,
     "PARTIAL_STATUS_NOT_DRIVEN_BY_ALL_SITES")
pat=r"static bool FullCoreReachability\s*\(\s*ProbeResult youtubePage,\s*ProbeResult youtube204,\s*ProbeResult openai,\s*ProbeResult github\)\s*=>\s*[^;]+;"
matches=re.findall(pat,GUI,re.S)
need(len(matches)==1,"PRODUCTION_CSHARP_PREDICATE_NOT_UNIQUE")
method=matches[0]
need("youtubePage.Ok" in method and "youtube204.Ok" in method and
     "openai.Ok" in method and "github.Ok" in method,"FULL_CORE_MATRIX_SOURCES")

with tempfile.TemporaryDirectory(prefix="dim_r685_native_core_site_") as temp:
    work=pathlib.Path(temp)
    (work/"check.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        '<OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>'
        '<ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable>'
        '</PropertyGroup></Project>',encoding="utf8")
    source='''using System;
internal sealed record ProbeResult(bool Ok);
internal static class Product {
%s
    internal static void Main(){
        for (int mask=0;mask<16;mask++){
            bool actual=FullCoreReachability(
                new ProbeResult((mask&1)!=0),
                new ProbeResult((mask&2)!=0),
                new ProbeResult((mask&4)!=0),
                new ProbeResult((mask&8)!=0));
            if(actual!=(mask==15))throw new Exception($"FALSE_CORE_SUCCESS_MASK_{mask}");
        }
        Console.WriteLine("R685_REAL_PRODUCTION_GUI_PREDICATE_16_OF_16_NATIVE_DOTNET10_PASS");
    }
}
''' % method
    (work/"Program.cs").write_text(source,encoding="utf8")
    p=subprocess.run(["dotnet","run","--project",str(work/"check.csproj"),
        "-c","Release","--no-launch-profile","--verbosity","quiet"],
        cwd=work,capture_output=True,text=True,timeout=120)
    need(p.returncode==0,"NATIVE_DOTNET_BUILD_OR_CORE_MATRIX_"+p.stderr[-400:])
    need("16_OF_16_NATIVE_DOTNET10_PASS" in p.stdout,"MATRIX_NOT_EXECUTED")
    print(p.stdout.strip())
print("R685_WPF_CORE_YOUTUBE_PAGE_AND_204_ACCURACY=PASS")