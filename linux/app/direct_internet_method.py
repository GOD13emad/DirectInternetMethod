#!/usr/bin/env python3
from __future__ import annotations
import ctypes
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile

import gi
gi.require_version("Gtk","4.0")
gi.require_version("Adw","1")
from gi.repository import Gtk, Adw, GLib, Gdk
from router_gateway import RouterGatewayWindow

APP_ID="io.github.god13emad.DirectInternetMethod"
VERSION="1.5.2"
GLib.set_prgname("DirectInternetMethod")
GLib.set_application_name("Direct Internet Method")
try:
    ctypes.CDLL(None).prctl(15, b"DirectInternet", 0, 0, 0)
except Exception:
    pass

APP_HOME=pathlib.Path.home()/".local/share/DirectInternetMethod"
PRIV_HOME=pathlib.Path("/usr/lib/directinternetmethod")
STATE=APP_HOME/"directmethod/state.json"
PREFS=APP_HOME/"settings.json"
CUSTOM_HOSTS=APP_HOME/"custom-hosts.txt"
ADULT_ENABLED=APP_HOME/"adult-enabled.txt"
ADULT_HOSTS=APP_HOME/"adult-hosts.txt"
ADULT_META=APP_HOME/"adult-hosts.meta.json"
ADULT_CATALOG_URLS=(
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
)
STRATEGY_FILE=APP_HOME/"strategy.txt"
SCOPE_FILE=APP_HOME/"scope.txt"
LATEST_API="https://api.github.com/repos/GOD13emad/DirectInternetMethod/releases/latest"

def ui_test_log(message):
    p=os.environ.get("DIM_UI_TEST_LOG")
    if p:
        pathlib.Path(p).open("a",encoding="utf-8").write(message+"\n")

def load_adult_site_check():
    try:
        if ADULT_ENABLED.is_file():
            return ADULT_ENABLED.read_text(encoding="utf-8").strip()=="1"
        prefs=json.loads(PREFS.read_text(encoding="utf-8"))
        return bool(prefs.get("adultCoverageEnabled",prefs.get("adultSiteLiveCheck",False)))
    except Exception:
        return False

def save_adult_site_check(enabled):
    enabled=bool(enabled)
    PREFS.parent.mkdir(parents=True,exist_ok=True)
    temp=PREFS.with_suffix(".tmp")
    temp.write_text(json.dumps({"adultCoverageEnabled":enabled,"adultSiteLiveCheck":enabled},separators=(",",":"))+"\n",encoding="utf-8")
    os.replace(temp,PREFS)
    flag=ADULT_ENABLED.with_suffix(".tmp")
    flag.write_text("1\n" if enabled else "0\n",encoding="utf-8")
    os.replace(flag,ADULT_ENABLED)
    if not enabled:
        for path in (ADULT_HOSTS,ADULT_META):
            try:path.unlink()
            except FileNotFoundError:pass

def validate_adult_catalog(text):
    label=re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    vals=[];seen=set()
    for raw in str(text or "").splitlines():
        v=raw.strip().lower()
        if not v or v.startswith("#"):
            continue
        if v.startswith("^"):v=v[1:]
        if len(v)<3 or len(v)>253 or "." not in v or any(not label.fullmatch(x) for x in v.split(".")):
            continue
        if v not in seen:
            seen.add(v);vals.append(v)
        if len(vals)>100000:
            raise RuntimeError("Adult catalog exceeds 100,000 validated domains.")
    if len(vals)<10000:
        raise RuntimeError("Adult catalog is unexpectedly small.")
    for required in ("xvideos.com","xnxx.com","xhamster.com","pornhub.com","redtube.com"):
        if required not in seen:
            raise RuntimeError("Adult catalog is missing a required coverage family.")
    return vals

def sync_adult_catalog(force=False):
    if not force and ADULT_HOSTS.is_file() and (time.time()-ADULT_HOSTS.stat().st_mtime)<86400:
        vals=validate_adult_catalog(ADULT_HOSTS.read_text(encoding="utf-8"))
        return {"entries":len(vals),"sha256":hashlib.sha256(ADULT_HOSTS.read_bytes()).hexdigest().upper(),"cached":True}
    last_error=None
    for source_url in ADULT_CATALOG_URLS:
        try:
            req=urllib.request.Request(source_url,headers={"User-Agent":"DirectInternetMethod/1.5.2"})
            with urllib.request.urlopen(req,timeout=20) as resp:
                raw=resp.read(4*1024*1024+1)
            if len(raw)<100000 or len(raw)>4*1024*1024:
                raise RuntimeError("Adult catalog size is outside the accepted range.")
            text=raw.decode("utf-8")
            vals=validate_adult_catalog(text)
            ADULT_HOSTS.parent.mkdir(parents=True,exist_ok=True)
            temp=ADULT_HOSTS.with_suffix(".tmp")
            temp.write_text("\n".join(vals)+"\n",encoding="utf-8")
            os.replace(temp,ADULT_HOSTS)
            digest=hashlib.sha256(raw).hexdigest().upper()
            meta_tmp=ADULT_META.with_suffix(".tmp")
            meta_tmp.write_text(json.dumps({"schema":1,"source":source_url,"fetchedUtc":time.time(),"sourceSha256":digest,"entries":len(vals)},separators=(",",":"))+"\n",encoding="utf-8")
            os.replace(meta_tmp,ADULT_META)
            return {"entries":len(vals),"sha256":digest,"cached":False,"source":source_url}
        except Exception as exc:
            last_error=exc
    raise RuntimeError("Adult catalog sync failed from all official upstream endpoints.") from last_error

def normalize_custom_site(raw):
    value=str(raw or "").strip()
    if not value or value.startswith("#"):
        return None
    exact=value.startswith("^")
    if exact:
        value=value[1:].strip()
    try:
        parsed=urllib.parse.urlsplit(value if "://" in value else "https://"+value)
        host=(parsed.hostname or "").strip(".").lower()
    except Exception:
        return None
    if len(host)<3 or len(host)>253 or "." not in host:
        return None
    label=re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label.fullmatch(x) for x in host.split(".")):
        return None
    return "^"+host if exact else host

def save_custom_hosts_text(text):
    vals=[]
    for raw in str(text or "").splitlines():
        v=normalize_custom_site(raw)
        if v and v not in vals:
            vals.append(v)
        if len(vals)>=256:
            break
    CUSTOM_HOSTS.parent.mkdir(parents=True,exist_ok=True)
    temp=CUSTOM_HOSTS.with_suffix(".tmp")
    temp.write_text(("\n".join(vals)+"\n") if vals else "",encoding="utf-8")
    os.replace(temp,CUSTOM_HOSTS)
    return len(vals)

def probe_url(url,physical,allowed):
    try:
        p=subprocess.run(["curl","-4","--interface",physical,"--noproxy","*","-A",
                          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
                          "-sS","-o","/dev/null","--connect-timeout","5","--max-time","8",
                          "-w","%{http_code}|%{remote_ip}|%{time_total}",url],
                         text=True,capture_output=True,timeout=10)
        parts=p.stdout.strip().split("|")
        code=parts[0] if parts else ""
        reached=(p.returncode==0 and bool(code) and code!="000")
        return {"ok":reached and code in allowed,"reached":reached,"code":code,
                "remote":parts[1] if len(parts)>1 else "","meta":p.stdout.strip(),
                "exit":p.returncode,"error":p.stderr.strip()}
    except Exception as e:
        return {"ok":False,"reached":False,"code":"","remote":"","meta":"","exit":-1,"error":str(e)}

def format_probe(name,result):
    if result.get("ok"):
        return f"{name}: PASS · HTTP {result.get('code','')}"
    if result.get("reached"):
        return f"{name}: FAIL · HTTP {result.get('code','')}"
    return f"{name}: FAIL · transport"

def format_adult_probes(results):
    ok=sum(1 for r in results if r.get("ok"))
    return f"Adult coverage: {'PASS' if ok==len(results) else 'FAIL'} · full pages {ok}/{len(results)}"

def _systemd_unit_matches(unit_value, pid_value, expected_unit):
    try:
        unit=str(unit_value or "")
        pid=int(pid_value or 0)
        if unit != expected_unit or pid <= 0:
            return False
        p=subprocess.run(["systemctl","show",unit,"-p","MainPID","-p","ActiveState","--value"],
                         text=True,capture_output=True,timeout=2)
        if p.returncode != 0:
            return False
        vals=[x.strip() for x in p.stdout.splitlines() if x.strip()]
        return str(pid) in vals and "active" in vals
    except Exception:
        return False

def _top_default_iface():
    try:
        p=subprocess.run(["ip","-4","route","show","default"],text=True,capture_output=True,timeout=2)
        line=next((x for x in p.stdout.splitlines() if x.strip()),"")
        parts=line.split()
        return parts[parts.index("dev")+1] if "dev" in parts else ""
    except Exception:
        return ""

def _external_tunnel_active():
    iface=_top_default_iface()
    if iface.startswith(("tun","tap","wg","warp","tailscale","zt")):
        return True
    try:
        p=subprocess.run(["nmcli","-t","-f","TYPE,DEVICE","connection","show","--active"],
                         text=True,capture_output=True,timeout=2)
        for line in p.stdout.splitlines():
            parts=line.split(":",1)
            dev=parts[1] if len(parts)>1 else ""
            if dev.startswith(("tun","tap","wg","warp","tailscale","zt")):
                return True
    except Exception:
        pass
    return False

def load_state():
    try:
        s=json.loads(STATE.read_text(encoding="utf-8"))
    except Exception:
        if _external_tunnel_active():
            return {"mode":"BLOCKED","detail":"External VPN/tunnel owns the default route. Disconnect it before Start."}
        return {"mode":"OFF","detail":"No active Direct Internet Method state."}
    uid=os.getuid()
    ctrld_ok=_systemd_unit_matches(s.get("ctrldUnit"),s.get("ctrldPid"),f"directinternetmethod-ctrld-{uid}.service")
    nfqws_ok=_systemd_unit_matches(s.get("nfqwsUnit"),s.get("nfqwsPid"),f"directinternetmethod-nfqws-{uid}.service")
    if ctrld_ok and nfqws_ok:
        detail=f"Physical: {s.get('physicalInterface','?')}  DNS link: {s.get('dnsInterface','?')}  DNS: {s.get('dnsIp','?')}  Methods: DoH + HTTP + TLS/SNI + QUIC"
        if _external_tunnel_active():
            return {"mode":"CONFLICT","detail":detail+"  External VPN/tunnel is also active."}
        return {"mode":"ACTIVE","detail":detail}
    return {"mode":"STALE","detail":"Owned state exists but one or more owned processes are missing or mismatched. Use Recovery."}

def run_system_action(action):
    unit=f"directinternetmethod-{action}.service"
    try:
        p=subprocess.run(["systemctl","start",unit],text=True,capture_output=True,timeout=120)
        return {"ok":p.returncode==0,"exit":p.returncode,"stderr":p.stderr.strip(),"stdout":p.stdout.strip(),"unit":unit}
    except subprocess.TimeoutExpired:
        return {"ok":False,"error":"SYSTEM_ACTION_TIMEOUT","unit":unit}

def verify_live():
    try:
        s=json.loads(STATE.read_text(encoding="utf-8"))
        physical=str(s.get("physicalInterface") or "")
    except Exception:
        return {"ok":False,"error":"STATE_UNREADABLE_AFTER_START"}
    if not physical:
        return {"ok":False,"error":"PHYSICAL_INTERFACE_MISSING"}
    if _external_tunnel_active():
        return {"ok":False,"error":"EXTERNAL_TUNNEL_APPEARED_AFTER_START"}
    def curl(url):
        p=subprocess.run(["curl","-4","--interface",physical,"--noproxy","*","-A",
                          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
                          "-sS","-o","/dev/null","--connect-timeout","5","--max-time","12","-w","%{http_code}|%{remote_ip}|%{time_total}",url],
                         text=True,capture_output=True)
        return {"exit":p.returncode,"meta":p.stdout.strip(),"error":p.stderr.strip()}
    d=subprocess.run(["getent","ahostsv4","www.youtube.com"],text=True,capture_output=True)
    h=curl("http://www.youtube.com/")
    y=curl("https://www.youtube.com/generate_204")
    o=curl("https://api.openai.com/v1/models")
    g=curl("https://github.com/")
    m=curl("https://gemini.google.com/")
    ok=(not _external_tunnel_active() and d.returncode==0
        and h["exit"]==0 and h["meta"].startswith(("200|","301|","302|","303|","307|","308|"))
        and y["exit"]==0 and y["meta"].startswith(("200|","204|"))
        and o["exit"]==0 and o["meta"].startswith(("401|","403|"))
        and g["exit"]==0 and g["meta"].startswith(("200|")))
    return {"ok":ok,"physicalInterface":physical,"directMethods":["encrypted-dns-doh","http-host-split-tcp80","tls-sni-desync-tcp443","quic-desync-udp443"],"youtubeHttp80":h,"youtube":y,"openai":o,"github":g,"gemini":m}

def _version_tuple(text):
    s=text.strip().lstrip("vV")
    try:
        return tuple(int(x) for x in s.split(".")[:3])
    except Exception:
        return (0,0,0)

def check_update_sync():
    req=urllib.request.Request(LATEST_API,headers={"User-Agent":f"DirectInternetMethod/{VERSION}","Accept":"application/vnd.github+json"})
    with urllib.request.urlopen(req,timeout=12) as resp:
        data=json.load(resp)
    tag=str(data.get("tag_name") or "")
    if _version_tuple(tag) <= _version_tuple(VERSION):
        return None
    release_version=tag.lstrip("vV")
    expected_linux=f"DirectInternetMethod_{release_version}_Linux_x86_64.zip"
    linux_assets=[]
    sums_assets=[]
    for a in data.get("assets") or []:
        name=str(a.get("name") or "")
        url=str(a.get("browser_download_url") or "")
        digest=str(a.get("digest") or "")
        item={"name":name,"url":url,"digest":digest}
        if name==expected_linux:
            linux_assets.append(item)
        elif name=="SHA256SUMS.txt":
            sums_assets.append(item)
    if len(linux_assets)!=1 or len(sums_assets)!=1:
        raise RuntimeError("Latest release must contain exactly one expected Linux ZIP and one SHA256SUMS.txt.")
    linux_asset=linux_assets[0]; sums_asset=sums_assets[0]
    for item in (linux_asset,sums_asset):
        if not re.fullmatch(r"sha256:[0-9A-Fa-f]{64}",item["digest"]):
            raise RuntimeError(f"GitHub release asset digest is missing/invalid for {item['name']}.")
    return {"tag":tag,"version":release_version,"asset":linux_asset,"sums":sums_asset}

def _download(url,path):
    req=urllib.request.Request(url,headers={"User-Agent":f"DirectInternetMethod/{VERSION}"})
    with urllib.request.urlopen(req,timeout=30) as src, open(path,"wb") as dst:
        shutil.copyfileobj(src,dst)

def download_and_install_update(info):
    cache=pathlib.Path.home()/".cache/DirectInternetMethod/updates"
    cache.mkdir(parents=True,exist_ok=True)
    sums_path=cache/"SHA256SUMS.txt"
    zip_path=cache/info["asset"]["name"]
    _download(info["sums"]["url"],sums_path)
    sums_actual=hashlib.sha256(sums_path.read_bytes()).hexdigest().upper()
    sums_api=str(info["sums"]["digest"]).split(":",1)[1].upper()
    if sums_actual!=sums_api:
        sums_path.unlink(missing_ok=True)
        raise RuntimeError("Downloaded SHA256SUMS.txt does not match GitHub asset digest.")
    matches=[]
    for raw in sums_path.read_text(encoding="utf-8").splitlines():
        parts=raw.strip().split()
        if len(parts)>=2 and parts[-1].lstrip("*")==info["asset"]["name"]:
            matches.append(parts[0].upper())
    if len(matches)!=1 or not re.fullmatch(r"[0-9A-F]{64}",matches[0]):
        raise RuntimeError("SHA256SUMS.txt must contain exactly one valid checksum for the Linux update.")
    expected=matches[0]
    api_expected=str(info["asset"]["digest"]).split(":",1)[1].upper()
    if expected!=api_expected:
        raise RuntimeError("Linux update checksum disagrees with GitHub asset digest.")
    _download(info["asset"]["url"],zip_path)
    actual=hashlib.sha256(zip_path.read_bytes()).hexdigest().upper()
    if actual!=expected or actual!=api_expected:
        zip_path.unlink(missing_ok=True)
        raise RuntimeError("Downloaded Linux update failed three-way SHA-256 verification.")

    temp=pathlib.Path(tempfile.mkdtemp(prefix="dim-update-",dir=str(cache)))
    with zipfile.ZipFile(zip_path) as z:
        base=temp.resolve()
        for member in z.infolist():
            target=(temp/member.filename).resolve()
            if base not in target.parents and target!=base:
                raise RuntimeError("Unsafe update archive path.")
        z.extractall(temp)
    installers=list(temp.rglob("install.sh"))
    if len(installers)!=1:
        raise RuntimeError("Update archive does not contain exactly one installer.")
    p=subprocess.run(["bash",str(installers[0])],text=True,capture_output=True,timeout=180)
    if p.returncode!=0:
        raise RuntimeError((p.stderr or p.stdout or f"installer exit {p.returncode}").strip())
    return p.stdout.strip()

class Window(Adw.ApplicationWindow):
    def __init__(self,app):
        super().__init__(application=app,title="Direct Internet Method")
        self.set_default_size(900,590)
        self.set_size_request(780,540)
        self.set_resizable(True)
        self.available_update=None
        self.adult_check_enabled=load_adult_site_check()
        if self.adult_check_enabled:
            try: save_adult_site_check(True)
            except Exception: pass
        self.live_check_generation=0

        header=Adw.HeaderBar()
        title_widget=Gtk.Label(label="Direct Internet Method")
        title_widget.add_css_class("heading")
        header.set_title_widget(title_widget)
        header.set_show_start_title_buttons(False)
        header.set_show_end_title_buttons(False)
        btn_min=Gtk.Button.new_from_icon_name("window-minimize-symbolic")
        btn_min.set_tooltip_text("Minimize")
        btn_min.connect("clicked",lambda *_: self.minimize())
        btn_max=Gtk.Button.new_from_icon_name("window-maximize-symbolic")
        btn_max.set_tooltip_text("Maximize / Restore")
        btn_max.connect("clicked",self.toggle_maximize)
        btn_close=Gtk.Button.new_from_icon_name("window-close-symbolic")
        btn_close.set_tooltip_text("Close")
        btn_close.connect("clicked",lambda *_: self.close())
        header.pack_end(btn_close);header.pack_end(btn_max);header.pack_end(btn_min)
        handle=Gtk.WindowHandle();handle.set_child(header)
        toolbar=Adw.ToolbarView();toolbar.add_top_bar(handle)

        box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=14)
        box.set_margin_top(18);box.set_margin_bottom(22);box.set_margin_start(24);box.set_margin_end(24)
        toolbar.set_content(box);self.set_content(toolbar)

        hero=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=16)
        pic=Gtk.Picture.new_for_filename(str(APP_HOME/"direct-internet-method.svg"))
        pic.set_size_request(92,92);pic.set_can_shrink(True);hero.append(pic)
        htxt=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=3)
        title=Gtk.Label(label="Direct Internet Method",xalign=0);title.add_css_class("title-1");htxt.append(title)
        slogan=Gtk.Label(label="زن زندگی آزادی",xalign=0);slogan.add_css_class("title-2");htxt.append(slogan)
        sub=Gtk.Label(label="Encrypted DNS (DoH) + HTTP/TLS/QUIC DPI bypass without VPN, proxy or default-route tunnel",xalign=0)
        sub.add_css_class("dim-label");htxt.append(sub)
        hero.append(htxt);box.append(hero)

        card=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=8)
        card.add_css_class("card");card.set_margin_top(10);card.set_margin_bottom(6)
        self.status=Gtk.Label(xalign=0);self.status.add_css_class("title-3")
        self.detail=Gtk.Label(xalign=0,wrap=True);self.detail.add_css_class("dim-label")
        card.append(self.status);card.append(self.detail);box.append(card)

        live=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=6);live.add_css_class("card")
        live_header=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=10)
        live_title=Gtk.Label(label="Live checks",xalign=0);live_title.add_css_class("heading");live_title.set_hexpand(True)
        live_header.append(live_title)
        adult_toggle_label=Gtk.Label(label="Adult coverage",xalign=1);adult_toggle_label.add_css_class("dim-label");live_header.append(adult_toggle_label)
        self.adult_switch=Gtk.Switch(active=self.adult_check_enabled);live_header.append(self.adult_switch)
        self.adult_switch.connect("notify::active",self.on_adult_toggle)
        live.append(live_header)
        self.gemini_live=Gtk.Label(label="Gemini: —",xalign=0);self.gemini_live.add_css_class("dim-label");live.append(self.gemini_live)
        self.adult_live=Gtk.Label(label="Adult coverage: "+("Checking…" if self.adult_check_enabled else "Disabled"),xalign=0);self.adult_live.add_css_class("dim-label");live.append(self.adult_live)
        box.append(live)

        buttons=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=8);buttons.set_homogeneous(True)
        self.buttons={}
        for text_,action,css in [
            ("Start","start","suggested-action"),("Stop","stop",None),("Refresh","refresh",None),
            ("Recovery","recovery","destructive-action"),("Router Gateway","router",None),("Custom Sites","custom",None),("Strategy","strategy",None),("Update","update",None)]:
            b=Gtk.Button(label=text_);b.set_size_request(120,48)
            if css:b.add_css_class(css)
            b.connect("clicked",self.on_action,action);buttons.append(b);self.buttons[action]=b
        box.append(buttons)

        self.result=Gtk.Label(xalign=0,wrap=True);self.result.add_css_class("dim-label");box.append(self.result)
        note=Gtk.Label(label="Normal Start / Stop / Recovery require no admin prompt. Install/update may authenticate once. No FreeNetHub or ChatGPT dependency.",xalign=0,wrap=True)
        note.add_css_class("dim-label");box.append(note)

        keys=Gtk.EventControllerKey();keys.connect("key-pressed",self.on_key);self.add_controller(keys)
        self.refresh()
        if self.adult_check_enabled:
            threading.Thread(target=self.adult_sync_worker,args=(False,),daemon=True).start()
        threading.Thread(target=self.update_check_worker,args=(False,),daemon=True).start()

    def toggle_maximize(self,*_args):
        if self.is_maximized():
            self.unmaximize()
        else:
            self.maximize()

    def refresh(self):
        s=load_state();mode=s["mode"]
        self.status.set_text("Status: "+mode);self.detail.set_text(s["detail"])
        for css in ("success","warning","error","dim-label"):
            self.status.remove_css_class(css)
        self.status.add_css_class("success" if mode=="ACTIVE" else "warning" if mode in ("BLOCKED","CONFLICT") else "error" if mode=="STALE" else "dim-label")
        start_ok=(mode=="OFF")
        stop_ok=(mode in ("ACTIVE","CONFLICT","STALE"))
        recovery_ok=(mode in ("CONFLICT","STALE"))
        self.buttons["start"].set_sensitive(start_ok)
        self.buttons["stop"].set_sensitive(stop_ok)
        self.buttons["recovery"].set_sensitive(recovery_ok)
        self.buttons["refresh"].set_sensitive(True)
        self.buttons["update"].set_sensitive(True)
        self.buttons["start"].remove_css_class("suggested-action")
        self.buttons["recovery"].remove_css_class("destructive-action")
        if start_ok:self.buttons["start"].add_css_class("suggested-action")
        if recovery_ok:self.buttons["recovery"].add_css_class("destructive-action")
        self.live_check_generation+=1
        generation=self.live_check_generation
        if mode=="ACTIVE":
            self.gemini_live.set_text("Gemini: Checking…")
            self.adult_live.set_text("Adult coverage: Checking…" if self.adult_check_enabled else "Adult coverage: Disabled")
            threading.Thread(target=self.live_checks_worker,args=(generation,),daemon=True).start()
        else:
            self.gemini_live.set_text("Gemini: Available when Direct Method is active")
            self.adult_live.set_text("Adult coverage: Disabled" if not self.adult_check_enabled else "Adult coverage: Available when Direct Method is active")

    def live_checks_worker(self,generation):
        try:
            state=json.loads(STATE.read_text(encoding="utf-8"))
            physical=str(state.get("physicalInterface") or "")
        except Exception:
            physical=""
        if not physical:
            GLib.idle_add(self.finish_live_checks,generation,{"ok":False,"reached":False},[{"ok":False,"reached":False}] if self.adult_check_enabled else None)
            return
        gemini=probe_url("https://gemini.google.com/",physical,{"200","301","302","303","307","308"})
        adult=None
        if self.adult_check_enabled:
            allowed={"200","301","302","303","307","308"}
            adult=[
                probe_url("https://www.pornhub.com/",physical,allowed),
                probe_url("https://www.xvideos.com/",physical,allowed),
                probe_url("https://www.xnxx.com/",physical,allowed),
                probe_url("https://xhamster.com/",physical,allowed),
            ]
        GLib.idle_add(self.finish_live_checks,generation,gemini,adult)

    def finish_live_checks(self,generation,gemini,adult):
        if generation!=self.live_check_generation:
            return False
        self.gemini_live.set_text(format_probe("Gemini",gemini))
        self.adult_live.set_text(format_adult_probes(adult) if adult is not None else "Adult coverage: Disabled")
        return False

    def adult_sync_worker(self,force):
        try:
            info=sync_adult_catalog(force)
            GLib.idle_add(self.finish_adult_sync,True,f"Adult coverage: {info['entries']:,} domains synced · Stop/Start to apply")
        except Exception as e:
            GLib.idle_add(self.finish_adult_sync,False,"Adult coverage: fallback active · catalog sync failed · "+str(e))

    def finish_adult_sync(self,ok,message):
        self.adult_live.set_text(message)
        return False

    def on_adult_toggle(self,switch,_pspec):
        self.adult_check_enabled=bool(switch.get_active())
        try:
            save_adult_site_check(self.adult_check_enabled)
        except Exception as e:
            self.adult_live.set_text("Adult coverage: settings error · "+str(e))
            return
        if self.adult_check_enabled:
            self.adult_live.set_text("Adult coverage: syncing catalog…")
            threading.Thread(target=self.adult_sync_worker,args=(True,),daemon=True).start()
        else:
            self.refresh()

    def on_key(self,_controller,keyval,_keycode,state):
        if keyval==Gdk.KEY_F5 or (keyval in (Gdk.KEY_r,Gdk.KEY_R) and bool(state & Gdk.ModifierType.CONTROL_MASK)):
            self.on_action(None,"refresh");return True
        if keyval==Gdk.KEY_Escape:
            self.close();return True
        return False

    def open_custom_sites(self):
        w=Gtk.Window(title="Custom Sites",transient_for=self,modal=True)
        w.set_default_size(570,470)
        outer=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=10)
        outer.set_margin_top(16);outer.set_margin_bottom(16);outer.set_margin_start(16);outer.set_margin_end(16)
        note=Gtk.Label(label="One site or URL per line. Saved domains and subdomains use the existing Direct Method on the next Start. Prefix ^ for exact-host only. Maximum 256 entries.",xalign=0,wrap=True)
        note.add_css_class("dim-label");outer.append(note)
        scroll=Gtk.ScrolledWindow();scroll.set_vexpand(True)
        view=Gtk.TextView();view.set_monospace(True);view.set_wrap_mode(Gtk.WrapMode.NONE)
        try:
            view.get_buffer().set_text(CUSTOM_HOSTS.read_text(encoding="utf-8") if CUSTOM_HOSTS.exists() else "")
        except Exception:
            view.get_buffer().set_text("")
        scroll.set_child(view);outer.append(scroll)
        row=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=8);row.set_halign(Gtk.Align.END)
        cancel=Gtk.Button(label="Cancel");save=Gtk.Button(label="Save");save.add_css_class("suggested-action")
        row.append(cancel);row.append(save);outer.append(row)
        cancel.connect("clicked",lambda *_:w.close())
        def do_save(*_):
            try:
                buf=view.get_buffer()
                count=save_custom_hosts_text(buf.get_text(buf.get_start_iter(),buf.get_end_iter(),True))
                self.result.set_text(f"Custom sites saved: {count}. Stop/Start to apply.")
                w.close()
            except Exception as e:
                self.result.set_text("Custom sites save failed: "+str(e))
        save.connect("clicked",do_save)
        w.set_child(outer);w.present()

    def open_strategy(self):
        current="balanced"
        all_sites=False
        try:
            raw=STRATEGY_FILE.read_text(encoding="utf-8").strip().lower()
            if raw in {"balanced","compatibility","strong"}:
                current=raw
        except Exception:
            pass
        try:
            all_sites=SCOPE_FILE.read_text(encoding="utf-8").strip().lower()=="all-sites"
        except Exception:
            pass
        w=Gtk.Window(title="Direct Strategy",transient_for=self,modal=True)
        w.set_default_size(540,390)
        outer=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=12)
        outer.set_margin_top(18);outer.set_margin_bottom(18);outer.set_margin_start(18);outer.set_margin_end(18)
        note=Gtk.Label(label="Balanced is the default. Compatibility uses split-only TCP handling. Strong is more aggressive and should be used only when Balanced still fails.",xalign=0,wrap=True)
        outer.append(note)
        values=["Balanced","Compatibility","Strong"]
        combo=Gtk.DropDown.new_from_strings(values)
        combo.set_selected({"balanced":0,"compatibility":1,"strong":2}.get(current,0))
        outer.append(combo)
        scope_toggle=Gtk.CheckButton(label="Apply DPI strategy to all web sites (experimental)")
        scope_toggle.set_active(all_sites);outer.append(scope_toggle)
        hint=Gtk.Label(label="Targeted mode affects only built-in and Custom Sites. All Sites mode can help unknown blocked domains, but may reduce compatibility or speed on some sites. Neither mode creates a VPN, proxy, or default-route tunnel.",xalign=0,wrap=True)
        hint.add_css_class("dim-label");outer.append(hint)
        row=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=8);row.set_halign(Gtk.Align.END)
        cancel=Gtk.Button(label="Cancel");save=Gtk.Button(label="Save");save.add_css_class("suggested-action")
        row.append(cancel);row.append(save);outer.append(row)
        cancel.connect("clicked",lambda *_:w.close())
        def do_save(*_):
            try:
                value=("balanced","compatibility","strong")[int(combo.get_selected())]
                STRATEGY_FILE.parent.mkdir(parents=True,exist_ok=True)
                temp=STRATEGY_FILE.with_suffix(".tmp")
                temp.write_text(value+"\n",encoding="utf-8")
                os.replace(temp,STRATEGY_FILE)
                scope_value="all-sites" if scope_toggle.get_active() else "targeted"
                st=SCOPE_FILE.with_suffix(".tmp")
                st.write_text(scope_value+"\n",encoding="utf-8")
                os.replace(st,SCOPE_FILE)
                self.result.set_text(f"Strategy saved: {value}; scope: {scope_value}. Stop/Start to apply.")
                w.close()
            except Exception as e:
                self.result.set_text("Strategy save failed: "+str(e))
        save.connect("clicked",do_save)
        w.set_child(outer);w.present()

    def on_action(self,_button,action):
        ui_test_log("ACTION:"+action)
        if action=="refresh":
            self.refresh();self.result.set_text("");return
        if action=="router":
            RouterGatewayWindow(self).present();return
        if action=="custom":
            self.open_custom_sites();return
        if action=="strategy":
            self.open_strategy();return
        if action=="update":
            if self.available_update:
                self.set_sensitive(False);self.result.set_text("Downloading and verifying update…")
                threading.Thread(target=self.update_install_worker,daemon=True).start()
            else:
                self.result.set_text("Checking for updates…")
                threading.Thread(target=self.update_check_worker,args=(True,),daemon=True).start()
            return
        self.set_sensitive(False);self.result.set_text("Working…")
        threading.Thread(target=self.worker,args=(action,),daemon=True).start()

    def worker(self,action):
        r=run_system_action(action)
        if action=="start" and r.get("ok"):
            v=verify_live()
            if not v.get("ok"):
                run_system_action("stop")
                r={"ok":False,"error":"LIVE_VERIFY_FAILED_ROLLED_BACK","verify":v}
            else:
                r["verify"]=v
        GLib.idle_add(self.finish,r)

    def finish(self,r):
        self.set_sensitive(True);self.refresh()
        if r.get("ok"):
            if "verify" in r:
                v=r["verify"]
                gemini_code=v.get("gemini",{}).get("meta","").split("|")[0] if v.get("gemini") else ""
                gemini_state=("PASS" if gemini_code in ("200","301","302","303","307","308") else "REACHABLE "+gemini_code if gemini_code and gemini_code!="000" else "FAIL")
                self.result.set_text("PASS — YouTube %s · OpenAI %s · GitHub %s · Gemini %s" % (
                    v["youtube"]["meta"].split("|")[0],v["openai"]["meta"].split("|")[0],v["github"]["meta"].split("|")[0],gemini_state))
            else:self.result.set_text("Completed.")
        else:self.result.set_text("Failed: "+str(r.get("error") or r.get("stderr") or r))
        return False

    def update_check_worker(self,user_initiated):
        try:
            info=check_update_sync()
            GLib.idle_add(self.finish_update_check,info,user_initiated,None)
        except Exception as e:
            GLib.idle_add(self.finish_update_check,None,user_initiated,str(e))

    def finish_update_check(self,info,user_initiated,error):
        self.available_update=info
        if error:
            self.buttons["update"].set_label("Check Update")
            if user_initiated:self.result.set_text("Update check failed: "+error)
        elif info:
            self.buttons["update"].set_label("Update v"+info["version"])
            if user_initiated:self.result.set_text("Verified release metadata found. Click Update again to install.")
        else:
            self.buttons["update"].set_label("Up to date")
            if user_initiated:self.result.set_text("No newer release is available.")
        return False

    def update_install_worker(self):
        try:
            out=download_and_install_update(self.available_update)
            GLib.idle_add(self.finish_update_install,True,out)
        except Exception as e:
            GLib.idle_add(self.finish_update_install,False,str(e))

    def finish_update_install(self,ok,message):
        self.set_sensitive(True);self.refresh()
        self.result.set_text(("Update installed. Restart the app. " if ok else "Update failed: ")+message)
        return False

class App(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)
        Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    def do_activate(self):
        w=self.props.active_window or Window(self);w.present()

if __name__=="__main__":
    App().run(None)
