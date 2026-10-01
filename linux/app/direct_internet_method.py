#!/usr/bin/env python3
from __future__ import annotations
import ctypes
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import urllib.request
import zipfile

import gi
gi.require_version("Gtk","4.0")
gi.require_version("Adw","1")
from gi.repository import Gtk, Adw, GLib, Gdk
from router_gateway import RouterGatewayWindow

APP_ID="io.github.god13emad.DirectInternetMethod"
VERSION="1.3.1"
GLib.set_prgname("DirectInternetMethod")
GLib.set_application_name("Direct Internet Method")
try:
    ctypes.CDLL(None).prctl(15, b"DirectInternet", 0, 0, 0)
except Exception:
    pass

APP_HOME=pathlib.Path.home()/".local/share/DirectInternetMethod"
PRIV_HOME=pathlib.Path("/usr/lib/directinternetmethod")
STATE=APP_HOME/"directmethod/state.json"
LATEST_API="https://api.github.com/repos/GOD13emad/DirectInternetMethod/releases/latest"

def ui_test_log(message):
    p=os.environ.get("DIM_UI_TEST_LOG")
    if p:
        pathlib.Path(p).open("a",encoding="utf-8").write(message+"\n")

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
        detail=f"Physical: {s.get('physicalInterface','?')}  DNS link: {s.get('dnsInterface','?')}  DNS: {s.get('dnsIp','?')}"
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
        p=subprocess.run(["curl","-4","--interface",physical,"--noproxy","*","-sS","-o","/dev/null","--max-time","12","-w","%{http_code}|%{remote_ip}|%{time_total}",url],
                         text=True,capture_output=True)
        return {"exit":p.returncode,"meta":p.stdout.strip(),"error":p.stderr.strip()}
    d=subprocess.run(["getent","ahostsv4","www.youtube.com"],text=True,capture_output=True)
    y=curl("https://www.youtube.com/generate_204")
    o=curl("https://api.openai.com/v1/models")
    g=curl("https://github.com/")
    ok=(not _external_tunnel_active() and d.returncode==0 and y["exit"]==0 and y["meta"].startswith(("200|","204|"))
        and o["exit"]==0 and o["meta"].startswith(("401|","403|"))
        and g["exit"]==0 and g["meta"].startswith(("200|")))
    return {"ok":ok,"physicalInterface":physical,"youtube":y,"openai":o,"github":g}

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
    linux_asset=None
    sums_asset=None
    for a in data.get("assets") or []:
        name=str(a.get("name") or "")
        url=str(a.get("browser_download_url") or "")
        if name.endswith("_Linux_x86_64.zip"):
            linux_asset={"name":name,"url":url}
        elif name=="SHA256SUMS.txt":
            sums_asset={"name":name,"url":url}
    if not linux_asset or not sums_asset:
        raise RuntimeError("Latest release is missing Linux ZIP or SHA256SUMS.txt.")
    return {"tag":tag,"version":tag.lstrip("vV"),"asset":linux_asset,"sums":sums_asset}

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
    expected=None
    for raw in sums_path.read_text(encoding="utf-8").splitlines():
        parts=raw.strip().split()
        if len(parts)>=2 and parts[-1].lstrip("*")==info["asset"]["name"]:
            expected=parts[0].upper()
            break
    if not expected or len(expected)!=64:
        raise RuntimeError("No checksum found for Linux update.")
    _download(info["asset"]["url"],zip_path)
    actual=hashlib.sha256(zip_path.read_bytes()).hexdigest().upper()
    if actual!=expected:
        zip_path.unlink(missing_ok=True)
        raise RuntimeError("Downloaded Linux update failed SHA-256 verification.")

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
        self.set_default_size(860,510)
        self.set_size_request(760,460)
        self.set_resizable(True)
        self.available_update=None

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
        sub=Gtk.Label(label="Direct DNS + DPI bypass without VPN, proxy or default-route tunnel",xalign=0)
        sub.add_css_class("dim-label");htxt.append(sub)
        hero.append(htxt);box.append(hero)

        card=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=8)
        card.add_css_class("card");card.set_margin_top(10);card.set_margin_bottom(6)
        self.status=Gtk.Label(xalign=0);self.status.add_css_class("title-3")
        self.detail=Gtk.Label(xalign=0,wrap=True);self.detail.add_css_class("dim-label")
        card.append(self.status);card.append(self.detail);box.append(card)

        buttons=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=8);buttons.set_homogeneous(True)
        self.buttons={}
        for text_,action,css in [
            ("Start","start","suggested-action"),("Stop","stop",None),("Refresh","refresh",None),
            ("Recovery","recovery","destructive-action"),("Router Gateway","router",None),("Update","update",None)]:
            b=Gtk.Button(label=text_);b.set_size_request(120,48)
            if css:b.add_css_class(css)
            b.connect("clicked",self.on_action,action);buttons.append(b);self.buttons[action]=b
        box.append(buttons)

        self.result=Gtk.Label(xalign=0,wrap=True);self.result.add_css_class("dim-label");box.append(self.result)
        note=Gtk.Label(label="Normal Start / Stop / Recovery require no admin prompt. Install/update may authenticate once. No FreeNetHub or ChatGPT dependency.",xalign=0,wrap=True)
        note.add_css_class("dim-label");box.append(note)

        keys=Gtk.EventControllerKey();keys.connect("key-pressed",self.on_key);self.add_controller(keys)
        self.refresh()
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

    def on_key(self,_controller,keyval,_keycode,state):
        if keyval==Gdk.KEY_F5 or (keyval in (Gdk.KEY_r,Gdk.KEY_R) and bool(state & Gdk.ModifierType.CONTROL_MASK)):
            self.on_action(None,"refresh");return True
        if keyval==Gdk.KEY_Escape:
            self.close();return True
        return False

    def on_action(self,_button,action):
        ui_test_log("ACTION:"+action)
        if action=="refresh":
            self.refresh();self.result.set_text("");return
        if action=="router":
            RouterGatewayWindow(self).present();return
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
                self.result.set_text("PASS — YouTube %s · OpenAI %s · GitHub %s" % (
                    v["youtube"]["meta"].split("|")[0],v["openai"]["meta"].split("|")[0],v["github"]["meta"].split("|")[0]))
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
