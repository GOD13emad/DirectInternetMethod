#!/usr/bin/env python3
from __future__ import annotations
import json, os, pathlib, subprocess, threading
import gi
gi.require_version("Gtk","4.0")
gi.require_version("Adw","1")
from gi.repository import Gtk, Adw, GLib

APP_ID="io.github.god13emad.DirectInternetMethod"
APP_HOME=pathlib.Path.home()/".local/share/DirectInternetMethod"
HELPER=APP_HOME/"direct_method_helper.sh"
STATE=APP_HOME/"directmethod/state.json"

def load_state():
    try:
        s=json.loads(STATE.read_text(encoding="utf-8"))
    except Exception:
        return {"mode":"OFF","detail":"No active Direct Internet Method state."}
    alive=[]
    for k in ("ctrldPid","nfqwsPid"):
        try:
            pid=int(s.get(k) or 0)
            alive.append(pid>0 and pathlib.Path(f"/proc/{pid}").exists())
        except Exception:
            alive.append(False)
    if all(alive):
        return {"mode":"ACTIVE","detail":f"Physical: {s.get('physicalInterface','?')}  DNS link: {s.get('dnsInterface','?')}  DNS: {s.get('dnsIp','?')}"}
    return {"mode":"STALE","detail":"Owned state exists but one or more processes are not running. Use Recovery."}

def run_helper(action):
    if not HELPER.is_file():
        return {"ok":False,"error":"HELPER_MISSING"}
    try:
        p=subprocess.run(["pkexec","/bin/bash",str(HELPER),action,str(APP_HOME),str(os.getuid()),str(os.getgid())],
                         text=True,capture_output=True,timeout=90)
        lines=[x for x in (p.stdout or "").splitlines() if x.strip()]
        try:r=json.loads(lines[-1]) if lines else {}
        except Exception:r={}
        r.setdefault("ok",p.returncode==0)
        r["exit"]=p.returncode
        if p.stderr.strip(): r["stderr"]=p.stderr.strip()
        return r
    except subprocess.TimeoutExpired:
        return {"ok":False,"error":"PRIVILEGED_ACTION_TIMEOUT"}

def verify_live():
    def curl(url):
        p=subprocess.run(["curl","-4","-sS","-o","/dev/null","--max-time","12","-w","%{http_code}|%{remote_ip}|%{time_total}",url],
                         text=True,capture_output=True)
        return {"exit":p.returncode,"meta":p.stdout.strip(),"error":p.stderr.strip()}
    d=subprocess.run(["getent","ahostsv4","www.youtube.com"],text=True,capture_output=True)
    y=curl("https://www.youtube.com/generate_204")
    o=curl("https://api.openai.com/v1/models")
    g=curl("https://github.com/")
    ok=(d.returncode==0 and y["exit"]==0 and y["meta"].startswith(("200|","204|"))
        and o["exit"]==0 and o["meta"].startswith(("401|","403|"))
        and g["exit"]==0 and g["meta"].startswith("200|"))
    return {"ok":ok,"youtube":y,"openai":o,"github":g}

class Window(Adw.ApplicationWindow):
    def __init__(self,app):
        super().__init__(application=app,title="Direct Internet Method")
        self.set_default_size(680,430)
        self.set_resizable(True)
        header=Adw.HeaderBar()
        header.set_show_title(True)
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
        toolbar=Adw.ToolbarView()
        toolbar.add_top_bar(header)
        box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=14)
        box.set_margin_top(18);box.set_margin_bottom(22);box.set_margin_start(24);box.set_margin_end(24)
        toolbar.set_content(box)
        self.set_content(toolbar)
        hero=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=16)
        pic=Gtk.Picture.new_for_filename(str(APP_HOME/"direct-internet-method.svg"))
        pic.set_size_request(92,92);pic.set_can_shrink(True)
        hero.append(pic)
        htxt=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=3)
        title=Gtk.Label(label="Direct Internet Method",xalign=0);title.add_css_class("title-1");htxt.append(title)
        slogan=Gtk.Label(label="زن زندگی آزادی",xalign=0);slogan.add_css_class("title-2");htxt.append(slogan)
        sub=Gtk.Label(label="Direct DNS + DPI bypass without VPN, proxy or default-route tunnel",xalign=0)
        sub.add_css_class("dim-label");htxt.append(sub)
        hero.append(htxt);box.append(hero)
        card=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=8)
        card.add_css_class("card");card.set_margin_top(10);card.set_margin_bottom(6)
        card.set_margin_start(0);card.set_margin_end(0)
        self.status=Gtk.Label(xalign=0);self.status.add_css_class("title-3")
        self.detail=Gtk.Label(xalign=0,wrap=True);self.detail.add_css_class("dim-label")
        card.append(self.status);card.append(self.detail);box.append(card)
        buttons=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=8);buttons.set_homogeneous(True)
        for text_,action,css in [("Start","start","suggested-action"),("Stop","stop",None),("Refresh","refresh",None),("Recovery","recovery","destructive-action")]:
            b=Gtk.Button(label=text_);b.set_size_request(120,48)
            if css:b.add_css_class(css)
            b.connect("clicked",self.on_action,action);buttons.append(b)
        box.append(buttons)
        self.result=Gtk.Label(xalign=0,wrap=True);self.result.add_css_class("dim-label");box.append(self.result)
        note=Gtk.Label(label="Administrative changes use the normal Linux authentication prompt. No FreeNetHub or ChatGPT dependency.",xalign=0,wrap=True)
        note.add_css_class("dim-label");box.append(note)
        self.refresh()

    def toggle_maximize(self,*_args):
        if self.is_maximized(): self.unmaximize()
        else: self.maximize()

    def refresh(self):
        s=load_state();self.status.set_text("Status: "+s["mode"]);self.detail.set_text(s["detail"])

    def on_action(self,_button,action):
        if action=="refresh":
            self.refresh();self.result.set_text("");return
        self.set_sensitive(False);self.result.set_text("Working…")
        threading.Thread(target=self.worker,args=(action,),daemon=True).start()

    def worker(self,action):
        actual="stop" if action=="recovery" else action
        r=run_helper(actual)
        if actual=="start" and r.get("ok"):
            v=verify_live()
            if not v.get("ok"):
                run_helper("stop")
                r={"ok":False,"error":"LIVE_VERIFY_FAILED_ROLLED_BACK","verify":v}
            else:
                r["verify"]=v
        GLib.idle_add(self.finish,r)

    def finish(self,r):
        self.set_sensitive(True);self.refresh()
        if r.get("ok"):
            if "verify" in r:
                v=r["verify"]
                self.result.set_text("PASS — YouTube %s · OpenAI %s · GitHub %s" % (v["youtube"]["meta"].split("|")[0],v["openai"]["meta"].split("|")[0],v["github"]["meta"].split("|")[0]))
            else:self.result.set_text("Completed.")
        else:
            self.result.set_text("Failed: "+str(r.get("error") or r.get("stderr") or r))
        return False

class App(Adw.Application):
    def __init__(self):super().__init__(application_id=APP_ID)
    def do_activate(self):
        w=self.props.active_window or Window(self);w.present()

if __name__=="__main__":
    App().run(None)
