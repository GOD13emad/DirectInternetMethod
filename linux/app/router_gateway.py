#!/usr/bin/env python3
from __future__ import annotations
import ipaddress, json, pathlib, re, socket, threading, urllib.request
import gi
gi.require_version("Gtk","4.0")
gi.require_version("Adw","1")
from gi.repository import Gtk, Adw, GLib, Gdk

APP_HOME=pathlib.Path.home()/".local/share/DirectInternetMethod"
DATA_PATH=APP_HOME/"router_gateway/providers.json"
RAW_URL="https://raw.githubusercontent.com/GOD13emad/DirectInternetMethod/main/router_gateway/providers.json"
VPNBOOK_URL="https://www.vpnbook.com/freevpn/pptp-vpn"

def _load():
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))

def _server(p):
    return p.get("ip") or p.get("host") or ""

def _guide(data,guide_id,protocol):
    g=next((x for x in data.get("routerGuides",[]) if x.get("id")==guide_id),None) or {}
    return g.get("l2tp" if str(protocol).startswith("L2TP") else "pptp","")

def _config(data,p,guide_id):
    protocol=str(p.get("protocol",""))
    lines=[
      "Direct Internet Method — Router Gateway",
      f"Provider: {p.get('provider','')}",
      f"Protocol: {protocol}",
      f"Country: {p.get('country','')}",
      f"Server: {_server(p)}",
      f"Hostname (reference): {p.get('host','')}" if p.get("ip") else "",
      f"Username: {p.get('username','')}",
      f"Password: {p.get('password','')}",
      f"IPsec PSK / Secret: {p.get('preSharedKey','')}" if protocol.startswith("L2TP") else "",
      f"Security: {p.get('security','')}",
      f"Credential status: {p.get('credentialStatus','')}",
      f"Source observed UTC: {p.get('sourceObservedUtc','')}",
      "",
      _guide(data,guide_id,protocol),
      "",
      "WARNING: PPTP is a legacy fallback; prefer L2TP/IPsec or OpenVPN." if protocol.startswith("PPTP") else
      "Tip: use the numeric server IP if .opengw.net is filtered."
    ]
    return "\n".join(x for x in lines if x is not None)

def _test(p):
    host=_server(p)
    port=1723 if str(p.get("protocol","")).startswith("PPTP") else 443
    try:
        ip=socket.gethostbyname(host)
        if not ipaddress.ip_address(ip).is_global:
            return False,f"DNS intercepted/private address {ip}"
        s=socket.create_connection((ip,port),timeout=2.0)
        s.close()
        return True,f"reachable TCP/{port} {ip}"
    except Exception as e:
        return False,str(e)

def _refresh():
    req=urllib.request.Request(RAW_URL,headers={"User-Agent":"DirectInternetMethod/1.3"})
    with urllib.request.urlopen(req,timeout=9) as r:
        data=json.load(r)
    try:
        req=urllib.request.Request(VPNBOOK_URL,headers={"User-Agent":"DirectInternetMethod/1.3"})
        with urllib.request.urlopen(req,timeout=9) as r:
            html=r.read().decode("utf-8","replace")
        m=re.search(r"(?is)Password.{0,1400}?(?:<code[^>]*>|>)([A-Za-z0-9]{6,16})(?:</code>|<)",html)
        if m:
            for p in data.get("profiles",[]):
                if p.get("provider")=="VPNBook":
                    p["password"]=m.group(1);p["credentialStatus"]="LIVE_REFRESHED_ROTATING"
    except Exception:
        pass
    DATA_PATH.parent.mkdir(parents=True,exist_ok=True)
    tmp=DATA_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    tmp.replace(DATA_PATH)
    return data

class RouterGatewayWindow(Adw.Window):
    def __init__(self,parent):
        super().__init__(transient_for=parent,modal=False,title="Router Gateway")
        self.set_default_size(980,700)
        self.data=_load();self.selected=None
        root=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=10)
        root.set_margin_top(16);root.set_margin_bottom(16);root.set_margin_start(18);root.set_margin_end(18)
        self.set_content(root)

        header=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=8)
        title=Gtk.Label(label="Router Gateway — L2TP/IPsec + PPTP",xalign=0);title.add_css_class("title-2")
        title.set_hexpand(True);header.append(title)
        self.status=Gtk.Label(label="Offline snapshot");self.status.add_css_class("dim-label");header.append(self.status)
        root.append(header)

        controls=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=8)
        self.protocol=Gtk.DropDown.new_from_strings(["All","L2TP/IPsec","PPTP"]);self.protocol.set_selected(0)
        self.protocol.connect("notify::selected",lambda *_:self.reload_rows());controls.append(self.protocol)
        self.router=Gtk.DropDown.new_from_strings(["Generic VPN Client","TP-Link VPN Client","ASUS VPN Fusion","MikroTik RouterOS"]);controls.append(self.router)
        self.router.connect("notify::selected",lambda *_:self.show_selected())
        b_refresh=Gtk.Button(label="Refresh data");b_refresh.connect("clicked",self.refresh_async);controls.append(b_refresh)
        b_test=Gtk.Button(label="Test selected");b_test.connect("clicked",self.test_async);controls.append(b_test)
        b_copy=Gtk.Button(label="Copy selected");b_copy.connect("clicked",self.copy_selected);controls.append(b_copy)
        root.append(controls)

        paned=Gtk.Paned.new(Gtk.Orientation.HORIZONTAL);paned.set_position(430);paned.set_vexpand(True)
        self.list=Gtk.ListBox();self.list.set_selection_mode(Gtk.SelectionMode.SINGLE);self.list.connect("row-selected",self.row_selected)
        scroll=Gtk.ScrolledWindow();scroll.set_child(self.list);paned.set_start_child(scroll)
        self.text=Gtk.TextView(editable=False,wrap_mode=Gtk.WrapMode.WORD_CHAR);self.text.set_monospace(True)
        scroll2=Gtk.ScrolledWindow();scroll2.set_child(self.text);paned.set_end_child(scroll2)
        root.append(paned)
        self.result=Gtk.Label(xalign=0,wrap=True);self.result.add_css_class("dim-label");root.append(self.result)
        warn=Gtk.Label(label="PPTP is legacy. Use a real router VPN Client feature; WAN PPTP/L2TP types and VPN pass-through are not equivalent.",xalign=0,wrap=True)
        warn.add_css_class("warning");root.append(warn)
        self.reload_rows()

    def guide_id(self):
        return ["generic","tplink","asus","mikrotik"][self.router.get_selected()]

    def reload_rows(self):
        while (child:=self.list.get_first_child()) is not None:self.list.remove(child)
        filt=["All","L2TP/IPsec","PPTP"][self.protocol.get_selected()]
        profiles=[p for p in self.data.get("profiles",[]) if filt=="All" or p.get("protocol")==filt]
        profiles.sort(key=lambda p:(1 if str(p.get("protocol","")).startswith("PPTP") else 0,p.get("observedPingMs") or 99999))
        for p in profiles:
            row=Gtk.ListBoxRow();row.profile=p
            box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=2)
            box.set_margin_top(8);box.set_margin_bottom(8);box.set_margin_start(10);box.set_margin_end(10)
            a=Gtk.Label(label=f"{p.get('provider')} · {p.get('protocol')} · {p.get('country')}",xalign=0);a.add_css_class("heading")
            b=Gtk.Label(label=f"{_server(p)}  ·  source ping {p.get('observedPingMs') or '—'} ms",xalign=0);b.add_css_class("dim-label")
            box.append(a);box.append(b);row.set_child(box);self.list.append(row)
        first=self.list.get_row_at_index(0)
        if first:self.list.select_row(first)

    def row_selected(self,_list,row):
        self.selected=getattr(row,"profile",None) if row else None
        self.show_selected()

    def show_selected(self):
        if not self.selected:return
        self.text.get_buffer().set_text(_config(self.data,self.selected,self.guide_id()))

    def copy_selected(self,*_):
        if not self.selected:return
        text=_config(self.data,self.selected,self.guide_id())
        Gdk.Display.get_default().get_clipboard().set(text);self.result.set_text("Selected profile copied.")

    def test_async(self,*_):
        if not self.selected:return
        self.result.set_text("Testing endpoint without changing routes or VPN state…")
        p=dict(self.selected)
        threading.Thread(target=lambda:GLib.idle_add(self._finish_test,*_test(p)),daemon=True).start()

    def _finish_test(self,ok,msg):
        self.result.set_text(("Reachable: " if ok else "Unverified: ")+msg+" — this is a reachability heuristic, not a full VPN handshake.")
        return False

    def refresh_async(self,*_):
        self.result.set_text("Refreshing repository snapshot and rotating credentials…")
        def work():
            try:data=_refresh();GLib.idle_add(self._finish_refresh,data,None)
            except Exception as e:GLib.idle_add(self._finish_refresh,None,str(e))
        threading.Thread(target=work,daemon=True).start()

    def _finish_refresh(self,data,error):
        if error:self.result.set_text("Refresh unavailable; current snapshot retained. "+error)
        else:
            self.data=data;self.status.set_text("Refreshed cache");self.reload_rows();self.result.set_text("Refresh complete.")
        return False
