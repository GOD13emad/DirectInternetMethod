#!/usr/bin/env python3
from __future__ import annotations
import threading
import gi
gi.require_version("Gtk","4.0")
gi.require_version("Adw","1")
from gi.repository import Gtk, Adw, GLib, Gdk
from router_gateway_core import APP_HOME, DATA_PATH, RAW_URL, VPNBOOK_URL, _load, _server, _guide, _config, _test, _refresh

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
