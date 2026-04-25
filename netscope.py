"""
Enhanced Python Network Packet Analyzer
========================================
A WireShark-inspired packet sniffer with:
- Multi-protocol support (TCP, UDP, ICMP, DNS, HTTP, ARP)
- Real-time traffic statistics & protocol distribution
- Packet filtering (by IP, protocol, port)
- Hex dump viewer
- Export to CSV/PCAP
- Color-coded protocol rows
- Session tracking
- Searchable packet log
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import (
    sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
    Raw, wrpcap, Ether
)
import threading
import csv
import datetime
import json
from collections import defaultdict
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# ─────────────────────────────────────────────
# Color Scheme (WireShark-inspired)
# ─────────────────────────────────────────────
PROTO_COLORS = {
    "TCP":  {"bg": "#e8f4f8", "fg": "#003d5c"},
    "UDP":  {"bg": "#e8f8e8", "fg": "#1a4a1a"},
    "ICMP": {"bg": "#fff8e8", "fg": "#5c3d00"},
    "ARP":  {"bg": "#f4e8f8", "fg": "#3d0058"},
    "DNS":  {"bg": "#f8f0e8", "fg": "#5c2a00"},
    "HTTP": {"bg": "#ffe8e8", "fg": "#5c0000"},
    "OTHER":{"bg": "#f0f0f0", "fg": "#333333"},
}

BG_DARK   = "#1e1e2e"
BG_PANEL  = "#252535"
FG_TEXT   = "#cdd6f4"
ACCENT    = "#89b4fa"
SUCCESS   = "#a6e3a1"
WARNING   = "#f9e2af"
DANGER    = "#f38ba8"
MUTED     = "#6c7086"
BORDER    = "#45475a"


# ─────────────────────────────────────────────
# Packet Model
# ─────────────────────────────────────────────
class PacketRecord:
    def __init__(self, number, timestamp, src, dst, proto, sport, dport,
                 length, info, raw_packet):
        self.number     = number
        self.timestamp  = timestamp
        self.src        = src
        self.dst        = dst
        self.proto      = proto
        self.sport      = sport
        self.dport      = dport
        self.length     = length
        self.info       = info
        self.raw_packet = raw_packet

    def to_tuple(self):
        return (self.number, self.timestamp, self.src, self.dst,
                self.proto, self.sport, self.dport, self.length, self.info)


# ─────────────────────────────────────────────
# Packet Parser
# ─────────────────────────────────────────────
def parse_packet(packet, number):
    """Parse a Scapy packet into a PacketRecord."""
    ts    = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    src   = dst = proto = sport = dport = info = "—"
    length = len(packet)

    if packet.haslayer(ARP):
        src   = packet[ARP].psrc
        dst   = packet[ARP].pdst
        proto = "ARP"
        op    = "Request" if packet[ARP].op == 1 else "Reply"
        info  = f"ARP {op}: who has {dst}? tell {src}"

    elif packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            sport = str(packet[TCP].sport)
            dport = str(packet[TCP].dport)
            flags = packet[TCP].flags
            proto = "HTTP" if dport in ("80","8080") or sport in ("80","8080") else "TCP"
            info  = f"TCP {sport} → {dport} [{flags}] Seq={packet[TCP].seq}"
            if packet.haslayer(Raw):
                payload = packet[Raw].load[:40].decode(errors="replace")
                if payload.startswith(("GET","POST","PUT","DELETE","HTTP")):
                    proto = "HTTP"
                    info  = payload.split("\r\n")[0][:80]

        elif packet.haslayer(UDP):
            sport = str(packet[UDP].sport)
            dport = str(packet[UDP].dport)
            proto = "DNS" if dport == "53" or sport == "53" else "UDP"
            info  = f"UDP {sport} → {dport}"
            if packet.haslayer(DNS):
                dns = packet[DNS]
                if dns.qr == 0 and dns.qd:
                    info = f"DNS Query: {dns.qd.qname.decode()}"
                elif dns.qr == 1 and dns.an:
                    info = f"DNS Response: {dns.an.rdata}"

        elif packet.haslayer(ICMP):
            proto = "ICMP"
            itype = packet[ICMP].type
            icode = packet[ICMP].code
            type_map = {0:"Echo Reply", 8:"Echo Request", 3:"Dest Unreachable",
                        11:"Time Exceeded"}
            info  = f"ICMP {type_map.get(itype, f'Type {itype}')} code={icode}"
        else:
            proto = "OTHER"
            info  = f"IP proto={packet[IP].proto}"

    return PacketRecord(number, ts, src, dst, proto, sport, dport, length, info, packet)


# ─────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────
class PacketAnalyzerApp:
    def __init__(self, root):
        self.root        = root
        self.root.title("NetScope — Packet Analyzer")
        self.root.geometry("1280x780")
        self.root.minsize(1000, 600)
        self.root.configure(bg=BG_DARK)

        # State
        self.packets        = []        # all captured PacketRecord
        self.filtered_ids   = []        # indices after filter
        self.sniffing       = False
        self.sniffer_thread = None
        self.packet_count   = 0
        self.stats          = defaultdict(int)   # proto → count
        self.sniffer_stop   = threading.Event()

        self._apply_styles()
        self._build_ui()

    # ──────────────────────────────────────────
    # Styles
    # ──────────────────────────────────────────
    def _apply_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=BG_DARK, foreground=FG_TEXT,
                        fieldbackground=BG_PANEL, bordercolor=BORDER,
                        troughcolor=BG_PANEL, focuscolor=ACCENT)

        style.configure("Treeview",
                        background=BG_PANEL, foreground=FG_TEXT,
                        fieldbackground=BG_PANEL, rowheight=22,
                        font=("Consolas", 10))
        style.configure("Treeview.Heading",
                        background=BG_DARK, foreground=ACCENT,
                        relief="flat", font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#313244")])

        style.configure("TButton", background=BG_PANEL, foreground=FG_TEXT,
                        bordercolor=BORDER, focuscolor=ACCENT,
                        font=("Segoe UI", 10), padding=6)
        style.map("TButton",
                  background=[("active", "#313244"), ("pressed", BORDER)])

        style.configure("Start.TButton", foreground=SUCCESS)
        style.configure("Stop.TButton",  foreground=DANGER)
        style.configure("TEntry", foreground=FG_TEXT, insertcolor=FG_TEXT)

        style.configure("TLabel", background=BG_DARK, foreground=FG_TEXT)
        style.configure("Panel.TLabel", background=BG_PANEL, foreground=FG_TEXT)
        style.configure("Muted.TLabel", background=BG_PANEL, foreground=MUTED,
                        font=("Segoe UI", 9))
        style.configure("Stat.TLabel",  background=BG_PANEL, foreground=ACCENT,
                        font=("Segoe UI", 18, "bold"))
        style.configure("TFrame",       background=BG_DARK)
        style.configure("Panel.TFrame", background=BG_PANEL)
        style.configure("TScrollbar",   background=BORDER, troughcolor=BG_PANEL,
                        bordercolor=BG_PANEL, arrowcolor=FG_TEXT)

    # ──────────────────────────────────────────
    # UI Construction
    # ──────────────────────────────────────────
    def _build_ui(self):
        # ── Top toolbar ──
        toolbar = ttk.Frame(self.root, style="Panel.TFrame")
        toolbar.pack(fill=tk.X, padx=8, pady=(8, 4))

        title_lbl = tk.Label(toolbar, text="● NetScope",
                             bg=BG_PANEL, fg=ACCENT,
                             font=("Segoe UI", 13, "bold"))
        title_lbl.pack(side=tk.LEFT, padx=12, pady=6)

        self.start_btn = ttk.Button(toolbar, text="▶  Start",
                                    style="Start.TButton",
                                    command=self.start_sniffing)
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = ttk.Button(toolbar, text="■  Stop",
                                   style="Stop.TButton",
                                   command=self.stop_sniffing, state="disabled")
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        ttk.Button(toolbar, text="🗑  Clear",
                   command=self.clear_packets).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="💾  Export CSV",
                   command=self.export_csv).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="📦  Save PCAP",
                   command=self.export_pcap).pack(side=tk.LEFT, padx=4)

        # status badge
        self.status_var = tk.StringVar(value="● Idle")
        self.status_lbl = tk.Label(toolbar, textvariable=self.status_var,
                                   bg=BG_PANEL, fg=MUTED,
                                   font=("Segoe UI", 10))
        self.status_lbl.pack(side=tk.RIGHT, padx=16)

        # ── Filter bar ──
        fbar = ttk.Frame(self.root, style="Panel.TFrame")
        fbar.pack(fill=tk.X, padx=8, pady=2)

        tk.Label(fbar, text="Filter:", bg=BG_PANEL, fg=MUTED,
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(12, 4))

        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        filter_entry = ttk.Entry(fbar, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=4, pady=6)
        tk.Label(fbar, text="(IP, protocol, port — e.g. 192.168.1.1 | TCP | 443)",
                 bg=BG_PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(side=tk.LEFT)

        # protocol quick-filter buttons
        for proto in ("ALL", "TCP", "UDP", "ICMP", "DNS", "HTTP", "ARP"):
            btn = tk.Button(fbar, text=proto, bg=BG_PANEL, fg=FG_TEXT,
                            relief="flat", padx=8, pady=3,
                            font=("Segoe UI", 9),
                            cursor="hand2",
                            command=lambda p=proto: self._quick_filter(p))
            btn.pack(side=tk.RIGHT, padx=2, pady=4)

        # ── Main paned area ──
        main_pane = tk.PanedWindow(self.root, orient=tk.VERTICAL,
                                   bg=BORDER, sashwidth=4,
                                   sashrelief="flat")
        main_pane.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # ── Packet list frame ──
        list_frame = ttk.Frame(main_pane)
        list_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("#", "Time", "Source", "Destination",
                   "Proto", "Sport", "Dport", "Len", "Info")
        col_widths = [52, 90, 130, 130, 60, 60, 60, 55, 400]

        self.tree = ttk.Treeview(list_frame, columns=columns,
                                  show="headings", selectmode="browse")
        for col, w in zip(columns, col_widths):
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort_column(c))
            self.tree.column(col, width=w, minwidth=40, anchor=tk.W)

        vsb = ttk.Scrollbar(list_frame, orient="vertical",
                             command=self.tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal",
                             command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        # row tags for protocol color coding
        for proto, colors in PROTO_COLORS.items():
            self.tree.tag_configure(proto,
                                    background=colors["bg"],
                                    foreground=colors["fg"])

        self.tree.bind("<<TreeviewSelect>>", self._on_packet_select)
        main_pane.add(list_frame, minsize=300)

        # ── Bottom detail pane ──
        detail_pane = tk.PanedWindow(main_pane, orient=tk.HORIZONTAL,
                                     bg=BORDER, sashwidth=4)
        main_pane.add(detail_pane, minsize=180)

        # Packet detail tree
        detail_frame = ttk.Frame(detail_pane, style="Panel.TFrame")
        self.detail_tree = ttk.Treeview(detail_frame, show="tree")
        self.detail_tree.configure(style="Treeview")
        d_vsb = ttk.Scrollbar(detail_frame, orient="vertical",
                               command=self.detail_tree.yview)
        self.detail_tree.configure(yscrollcommand=d_vsb.set)
        self.detail_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        detail_pane.add(detail_frame, minsize=300)

        # Hex dump panel
        hex_frame = ttk.Frame(detail_pane, style="Panel.TFrame")
        hex_label = tk.Label(hex_frame, text="Hex Dump",
                              bg=BG_PANEL, fg=MUTED,
                              font=("Segoe UI", 9, "bold"))
        hex_label.pack(anchor="w", padx=8, pady=(6,2))
        self.hex_text = tk.Text(hex_frame,
                                 font=("Consolas", 9),
                                 bg=BG_DARK, fg=FG_TEXT,
                                 insertbackground=FG_TEXT,
                                 state="disabled",
                                 wrap="none",
                                 relief="flat")
        hex_vsb = ttk.Scrollbar(hex_frame, orient="vertical",
                                 command=self.hex_text.yview)
        self.hex_text.configure(yscrollcommand=hex_vsb.set)
        self.hex_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8,0))
        hex_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        detail_pane.add(hex_frame, minsize=300)

        # ── Status bar ──
        status_bar = ttk.Frame(self.root, style="Panel.TFrame")
        status_bar.pack(fill=tk.X, padx=8, pady=(4, 8))

        self.count_var  = tk.StringVar(value="Packets: 0")
        self.tcp_var    = tk.StringVar(value="TCP: 0")
        self.udp_var    = tk.StringVar(value="UDP: 0")
        self.icmp_var   = tk.StringVar(value="ICMP: 0")
        self.dns_var    = tk.StringVar(value="DNS: 0")
        self.http_var   = tk.StringVar(value="HTTP: 0")
        self.arp_var    = tk.StringVar(value="ARP: 0")

        for var, color in [
            (self.count_var, FG_TEXT),
            (self.tcp_var,   PROTO_COLORS["TCP"]["fg"]),
            (self.udp_var,   PROTO_COLORS["UDP"]["fg"]),
            (self.icmp_var,  PROTO_COLORS["ICMP"]["fg"]),
            (self.dns_var,   PROTO_COLORS["DNS"]["fg"]),
            (self.http_var,  PROTO_COLORS["HTTP"]["fg"]),
            (self.arp_var,   PROTO_COLORS["ARP"]["fg"]),
        ]:
            lbl = tk.Label(status_bar, textvariable=var,
                           bg=BG_PANEL, fg=color,
                           font=("Segoe UI", 9), padx=14)
            lbl.pack(side=tk.LEFT)

    # ──────────────────────────────────────────
    # Sniffing Logic
    # ──────────────────────────────────────────
    def start_sniffing(self):
        if self.sniffing:
            return
        self.sniffing = True
        self.sniffer_stop.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("● Capturing…")
        self.status_lbl.config(fg=SUCCESS)

        self.sniffer_thread = threading.Thread(
            target=self._sniff_worker, daemon=True)
        self.sniffer_thread.start()

    def _sniff_worker(self):
        sniff(prn=self._handle_packet, store=False,
              stop_filter=lambda _: self.sniffer_stop.is_set())

    def stop_sniffing(self):
        self.sniffer_stop.set()
        self.sniffing = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set(f"● Stopped  ({self.packet_count} packets)")
        self.status_lbl.config(fg=MUTED)

    def _handle_packet(self, packet):
        self.packet_count += 1
        record = parse_packet(packet, self.packet_count)
        self.packets.append(record)
        self.stats[record.proto] += 1
        self.root.after(0, self._append_row, record)

    def _append_row(self, record):
        fval = self.filter_var.get().strip().lower()
        if fval and not self._matches_filter(record, fval):
            return

        tag   = record.proto if record.proto in PROTO_COLORS else "OTHER"
        iid   = self.tree.insert("", "end",
                                  values=record.to_tuple(),
                                  tags=(tag,))

        # auto-scroll if user is near the bottom
        if self.tree.yview()[1] > 0.9:
            self.tree.see(iid)

        self._update_status()

    def _update_status(self):
        self.count_var.set(f"Packets: {self.packet_count}")
        self.tcp_var.set(f"TCP: {self.stats.get('TCP',0)}")
        self.udp_var.set(f"UDP: {self.stats.get('UDP',0)}")
        self.icmp_var.set(f"ICMP: {self.stats.get('ICMP',0)}")
        self.dns_var.set(f"DNS: {self.stats.get('DNS',0)}")
        self.http_var.set(f"HTTP: {self.stats.get('HTTP',0)}")
        self.arp_var.set(f"ARP: {self.stats.get('ARP',0)}")

    # ──────────────────────────────────────────
    # Filtering
    # ──────────────────────────────────────────
    def _matches_filter(self, record, fval):
        haystack = " ".join([record.src, record.dst, record.proto,
                              record.sport, record.dport, record.info]).lower()
        return fval in haystack

    def _quick_filter(self, proto):
        if proto == "ALL":
            self.filter_var.set("")
        else:
            self.filter_var.set(proto)

    def apply_filter(self):
        fval = self.filter_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        for record in self.packets:
            if not fval or self._matches_filter(record, fval):
                tag = record.proto if record.proto in PROTO_COLORS else "OTHER"
                self.tree.insert("", "end", values=record.to_tuple(), tags=(tag,))

    # ──────────────────────────────────────────
    # Packet Detail / Hex Dump
    # ──────────────────────────────────────────
    def _on_packet_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0], "values")
        pkt_num = int(values[0])
        record  = next((p for p in self.packets if p.number == pkt_num), None)
        if record is None:
            return
        self._show_detail(record)
        self._show_hex(record)

    def _show_detail(self, record):
        self.detail_tree.delete(*self.detail_tree.get_children())
        pkt = record.raw_packet

        def add_layer(parent, layer_name, fields):
            node = self.detail_tree.insert(parent, "end",
                                            text=f"▼ {layer_name}", open=True)
            for k, v in fields.items():
                self.detail_tree.insert(node, "end", text=f"  {k}: {v}")
            return node

        if pkt.haslayer(Ether):
            e = pkt[Ether]
            add_layer("", "Ethernet", {
                "Src MAC": e.src, "Dst MAC": e.dst, "Type": hex(e.type)})

        if pkt.haslayer(ARP):
            a = pkt[ARP]
            add_layer("", "ARP", {
                "Operation": "Request" if a.op==1 else "Reply",
                "Sender MAC": a.hwsrc, "Sender IP": a.psrc,
                "Target MAC": a.hwdst, "Target IP": a.pdst})

        if pkt.haslayer(IP):
            ip = pkt[IP]
            add_layer("", "Internet Protocol", {
                "Version": ip.version, "IHL": ip.ihl,
                "TTL": ip.ttl, "Protocol": ip.proto,
                "Src": ip.src, "Dst": ip.dst,
                "Checksum": hex(ip.chksum), "Length": ip.len})

        if pkt.haslayer(TCP):
            t = pkt[TCP]
            add_layer("", "Transmission Control Protocol", {
                "Src Port": t.sport, "Dst Port": t.dport,
                "Seq": t.seq, "Ack": t.ack,
                "Flags": str(t.flags), "Window": t.window,
                "Checksum": hex(t.chksum)})

        if pkt.haslayer(UDP):
            u = pkt[UDP]
            add_layer("", "User Datagram Protocol", {
                "Src Port": u.sport, "Dst Port": u.dport,
                "Length": u.len, "Checksum": hex(u.chksum)})

        if pkt.haslayer(ICMP):
            ic = pkt[ICMP]
            add_layer("", "Internet Control Message Protocol", {
                "Type": ic.type, "Code": ic.code,
                "Checksum": hex(ic.chksum), "ID": ic.id, "Seq": ic.seq})

        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            add_layer("", "Domain Name System", {
                "ID": dns.id, "QR": "Response" if dns.qr else "Query",
                "Opcode": dns.opcode, "QD Count": dns.qdcount,
                "AN Count": dns.ancount})

        if pkt.haslayer(Raw):
            raw = pkt[Raw].load
            add_layer("", "Payload (Raw)", {
                "Length": len(raw),
                "ASCII": raw[:64].decode(errors="replace")})

    def _show_hex(self, record):
        raw = bytes(record.raw_packet)
        lines = []
        for i in range(0, len(raw), 16):
            chunk  = raw[i:i+16]
            hex_part  = " ".join(f"{b:02x}" for b in chunk)
            hex_part  = f"{hex_part:<47}"
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part}  {ascii_part}")

        self.hex_text.config(state="normal")
        self.hex_text.delete("1.0", tk.END)
        self.hex_text.insert(tk.END, "\n".join(lines))
        self.hex_text.config(state="disabled")

    # ──────────────────────────────────────────
    # Export
    # ──────────────────────────────────────────
    def export_csv(self):
        if not self.packets:
            messagebox.showinfo("No Data", "No packets to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export packets as CSV")
        if not path:
            return
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["#","Time","Source","Destination",
                              "Protocol","SPort","DPort","Len","Info"])
            for r in self.packets:
                writer.writerow(r.to_tuple())
        messagebox.showinfo("Exported", f"Saved {len(self.packets)} packets to:\n{path}")

    def export_pcap(self):
        if not self.packets:
            messagebox.showinfo("No Data", "No packets to save.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            title="Save capture as PCAP")
        if not path:
            return
        wrpcap(path, [r.raw_packet for r in self.packets])
        messagebox.showinfo("Saved", f"PCAP saved to:\n{path}\n"
                                      f"(Openable in Wireshark)")

    # ──────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────
    def clear_packets(self):
        if self.sniffing:
            messagebox.showwarning("Active", "Stop capture before clearing.")
            return
        self.packets.clear()
        self.stats.clear()
        self.packet_count = 0
        self.tree.delete(*self.tree.get_children())
        self.detail_tree.delete(*self.detail_tree.get_children())
        self.hex_text.config(state="normal")
        self.hex_text.delete("1.0", tk.END)
        self.hex_text.config(state="disabled")
        self._update_status()

    def _sort_column(self, col):
        """Toggle-sort tree by column."""
        col_map = {"#": 0, "Time": 1, "Source": 2, "Destination": 3,
                   "Proto": 4, "Sport": 5, "Dport": 6, "Len": 7, "Info": 8}
        idx = col_map.get(col, 0)
        items = [(self.tree.set(iid, col), iid)
                 for iid in self.tree.get_children("")]
        try:
            items.sort(key=lambda x: int(x[0]) if x[0].isdigit() else x[0])
        except Exception:
            items.sort()
        for order, (_, iid) in enumerate(items):
            self.tree.move(iid, "", order)


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import os, sys

    # Require root/admin on Linux/Mac
    if sys.platform != "win32" and os.geteuid() != 0:
        print("⚠  Run as root for packet capture:  sudo python enhanced_packet_analyzer.py")
        sys.exit(1)

    root = tk.Tk()
    app  = PacketAnalyzerApp(root)
    root.mainloop()
