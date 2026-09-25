"""
NETmate — Network Security Engineer Assistant
Developed by GET Intern'26, BT Group
For guidance purposes only — verify all commands before production use
"""

import tkinter as tk
from tkinter import ttk, font as tkfont
import json, os, re

# ─────────────────────────────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────────────────────────────
BASE  = os.path.dirname(os.path.abspath(__file__))
D     = os.path.join(BASE, "data")

# ─────────────────────────────────────────────────────────────────
#  COLOUR PALETTES
#  Dark:  ~55% black / ~15% white (text only) / ~30% red accents
#  Light: ~50% white / ~20% black / ~30% red accents
# ─────────────────────────────────────────────────────────────────
PAL = {
    "dark": {
        "root":        "#080808",
        "panel":       "#0d0d0d",
        "surface":     "#111111",
        "raised":      "#161616",
        "input_bg":    "#0d0d0d",
        "input_fg":    "#e0e0e0",
        "ph_fg":       "#383838",
        "topbar":      "#0a0a0a",
        "footer":      "#070707",
        "output_bg":   "#080808",
        "border":      "#1c1c1c",
        "border2":     "#252525",
        "tab_bg":      "#0d0d0d",
        "tab_sel":     "#111111",
        "sash":        "#111111",
        "code_bg":     "#050505",
        "code_fg":     "#00cc66",
        "code_cmt":    "#2d5c2d",
        "fg1":         "#e4e4e4",
        "fg2":         "#888888",
        "fg3":         "#444444",
        "fg4":         "#2a2a2a",
        "red":         "#cc1a1a",
        "red_bright":  "#ee2222",
        "red_dim":     "#661010",
        "red_bg":      "#150404",
        "green":       "#1a9944",
        "amber":       "#bb7700",
        "blue":        "#1a77bb",
        "tip_bg":      "#0f0f0f",
        "tip_border":  "#cc1a1a",
        "btn_fg":      "#ffffff",
        "btn_ref_bg":  "#1a0505",
        "btn_ref_fg":  "#cc4444",
        "sec_pre":     "#0d2e4d",
        "sec_prep":    "#0d3322",
        "sec_roll":    "#3d1400",
        "sec_check":   "#2a1a00",
        "sec_concept": "#1a0a2e",
        "tag_fg":      "#cccccc",
    },
    "light": {
        "root":        "#efefef",
        "panel":       "#f8f8f8",
        "surface":     "#ffffff",
        "raised":      "#f2f2f2",
        "input_bg":    "#ffffff",
        "input_fg":    "#111111",
        "ph_fg":       "#aaaaaa",
        "topbar":      "#ffffff",
        "footer":      "#e8e8e8",
        "output_bg":   "#f5f5f5",
        "border":      "#d8d8d8",
        "border2":     "#c4c4c4",
        "tab_bg":      "#f0f0f0",
        "tab_sel":     "#fafafa",
        "sash":        "#d0d0d0",
        "code_bg":     "#111111",
        "code_fg":     "#00aa55",
        "code_cmt":    "#336633",
        "fg1":         "#111111",
        "fg2":         "#444444",
        "fg3":         "#888888",
        "fg4":         "#cccccc",
        "red":         "#cc1a1a",
        "red_bright":  "#aa1010",
        "red_dim":     "#dd4444",
        "red_bg":      "#fff2f2",
        "green":       "#117733",
        "amber":       "#886600",
        "blue":        "#115599",
        "tip_bg":      "#1a1a1a",
        "tip_border":  "#cc1a1a",
        "btn_fg":      "#ffffff",
        "btn_ref_bg":  "#fff0f0",
        "btn_ref_fg":  "#cc2222",
        "sec_pre":     "#115588",
        "sec_prep":    "#116633",
        "sec_roll":    "#993300",
        "sec_check":   "#775500",
        "sec_concept": "#5500aa",
        "tag_fg":      "#ffffff",
    }
}

# ─────────────────────────────────────────────────────────────────
#  DATA LOADER
# ─────────────────────────────────────────────────────────────────
class DataLoader:
    def __init__(self):
        self.cisco  = self._load("cisco_asa.json")
        self.f5     = self._load("f5_ltm.json")
        self.ref    = self._load("reference.json")
        self.tips   = self._load("tooltips.json")

        # Build flat lookup: id -> playbook
        self._pb = {}
        for t in self.cisco.get("ticket_types", []):
            t["_device_group"] = "cisco"
            self._pb[t["id"]] = t
        for t in self.f5.get("ticket_types", []):
            t["_device_group"] = "f5"
            self._pb[t["id"]] = t

    def _load(self, fn):
        path = os.path.join(D, fn)
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def cisco_problems(self):
        return [(t["id"], t["label"]) for t in self.cisco.get("ticket_types", [])]

    def f5_problems(self):
        return [(t["id"], t["label"]) for t in self.f5.get("ticket_types", [])]

    def problems_for_device(self, dev):
        if dev.startswith("Cisco"):
            return self.cisco_problems()
        elif dev.startswith("F5"):
            return self.f5_problems()
        return self.cisco_problems() + self.f5_problems()

    def playbook(self, pid):
        return self._pb.get(pid)

    def match_raw(self, text):
        tl = text.lower()
        best, score = None, 0
        for pid, pb in self._pb.items():
            s = sum(1 for kw in pb.get("keywords", []) if kw in tl)
            if s > score:
                score, best = s, pb
        return (best or self._pb.get("acl_permit")), score

    def tooltip(self, key):
        return self.tips.get(key, {}).get("tooltip", "")

    def tacacs_text(self):
        return self._format_ref(self.ref["tacacs"])

    def aaa_text(self):
        return self._format_ref(self.ref["aaa"])

    def _format_ref(self, data):
        lines = [data["title"], "=" * len(data["title"]), ""]
        for sec in data["sections"]:
            lines.append(f"  ── {sec['title']} ──")
            for cmd in sec["commands"]:
                lines.append(f"  {cmd}")
            lines.append("")
        return "\n".join(lines)

# ─────────────────────────────────────────────────────────────────
#  LOGIC ENGINE
# ─────────────────────────────────────────────────────────────────
class Engine:
    def __init__(self, db: DataLoader):
        self.db = db

    # Fill {tokens} with real values
    def _fill(self, lines, ctx, raw_mode=False):
        if raw_mode:
            return lines   # return with <PLACEHOLDERS> intact
        out = []
        mapping = {
            "<SOURCE_IP>":      ctx.get("source_ip",    "<SOURCE_IP>"),
            "<DEST_IP>":        ctx.get("dest_ip",      "<DEST_IP>"),
            "<INTERFACE>":      ctx.get("interface",    "<INTERFACE>"),
            "<SRC_INTERFACE>":  ctx.get("interface",    "<SRC_INTERFACE>"),
            "<DST_INTERFACE>":  ctx.get("interface",    "<DST_INTERFACE>"),
            "<PORT>":           ctx.get("port",         "<PORT>"),
            "<PROTOCOL>":       ctx.get("protocol",     "tcp"),
            "<ACL_NAME>":       ctx.get("acl_name",     "<ACL_NAME>"),
            "<DST_ACL_NAME>":   ctx.get("acl_name",     "<DST_ACL_NAME>"),
            "<DEVICE_ID>":      ctx.get("device_id",    "<DEVICE_ID>"),
            "<VIP_NAME>":       ctx.get("vip_name",     "<VIP_NAME>"),
            "<POOL_NAME>":      ctx.get("pool_name",    "<POOL_NAME>"),
            "<SSL_PROFILE_NAME>": ctx.get("ssl_profile","<SSL_PROFILE_NAME>"),
            "<NODE_IP>":        ctx.get("dest_ip",      "<NODE_IP>"),
            "<PEER_IP>":        ctx.get("dest_ip",      "<PEER_IP>"),
        }
        for line in lines:
            r = line
            for k, v in mapping.items():
                r = r.replace(k, v)
            out.append(r)
        return out

    def solve_structured(self, pid, ctx):
        pb = self.db.playbook(pid)
        if not pb:
            return None
        return {
            "label":     pb["label"],
            "concept":   pb["concept"],
            "precheck":  self._fill(pb["precheck"],  ctx),
            "prep":      self._fill(pb["prep"],      ctx),
            "rollback":  self._fill(pb["rollback"],  ctx),
            "check":     self._fill_check(pb["check"], ctx),
            "raw_mode":  False,
        }

    def solve_raw(self, text):
        pb, score = self.db.match_raw(text)
        ctx = self._extract(text)
        return {
            "label":    pb["label"],
            "concept":  pb["concept"],
            "precheck": self._fill(pb["precheck"],  ctx, raw_mode=True),
            "prep":     self._fill(pb["prep"],      ctx, raw_mode=True),
            "rollback": self._fill(pb["rollback"],  ctx, raw_mode=True),
            "check":    self._fill_check(pb["check"], ctx, raw_mode=True),
            "raw_mode": True,
            "score":    score,
            "auto_ctx": ctx,
        }

    def _fill_check(self, chk, ctx, raw_mode=False):
        def f(v):
            if isinstance(v, str):
                return v if raw_mode else self._fill([v], ctx)[0]
            if isinstance(v, list):
                return self._fill(v, ctx, raw_mode)
            if isinstance(v, dict):
                return {k: f(vv) for k, vv in v.items()}
            return v
        return {k: f(v) for k, v in chk.items()}

    def _extract(self, text):
        ctx = {}
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        if len(ips) >= 1: ctx["source_ip"] = ips[0]
        if len(ips) >= 2: ctx["dest_ip"]   = ips[1]
        ports = re.findall(r'\b(?:443|80|22|3389|21|25|53|161|3306|1433|8080|8443|500|4500)\b', text)
        if ports: ctx["port"] = ports[0]
        iface = re.findall(r'\b(?:outside|inside|dmz|DEV|HYP-INFRA|INSIDE|OUTSIDE)\b', text, re.I)
        if iface: ctx["interface"] = iface[0]
        acl = re.findall(r'access-list\s+(\S+)', text, re.I)
        if acl: ctx["acl_name"] = acl[0]
        dev = re.findall(r'\b(\d{7})\b', text)
        if dev: ctx["device_id"] = dev[0]
        return ctx

# ─────────────────────────────────────────────────────────────────
#  TOOLTIP POPUP
# ─────────────────────────────────────────────────────────────────
class Tooltip:
    def __init__(self, w, fn, pal_fn):
        self._w, self._fn, self._pf = w, fn, pal_fn
        self._win = None
        w.bind("<Enter>", self.show); w.bind("<Leave>", self.hide)

    def show(self, _=None):
        txt = self._fn()
        if not txt: return
        p = self._pf()
        x = self._w.winfo_rootx() + self._w.winfo_width() + 8
        y = self._w.winfo_rooty()
        self._win = tw = tk.Toplevel(self._w)
        tw.wm_overrideredirect(True)
        tw.attributes("-topmost", True)
        tw.wm_geometry(f"+{x}+{y}")
        outer = tk.Frame(tw, bg=p["tip_border"], padx=1, pady=1)
        outer.pack(fill="both", expand=True)
        lbl = tk.Label(outer, text=txt, justify="left",
                       wraplength=500, bg=p["tip_bg"],
                       fg=p["fg1"],
                       font=("Consolas", 9), padx=14, pady=12)
        lbl.pack()

    def hide(self, _=None):
        if self._win:
            try: self._win.destroy()
            except: pass
            self._win = None

# ─────────────────────────────────────────────────────────────────
#  REFERENCE POPUP WINDOW
# ─────────────────────────────────────────────────────────────────
class RefWindow:
    def __init__(self, parent, title, content, pal_fn):
        self._pf = pal_fn
        self._win = None
        self._parent = parent
        self._title = title
        self._content = content

    def show(self):
        if self._win and self._win.winfo_exists():
            self._win.lift(); return
        p = self._pf()
        win = tk.Toplevel(self._parent)
        win.title(f"NETmate — {self._title}")
        win.geometry("700x680")
        win.configure(bg=p["root"])
        self._win = win

        hdr = tk.Frame(win, bg=p["topbar"], height=44)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr, text=f"  ◈  {self._title}",
                 font=("Segoe UI", 12, "bold"),
                 bg=p["topbar"], fg=p["red"]).pack(side="left", pady=8)
        tk.Button(hdr, text="✕  Close", font=("Segoe UI", 9),
                  bg=p["surface"], fg=p["fg2"],
                  relief="flat", cursor="hand2", padx=8,
                  command=win.destroy).pack(side="right", padx=12, pady=8)

        acc = tk.Frame(win, bg=p["red"], height=2); acc.pack(fill="x")

        frame = tk.Frame(win, bg=p["root"]); frame.pack(fill="both", expand=True, padx=0)
        vsb = tk.Scrollbar(frame, orient="vertical")
        txt = tk.Text(frame, font=("Consolas", 10),
                      bg=p["code_bg"], fg=p["code_fg"],
                      relief="flat", bd=0, wrap="none",
                      padx=16, pady=12,
                      yscrollcommand=vsb.set)
        vsb.configure(command=txt.yview)
        vsb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", self._content)
        txt.configure(state="disabled")

# ─────────────────────────────────────────────────────────────────
#  OUTPUT RENDERER
# ─────────────────────────────────────────────────────────────────
class Renderer:
    def __init__(self, widget: tk.Text, pal_fn):
        self.w = widget
        self.pf = pal_fn
        self._setup_tags()

    def _setup_tags(self):
        p = self.pf()
        w = self.w
        B  = ("Segoe UI", 11, "bold")
        b  = ("Segoe UI", 10, "bold")
        n  = ("Segoe UI", 10)
        s  = ("Segoe UI",  9)
        C  = ("Consolas",  10)
        Cs = ("Consolas",  9)

        w.tag_configure("app_title",   font=("Segoe UI",15,"bold"), foreground=p["red"],       spacing3=4)
        w.tag_configure("app_sub",     font=s,                      foreground=p["fg3"],       spacing3=10)
        w.tag_configure("divider",     font=Cs,                     foreground=p["fg4"],       spacing1=2, spacing3=4)
        w.tag_configure("concept_hdr", font=b,                      foreground=p["fg1"],       background=p["sec_concept"], spacing1=6, spacing3=6)
        w.tag_configure("concept_txt", font=n,                      foreground=p["fg2"],       lmargin1=12, lmargin2=12, spacing3=4)
        w.tag_configure("pre_hdr",     font=B,                      foreground=p["tag_fg"],    background=p["sec_pre"],    spacing1=8, spacing3=8)
        w.tag_configure("prep_hdr",    font=B,                      foreground=p["tag_fg"],    background=p["sec_prep"],   spacing1=8, spacing3=8)
        w.tag_configure("roll_hdr",    font=B,                      foreground="#ff9966",      background=p["sec_roll"],   spacing1=8, spacing3=8)
        w.tag_configure("check_hdr",   font=B,                      foreground=p["tag_fg"],    background=p["sec_check"],  spacing1=8, spacing3=8)
        w.tag_configure("sec_desc",    font=s,                      foreground=p["fg3"],       lmargin1=4, spacing3=6)
        w.tag_configure("cmd",         font=C,                      foreground=p["code_fg"],   background=p["code_bg"],    lmargin1=14, lmargin2=14, spacing1=1, spacing3=1)
        w.tag_configure("cmt",         font=Cs,                     foreground=p["code_cmt"],  background=p["code_bg"],    lmargin1=14, lmargin2=14, spacing1=1, spacing3=1)
        w.tag_configure("chk_C",       font=b,                      foreground=p["blue"])
        w.tag_configure("chk_H",       font=b,                      foreground=p["amber"])
        w.tag_configure("chk_E",       font=b,                      foreground=p["green"])
        w.tag_configure("chk_C2",      font=b,                      foreground=p["red_bright"])
        w.tag_configure("chk_K",       font=b,                      foreground=p["fg2"])
        w.tag_configure("chk_body",    font=n,                      foreground=p["fg2"],       lmargin1=18, lmargin2=18, spacing3=4)
        w.tag_configure("chk_cmd",     font=C,                      foreground=p["code_fg"],   background=p["code_bg"],    lmargin1=20, lmargin2=20, spacing1=1, spacing3=1)
        w.tag_configure("chk_cmt",     font=Cs,                     foreground=p["code_cmt"],  background=p["code_bg"],    lmargin1=20, lmargin2=20, spacing1=1, spacing3=1)
        w.tag_configure("warn",        font=s,                      foreground=p["amber"])
        w.tag_configure("meta",        font=s,                      foreground=p["fg3"])
        w.tag_configure("bold",        font=b,                      foreground=p["fg1"])
        w.tag_configure("h2",          font=b,                      foreground=p["fg2"],       spacing1=6)
        w.tag_configure("raw_badge",   font=("Segoe UI",9,"bold"),  foreground=p["amber"])

    def refresh(self):
        self._setup_tags()

    def clear(self):
        self.w.configure(state="normal")
        self.w.delete("1.0", "end")
        self.w.configure(state="disabled")

    def _w(self, txt, tag=None):
        self.w.configure(state="normal")
        if tag: self.w.insert("end", txt, tag)
        else:   self.w.insert("end", txt)
        self.w.configure(state="disabled")

    def _div(self, n=78):
        self._w("\n" + "─"*n + "\n", "divider")

    def _cmd_lines(self, lines, cmt_tag="cmt", cmd_tag="cmd"):
        for line in lines:
            s = line.strip()
            if s == "":
                self._w("\n")
            elif s.startswith("!"):
                self._w(f"  {line}\n", cmt_tag)
            else:
                self._w(f"  {line}\n", cmd_tag)

    # ── WELCOME ──────────────────────────────────────────
    def welcome(self):
        self.clear()
        self._w("\n")
        self._w("  NETmate\n", "app_title")
        self._w("  Network Security Engineer Assistant  ·  Cisco ASA/Firepower  ·  F5 BIG-IP LTM\n\n", "app_sub")
        self._div()
        self._w("\n  HOW TO USE\n\n", "bold")
        steps = [
            ("Structured Input", "Select Device → Problem Type → fill fields → click  ⚡ GENERATE"),
            ("Raw Ticket",       "Paste full ticket text into Raw Ticket tab → click  ⚡ ANALYSE"),
            ("Field Tooltips",   "Hover the  ?  button beside any input field to see CLI commands that help you find that value"),
            ("TACACS / AAA",     "Click either button at the bottom of the input panel to open the full command reference"),
        ]
        for title, desc in steps:
            self._w(f"  ◆  {title}\n", "h2")
            self._w(f"     {desc}\n\n", "chk_body")
        self._div()
        self._w("\n  OUTPUT SECTIONS\n\n", "bold")
        secs = [
            ("Concept",    "Plain-English explanation of the problem and engineering approach"),
            ("Pre-Check",  "CLI commands to analyse current config and confirm the fault before any change"),
            ("Prep",       "Exact CLI commands to implement the solution — apply in order, validate after"),
            ("Rollback",   "Commands to undo every change made in Prep — apply if validation fails"),
            ("C.H.E.C.K",  "Quality check template: Confirm · Have · Ensure · Comprehend · Know"),
        ]
        for name, desc in secs:
            self._w(f"  {name:<12}  {desc}\n", "chk_body")
        self._w("\n")
        self._div()
        self._w("\n  Supported: Cisco ASA · Cisco Firepower · F5 BIG-IP LTM\n", "meta")
        self._w("  Developed by GET Intern'26, BT Group\n\n", "meta")

    # ── MAIN RENDER ──────────────────────────────────────
    def render(self, result, display_ctx=None):
        self.clear()
        self._w("\n")
        self._w(f"  ◈  {result['label'].upper()}\n", "app_title")

        if display_ctx:
            parts = [f"{k}: {v}" for k, v in display_ctx.items() if v]
            if parts:
                self._w("  " + "   |   ".join(parts) + "\n", "meta")

        if result.get("raw_mode"):
            self._w("  ⚡ RAW TICKET MODE — commands shown with <PLACEHOLDERS>\n", "raw_badge")
            if result.get("auto_ctx"):
                auto = ", ".join(f"{k}={v}" for k,v in result["auto_ctx"].items())
                self._w(f"  Auto-extracted: {auto}\n", "meta")

        self._div()

        # ── CONCEPT ──────────────────────────────────────
        self._w("\n  ▌  CONCEPTUAL EXPLANATION\n", "concept_hdr")
        self._w("\n", "concept_txt")
        for line in result["concept"].split("\n"):
            self._w(f"  {line}\n", "concept_txt")
        self._w("\n")
        self._div()

        # ── PRE-CHECK ────────────────────────────────────
        self._w("\n  ▶  SECTION 1 — PRE-CHECK\n", "pre_hdr")
        self._w("  Run these commands to analyse the current config and confirm the fault before making any change.\n\n", "sec_desc")
        self._cmd_lines(result["precheck"])
        self._w("\n")
        self._div()

        # ── PREP ─────────────────────────────────────────
        self._w("\n  ✦  SECTION 2 — PREP  /  CHANGE\n", "prep_hdr")
        self._w("  Apply these commands in order to implement the solution. Validate after each phase.\n\n", "sec_desc")
        self._cmd_lines(result["prep"])
        self._w("\n")
        self._div()

        # ── ROLLBACK ─────────────────────────────────────
        self._w("\n  ↩  SECTION 3 — ROLLBACK\n", "roll_hdr")
        self._w("  ⚠  Execute these commands to undo all changes if post-change validation fails.\n\n", "sec_desc")
        self._cmd_lines(result["rollback"])
        self._w("\n")
        self._div()

        # ── C.H.E.C.K ────────────────────────────────────
        self._render_check(result["check"])

        self._w("\n  ─────────────────────────────────────────────────────────────\n", "divider")
        self._w("  ⚠  For guidance only. Verify all commands against your device config before production use.\n", "warn")
        self.w.see("1.0")

    def _render_check(self, chk):
        self._w("\n  ◉  SECTION 4 — C.H.E.C.K  QUALITY FRAMEWORK\n", "check_hdr")
        self._w("  Complete this section after implementing the change and update the ticket accordingly.\n\n", "sec_desc")

        items = [
            ("C — CONFIRM",    "chk_C",  "confirm",
             "Summarise what the customer wants. Clarify the objective."),
            ("H — HAVE",       "chk_H",  "have",
             "Record how permission was obtained. Name, role, and approval method."),
            ("E — ENSURE",     "chk_E",  "ensure",
             "Confirm you are on the correct device. Paste NSCLI output showing device numbers."),
            ("C — COMPREHEND", "chk_C2", "comprehend",
             "What could break. Expected result. Other teams impacted?"),
            ("K — KNOW",       "chk_K",  None,
             "Show config before, the change, and config after — confirm success."),
        ]

        for header, tag, key, hint in items:
            self._w(f"\n  [ {header} ]\n", tag)
            self._w(f"  {hint}\n", "chk_body")

            if key == "comprehend":
                comp = chk.get("comprehend", {})
                if isinstance(comp, dict):
                    self._w(f"  What could break:      {comp.get('what_could_break','')}\n", "chk_body")
                    self._w(f"  Expected result:       {comp.get('expected_result','')}\n", "chk_body")
                    self._w(f"  Other teams impacted:  {comp.get('other_teams','')}\n", "chk_body")
            elif key:
                val = chk.get(key, "")
                if isinstance(val, str):
                    for line in val.split("\n"):
                        s = line.strip()
                        if s.startswith("!"):
                            self._w(f"  {line}\n", "chk_cmt")
                        elif s and not s.startswith("nscli") and not s.startswith("show") and not s.startswith("conf"):
                            self._w(f"  {line}\n", "chk_body")
                        elif s:
                            self._w(f"  {line}\n", "chk_cmd")
            else:
                # K — Know: before / change / after
                self._w("\n  Before:\n", "chk_body")
                self._cmd_lines(chk.get("know_before", []), "chk_cmt", "chk_cmd")
                self._w("\n  Change:\n", "chk_body")
                self._cmd_lines(chk.get("know_change", []), "chk_cmt", "chk_cmd")
                self._w("\n  After:\n", "chk_body")
                self._cmd_lines(chk.get("know_after", []),  "chk_cmt", "chk_cmd")

        self._w("\n")

# ─────────────────────────────────────────────────────────────────
#  MAIN APPLICATION
# ─────────────────────────────────────────────────────────────────
class NETmate:

    DEVICES = ["Cisco ASA", "Cisco Firepower", "F5 BIG-IP LTM"]

    # Field definitions: (internal_key, display_label, placeholder, tooltip_key)
    FIELDS = [
        ("source_ip",   "Source IP",          "e.g.  10.10.1.5",             "source_ip"),
        ("dest_ip",     "Destination IP",      "e.g.  172.24.128.40",         "dest_ip"),
        ("interface",   "Interface / Zone",    "e.g.  outside",               "interface"),
        ("port",        "Port",                "e.g.  443",                   "port"),
        ("acl_name",    "ACL Name / No.",      "e.g.  101  or  OUTSIDE_IN",   "acl_name"),
        ("device_id",   "Device ID",           "e.g.  1309582",               "device_id"),
        ("protocol",    "Protocol",            "tcp  /  udp  /  ip",          None),
        ("vip_name",    "VIP / VS Name",       "e.g.  VIP-161.47.163.216-443","vip_name"),
        ("pool_name",   "Pool Name",           "e.g.  POOL_EIP_72.3.244-8080","pool_name"),
        ("ssl_profile", "SSL Profile Name",    "e.g.  wildcard.example.com",  "ssl_profile"),
    ]

    def __init__(self, root: tk.Tk):
        self.root   = root
        self.mode   = "dark"
        self.db     = DataLoader()
        self.eng    = Engine(self.db)
        self._ents  = {}   # key -> Entry
        self._ph    = {}   # key -> bool (showing placeholder)
        self._vars  = {}   # combo StringVars
        self._twid  = []   # (role, widget) for theme refresh
        self._ref_tacacs = None
        self._ref_aaa    = None

        root.title("NETmate — Network Security Engineer Assistant")
        root.geometry("1500x920")
        root.minsize(1100, 680)
        self._build_fonts()
        self._build_ui()
        self._apply_theme()

    def p(self): return PAL[self.mode]

    # ── FONTS ────────────────────────────────────────────
    def _build_fonts(self):
        self.f_logo  = tkfont.Font(family="Segoe UI", size=16, weight="bold")
        self.f_hdr   = tkfont.Font(family="Segoe UI", size=11, weight="bold")
        self.f_body  = tkfont.Font(family="Segoe UI", size=10)
        self.f_small = tkfont.Font(family="Segoe UI", size=9)
        self.f_tiny  = tkfont.Font(family="Segoe UI", size=8)
        self.f_sec   = tkfont.Font(family="Segoe UI", size=8,  weight="bold")
        self.f_label = tkfont.Font(family="Segoe UI", size=9)
        self.f_btn   = tkfont.Font(family="Segoe UI", size=11, weight="bold")
        self.f_mono  = tkfont.Font(family="Consolas",  size=10)
        self.f_monosm= tkfont.Font(family="Consolas",  size=9)

    # ── UI SKELETON ──────────────────────────────────────
    def _build_ui(self):
        self.root.configure(bg=self.p()["root"])

        # Top bar
        self.topbar = tk.Frame(self.root, height=52); self.topbar.pack(fill="x")
        self.topbar.pack_propagate(False)
        self._twid.append(("topbar", self.topbar))

        self.lbl_logo = tk.Label(self.topbar, text="◈  NETmate", font=self.f_logo, padx=18)
        self.lbl_logo.pack(side="left")
        self._twid.append(("logo", self.lbl_logo))

        self.lbl_sub = tk.Label(self.topbar,
            text="Network Security Engineer Assistant  ·  Cisco ASA · Cisco Firepower · F5 BIG-IP LTM",
            font=self.f_small)
        self.lbl_sub.pack(side="left", padx=6)
        self._twid.append(("subtitle", self.lbl_sub))

        self.btn_theme = tk.Button(self.topbar, text="☀  Light Mode",
            font=self.f_small, relief="flat", cursor="hand2",
            padx=12, pady=4, command=self._toggle_theme)
        self.btn_theme.pack(side="right", padx=14, pady=10)
        self._twid.append(("btn_sec", self.btn_theme))

        # Accent divider
        self.acc = tk.Frame(self.root, height=2); self.acc.pack(fill="x")
        self._twid.append(("accent", self.acc))

        # Pane: LEFT = output, RIGHT = input
        self.pane = tk.PanedWindow(self.root, orient="horizontal",
                                   bd=0, sashwidth=4, handlesize=0)
        self.pane.pack(fill="both", expand=True)
        self._twid.append(("pane", self.pane))

        self._build_input_panel()
        self._build_output_panel()

        # Footer
        self.footer = tk.Frame(self.root, height=26); self.footer.pack(fill="x", side="bottom")
        self.footer.pack_propagate(False)
        self._twid.append(("footer", self.footer))
        self.lbl_foot = tk.Label(self.footer,
            text="Developed by GET Intern'26, BT Group   ·   "
                 "This is for guidance purposes only — verify all commands before applying to production   ·   "
                 "If still unsure, refer to NetSec Modules",
            font=self.f_tiny)
        self.lbl_foot.pack(side="left", padx=16, pady=5)
        self._twid.append(("footer_lbl", self.lbl_foot))

    # ── OUTPUT PANEL (Left) ──────────────────────────────
    def _build_output_panel(self):
        self.out_frame = tk.Frame(self.pane)
        self.pane.add(self.out_frame, minsize=560)
        self._twid.append(("panel", self.out_frame))

        # Header strip
        ohdr = tk.Frame(self.out_frame, height=38); ohdr.pack(fill="x"); ohdr.pack_propagate(False)
        self._twid.append(("panel", ohdr))
        self.lbl_out_title = tk.Label(ohdr, text="  ◈  SOLUTION OUTPUT",
            font=self.f_hdr, anchor="w", padx=12)
        self.lbl_out_title.pack(side="left", fill="y")
        self._twid.append(("out_title", self.lbl_out_title))
        self.btn_clear = tk.Button(ohdr, text="✕  Clear",
            font=self.f_small, relief="flat", cursor="hand2", padx=8,
            command=self._on_clear)
        self.btn_clear.pack(side="right", padx=10, pady=6)
        self._twid.append(("btn_sec", self.btn_clear))

        self.out_sep = tk.Frame(self.out_frame, height=1); self.out_sep.pack(fill="x")
        self._twid.append(("border_line", self.out_sep))

        # Output text + scrollbar
        tf = tk.Frame(self.out_frame); tf.pack(fill="both", expand=True)
        self._twid.append(("panel", tf))
        vsb = tk.Scrollbar(tf, orient="vertical")
        self.txt_out = tk.Text(tf, font=self.f_monosm, relief="flat", bd=0,
                               wrap="word", state="disabled", cursor="arrow",
                               padx=16, pady=12, spacing1=1, spacing3=1,
                               yscrollcommand=vsb.set)
        vsb.configure(command=self.txt_out.yview)
        vsb.pack(side="right", fill="y")
        self.txt_out.pack(fill="both", expand=True)
        # Isolated scroll
        self.txt_out.bind("<Enter>", lambda e: self._set_scroll("out"))
        self.txt_out.bind("<Leave>", lambda e: self._set_scroll(None))

        self.renderer = Renderer(self.txt_out, self.p)
        self.renderer.welcome()

    # ── INPUT PANEL (Right) ──────────────────────────────
    def _build_input_panel(self):
        self.in_frame = tk.Frame(self.pane)
        self.pane.add(self.in_frame, minsize=380, width=445)
        self._twid.append(("panel", self.in_frame))

        # Notebook
        self.nb = ttk.Notebook(self.in_frame)
        self.nb.pack(fill="both", expand=True)

        self.tab_str = tk.Frame(self.nb); self.tab_raw = tk.Frame(self.nb)
        self.nb.add(self.tab_str, text="  ⊞  Structured  ")
        self.nb.add(self.tab_raw, text="  ☰  Raw Ticket  ")
        self._twid.append(("panel", self.tab_str))
        self._twid.append(("panel", self.tab_raw))

        self._build_structured_tab()
        self._build_raw_tab()
        self._build_ref_buttons()

    # ── STRUCTURED TAB ───────────────────────────────────
    def _build_structured_tab(self):
        tab = self.tab_str
        # Scrollable canvas (isolated scroll)
        self._sc = tk.Canvas(tab, bd=0, highlightthickness=0)
        sc_vsb = tk.Scrollbar(tab, orient="vertical", command=self._sc.yview)
        self._sc.configure(yscrollcommand=sc_vsb.set)
        sc_vsb.pack(side="right", fill="y")
        self._sc.pack(side="left", fill="both", expand=True)
        self._inner = tk.Frame(self._sc)
        self._iid = self._sc.create_window((0,0), window=self._inner, anchor="nw")
        self._inner.bind("<Configure>", lambda e: self._sc.configure(
            scrollregion=self._sc.bbox("all")))
        self._sc.bind("<Configure>", lambda e: self._sc.itemconfig(self._iid, width=e.width))
        self._sc.bind("<Enter>",  lambda e: self._set_scroll("sc"))
        self._sc.bind("<Leave>",  lambda e: self._set_scroll(None))
        self._inner.bind("<Enter>", lambda e: self._set_scroll("sc"))
        self._inner.bind("<Leave>", lambda e: self._set_scroll(None))
        self._twid.append(("sc", self._sc))
        self._twid.append(("panel", self._inner))

        s = self._inner
        pad = dict(padx=16, pady=3)

        # Section: Device
        self._shdr(s, "DEVICE & TICKET TYPE", top=14)
        self._combo(s, "Device", "device", self.DEVICES, self._on_device_change, **pad)
        self._combo(s, "Problem Type", "problem", [], None, **pad)

        # Section: Network
        self._shdr(s, "NETWORK DETAILS", top=12)
        for key, label, ph, tip_key in self.FIELDS:
            self._entry(s, label, key, ph, tip_key, **pad)

        # Section: Notes
        self._shdr(s, "TICKET NOTES", top=12)
        nl = tk.Label(s, text="Extra context or customer request:", font=self.f_label, anchor="w")
        nl.pack(fill="x", padx=16, pady=(0,2))
        self._twid.append(("label", nl))
        self._note_border = tk.Frame(s); self._note_border.pack(fill="x", padx=16, pady=(0,6))
        self._twid.append(("input_frame", self._note_border))
        self.txt_notes = tk.Text(self._note_border, height=3, font=self.f_monosm,
                                 relief="flat", bd=0, wrap="word")
        self.txt_notes.pack(fill="x", padx=4, pady=4)

        # Generate button
        self._gen_frame = tk.Frame(s); self._gen_frame.pack(fill="x", padx=16, pady=(12,18))
        self._twid.append(("panel", self._gen_frame))
        self.btn_gen = tk.Button(self._gen_frame, text="⚡  GENERATE SOLUTION",
            font=self.f_btn, relief="flat", cursor="hand2", pady=11, bd=0,
            command=self._on_generate)
        self.btn_gen.pack(fill="x")
        self.btn_gen.bind("<Enter>", lambda e: e.widget.config(bg=self.p()["red_bright"]))
        self.btn_gen.bind("<Leave>", lambda e: e.widget.config(bg=self.p()["red"]))
        self._twid.append(("btn_pri", self.btn_gen))

    # ── RAW TICKET TAB ───────────────────────────────────
    def _build_raw_tab(self):
        tab = self.tab_raw
        f0 = tk.Frame(tab); f0.pack(fill="x", padx=16, pady=(14,4))
        self._twid.append(("panel", f0))
        il = tk.Label(f0,
            text="Paste full ticket text — engine auto-matches to the correct playbook.\n"
                 "Commands will be shown with <PLACEHOLDER> tokens.",
            font=self.f_small, anchor="w", justify="left")
        il.pack(side="left")
        self._twid.append(("label", il))

        self._raw_border = tk.Frame(tab); self._raw_border.pack(fill="both", expand=True, padx=16, pady=(0,6))
        self._twid.append(("input_frame", self._raw_border))
        raw_vsb = tk.Scrollbar(self._raw_border, orient="vertical")
        self.txt_raw = tk.Text(self._raw_border, font=self.f_monosm, relief="flat",
                               bd=0, wrap="word", yscrollcommand=raw_vsb.set)
        raw_vsb.configure(command=self.txt_raw.yview)
        raw_vsb.pack(side="right", fill="y")
        self.txt_raw.pack(fill="both", expand=True, padx=4, pady=4)

        self._raw_btn_f = tk.Frame(tab); self._raw_btn_f.pack(fill="x", padx=16, pady=(0,14))
        self._twid.append(("panel", self._raw_btn_f))
        self.btn_raw = tk.Button(self._raw_btn_f, text="⚡  ANALYSE TICKET",
            font=self.f_btn, relief="flat", cursor="hand2", pady=11, bd=0,
            command=self._on_raw)
        self.btn_raw.pack(fill="x")
        self.btn_raw.bind("<Enter>", lambda e: e.widget.config(bg=self.p()["red_bright"]))
        self.btn_raw.bind("<Leave>", lambda e: e.widget.config(bg=self.p()["red"]))
        self._twid.append(("btn_pri", self.btn_raw))

    # ── TACACS / AAA BUTTONS ─────────────────────────────
    def _build_ref_buttons(self):
        rf = tk.Frame(self.in_frame, height=52); rf.pack(fill="x", side="bottom")
        rf.pack_propagate(False)
        self._twid.append(("ref_bar", rf))

        sep = tk.Frame(rf, height=1); sep.pack(fill="x")
        self._twid.append(("border_line", sep))

        inner = tk.Frame(rf); inner.pack(fill="both", expand=True, padx=12, pady=6)
        self._twid.append(("ref_bar", inner))

        self.btn_tacacs = tk.Button(inner, text="⊞  TACACS Commands",
            font=self.f_small, relief="flat", cursor="hand2",
            padx=14, pady=6, command=self._open_tacacs)
        self.btn_tacacs.pack(side="left", padx=(0,6))
        self._twid.append(("btn_ref", self.btn_tacacs))

        self.btn_aaa = tk.Button(inner, text="⊞  AAA Commands",
            font=self.f_small, relief="flat", cursor="hand2",
            padx=14, pady=6, command=self._open_aaa)
        self.btn_aaa.pack(side="left")
        self._twid.append(("btn_ref", self.btn_aaa))

    # ── WIDGET FACTORIES ─────────────────────────────────
    def _shdr(self, parent, text, top=10):
        f = tk.Frame(parent); f.pack(fill="x", padx=12, pady=(top,3))
        lbl = tk.Label(f, text=text, font=self.f_sec, anchor="w")
        lbl.pack(side="left", padx=4)
        sep = tk.Frame(f, height=1); sep.pack(fill="x", expand=True, padx=6, pady=5)
        self._twid.append(("sec_lbl", lbl))
        self._twid.append(("sep", sep))

    def _combo(self, parent, label, key, choices, cb=None, padx=16, pady=3):
        row = tk.Frame(parent); row.pack(fill="x", padx=padx, pady=(pady,0))
        self._twid.append(("panel", row))
        lbl = tk.Label(row, text=label, width=18, anchor="w", font=self.f_label)
        lbl.pack(side="left")
        self._twid.append(("label", lbl))
        var = tk.StringVar(); self._vars[key] = var
        cmb = ttk.Combobox(row, textvariable=var, state="readonly",
                           font=self.f_body, width=24)
        cmb["values"] = choices
        if choices: cmb.current(0)
        cmb.pack(side="left", fill="x", expand=True)
        if cb: cmb.bind("<<ComboboxSelected>>", cb)
        self._ents[key] = cmb

    def _entry(self, parent, label, key, ph="", tip_key=None, padx=16, pady=3):
        row = tk.Frame(parent); row.pack(fill="x", padx=padx, pady=(pady,0))
        self._twid.append(("panel", row))
        lbl = tk.Label(row, text=label, width=18, anchor="w", font=self.f_label)
        lbl.pack(side="left")
        self._twid.append(("label", lbl))
        ef = tk.Frame(row); ef.pack(side="left", fill="x", expand=True)
        self._twid.append(("input_frame", ef))
        ent = tk.Entry(ef, font=self.f_body, relief="flat", bd=4)
        ent.pack(fill="x")
        if ph:
            ent.insert(0, ph); self._ph[key] = True
            ent.bind("<FocusIn>",  lambda e, en=ent, k=key:   self._ph_in(en, k))
            ent.bind("<FocusOut>", lambda e, en=ent, k=key, p=ph: self._ph_out(en, k, p))
        self._ents[key] = ent
        self._twid.append(("entry", ent))
        if tip_key:
            tip_text = self.db.tooltip(tip_key)
            tb = tk.Label(row, text=" ? ", font=self.f_tiny, cursor="question_arrow",
                          width=3, relief="flat")
            tb.pack(side="right", padx=(4,0))
            Tooltip(tb, lambda tt=tip_text: tt, self.p)
            self._twid.append(("tip_btn", tb))

    def _ph_in(self, e, k):
        if self._ph.get(k):
            e.delete(0, "end"); e.config(fg=self.p()["input_fg"]); self._ph[k] = False

    def _ph_out(self, e, k, ph):
        if not e.get():
            e.insert(0, ph); e.config(fg=self.p()["ph_fg"]); self._ph[k] = True

    # ── SCROLL ISOLATION ─────────────────────────────────
    def _set_scroll(self, target):
        self.root.unbind_all("<MouseWheel>")
        if target == "sc":
            self.root.bind_all("<MouseWheel>", lambda e:
                self._sc.yview_scroll(int(-1*(e.delta/120)), "units"))
        elif target == "out":
            self.root.bind_all("<MouseWheel>", lambda e:
                self.txt_out.yview_scroll(int(-1*(e.delta/120)), "units"))

    # ── EVENTS ───────────────────────────────────────────
    def _on_device_change(self, _=None):
        dev = self._vars.get("device", tk.StringVar()).get()
        probs = self.db.problems_for_device(dev)
        labels = [lbl for _, lbl in probs]
        cmb = self._ents.get("problem")
        if cmb:
            cmb["values"] = labels
            cmb.current(0) if labels else cmb.set("")

    def _get_ctx(self):
        ph_map = {
            "source_ip":   "e.g.  10.10.1.5",
            "dest_ip":     "e.g.  172.24.128.40",
            "interface":   "e.g.  outside",
            "port":        "e.g.  443",
            "acl_name":    "e.g.  101  or  OUTSIDE_IN",
            "device_id":   "e.g.  1309582",
            "protocol":    "tcp  /  udp  /  ip",
            "vip_name":    "e.g.  VIP-161.47.163.216-443",
            "pool_name":   "e.g.  POOL_EIP_72.3.244-8080",
            "ssl_profile": "e.g.  wildcard.example.com",
        }
        ctx = {}
        for key, ph in ph_map.items():
            w = self._ents.get(key)
            if w:
                val = w.get().strip()
                if val and val != ph:
                    ctx[key] = val
        return ctx

    def _get_pid(self):
        dev   = self._vars.get("device",  tk.StringVar()).get()
        label = self._vars.get("problem", tk.StringVar()).get()
        for pid, lbl in self.db.problems_for_device(dev):
            if lbl == label:
                return pid
        return "acl_permit"

    def _on_generate(self):
        dev    = self._vars.get("device",  tk.StringVar()).get()
        prob   = self._vars.get("problem", tk.StringVar()).get()
        ctx    = self._get_ctx()
        pid    = self._get_pid()
        result = self.eng.solve_structured(pid, ctx)
        if not result:
            return
        disp = {"Device": dev, "Problem": prob}
        disp.update({k: v for k, v in ctx.items() if v})
        self.renderer.render(result, disp)

    def _on_raw(self):
        raw = self.txt_raw.get("1.0", "end").strip()
        if not raw:
            return
        result = self.eng.solve_raw(raw)
        self.renderer.render(result, {"Mode": "Raw Ticket Analysis"})

    def _on_clear(self):
        self.renderer.welcome()

    def _open_tacacs(self):
        if not self._ref_tacacs:
            self._ref_tacacs = RefWindow(self.root, "TACACS Command Reference",
                                         self.db.tacacs_text(), self.p)
        self._ref_tacacs.show()

    def _open_aaa(self):
        if not self._ref_aaa:
            self._ref_aaa = RefWindow(self.root, "AAA Command Reference",
                                       self.db.aaa_text(), self.p)
        self._ref_aaa.show()

    # ── THEME ────────────────────────────────────────────
    def _toggle_theme(self):
        self.mode = "light" if self.mode == "dark" else "dark"
        self.btn_theme.config(text="☀  Light Mode" if self.mode == "dark" else "🌙  Dark Mode")
        self._apply_theme()

    def _apply_theme(self):
        p = self.p()
        self.root.configure(bg=p["root"])

        # TTK style
        st = ttk.Style(); st.theme_use("default")
        st.configure("TNotebook",
            background=p["tab_bg"], borderwidth=0, tabmargins=[0,0,0,0])
        st.configure("TNotebook.Tab",
            background=p["tab_bg"], foreground=p["fg2"],
            font=("Segoe UI",10), padding=[14,7], borderwidth=0)
        st.map("TNotebook.Tab",
            background=[("selected",p["tab_sel"]),("active",p["raised"])],
            foreground=[("selected",p["red"]),    ("active",p["fg1"])])
        st.configure("TCombobox",
            background=p["input_bg"], foreground=p["input_fg"],
            fieldbackground=p["input_bg"],
            selectbackground=p["red"], selectforeground="#ffffff",
            arrowcolor=p["red"])
        st.map("TCombobox",
            fieldbackground=[("readonly",p["input_bg"])],
            foreground=[("readonly",p["input_fg"])])
        st.configure("TPanedwindow", background=p["sash"])

        for role, w in self._twid:
            try:
                if role == "topbar":
                    w.configure(bg=p["topbar"])
                elif role == "logo":
                    w.configure(bg=p["topbar"], fg=p["red"])
                elif role == "subtitle":
                    w.configure(bg=p["topbar"], fg=p["fg3"])
                elif role == "panel":
                    w.configure(bg=p["panel"])
                elif role == "sc":
                    w.configure(bg=p["panel"], highlightthickness=0)
                elif role == "accent":
                    w.configure(bg=p["red"])
                elif role == "pane":
                    w.configure(bg=p["sash"])
                elif role == "footer":
                    w.configure(bg=p["footer"])
                elif role == "footer_lbl":
                    w.configure(bg=p["footer"], fg=p["fg3"])
                elif role == "label":
                    w.configure(bg=p["panel"], fg=p["fg2"])
                elif role == "sec_lbl":
                    w.configure(bg=p["panel"], fg=p["fg3"])
                elif role == "sep":
                    w.configure(bg=p["border"])
                elif role == "input_frame":
                    w.configure(bg=p["border"])
                elif role == "entry":
                    is_ph = False
                    for key, en in self._ents.items():
                        if en is w:
                            is_ph = self._ph.get(key, False); break
                    w.configure(bg=p["input_bg"],
                                fg=p["ph_fg"] if is_ph else p["input_fg"],
                                insertbackground=p["input_fg"],
                                selectbackground=p["red"],
                                selectforeground="#ffffff")
                elif role == "tip_btn":
                    w.configure(bg=p["raised"], fg=p["red_dim"])
                elif role == "btn_pri":
                    w.configure(bg=p["red"], fg=p["btn_fg"],
                                activebackground=p["red_bright"],
                                activeforeground="#ffffff")
                elif role == "btn_sec":
                    w.configure(bg=p["surface"], fg=p["fg2"],
                                activebackground=p["raised"],
                                activeforeground=p["fg1"])
                elif role == "btn_ref":
                    w.configure(bg=p["btn_ref_bg"], fg=p["btn_ref_fg"],
                                activebackground=p["red_bg"],
                                activeforeground=p["red"])
                elif role == "ref_bar":
                    w.configure(bg=p["surface"])
                elif role == "out_title":
                    w.configure(bg=p["panel"], fg=p["fg1"])
                elif role == "border_line":
                    w.configure(bg=p["border"])
            except Exception:
                pass

        # Text widgets
        self.txt_out.configure(bg=p["output_bg"], fg=p["fg1"],
            insertbackground=p["fg1"],
            selectbackground=p["red"], selectforeground="#ffffff")
        self.txt_notes.configure(bg=p["input_bg"], fg=p["input_fg"],
            insertbackground=p["fg1"])
        self.txt_raw.configure(bg=p["input_bg"], fg=p["input_fg"],
            insertbackground=p["fg1"])
        self._note_border.configure(bg=p["border"])
        self._raw_border.configure(bg=p["border"])
        self._raw_btn_f.configure(bg=p["panel"])
        self._inner.configure(bg=p["panel"])

        self.renderer.refresh()


# ─────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    try: root.iconbitmap("")
    except: pass
    app = NETmate(root)
    app._on_device_change()
    root.mainloop()
