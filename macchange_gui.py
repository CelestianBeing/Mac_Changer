#!/usr/bin/python3
# Disclaimer: Educational & authorized testing only

import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
import re
import threading
import winreg
import ctypes
import random
import time

# ── palette ───────────────────────────────────────────────────────────────────
BG      = "#0d1117"
SURFACE = "#161b22"
BORDER  = "#30363d"
ACCENT  = "#58a6ff"
SUCCESS = "#3fb950"
DANGER  = "#f85149"
WARN    = "#e3b341"
TEXT    = "#e6edf3"
MUTED   = "#8b949e"
MONO    = "Courier New"
SANS    = "Segoe UI"

# ── Windows helpers ───────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def is_valid_mac(mac: str) -> bool:
    return bool(re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac))

def random_mac() -> str:
    b = [random.randint(0, 255) for _ in range(6)]
    b[0] = (b[0] & 0xfe) | 0x02   # locally administered, unicast
    return ":".join(f"{x:02x}" for x in b)

def get_interfaces() -> list:
    interfaces = []
    try:
        out = subprocess.check_output(
            ["getmac", "/v", "/fo", "csv", "/nh"],
            stderr=subprocess.DEVNULL
        ).decode(errors="replace")
        for line in out.strip().splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) < 3:
                continue
            name, desc, mac_raw = parts[0], parts[1], parts[2]
            if "N/A" in mac_raw or "Disabled" in mac_raw:
                continue
            mac = mac_raw.replace("-", ":").lower()
            interfaces.append({"name": name, "description": desc, "mac": mac})
    except Exception:
        pass

    if not interfaces:
        try:
            out = subprocess.check_output(
                ["ipconfig", "/all"], stderr=subprocess.DEVNULL
            ).decode(errors="replace")
            for block in re.split(r"\r?\n\r?\n", out):
                name_m = re.search(r"^(.+?):$", block, re.MULTILINE)
                mac_m  = re.search(r"Physical Address[.\s]+:\s+([0-9A-Fa-f\-]{17})", block)
                if name_m and mac_m:
                    interfaces.append({
                        "name": name_m.group(1).strip(),
                        "description": name_m.group(1).strip(),
                        "mac": mac_m.group(1).replace("-", ":").lower()
                    })
        except Exception:
            pass
    return interfaces

def get_adapter_guid(friendly_name: str):
    base = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as net_key:
            i = 0
            while True:
                try:
                    guid = winreg.EnumKey(net_key, i); i += 1
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                            f"{base}\\{guid}\\Connection") as conn:
                            name, _ = winreg.QueryValueEx(conn, "Name")
                            if name.lower() == friendly_name.lower():
                                return guid
                    except OSError:
                        pass
                except OSError:
                    break
    except Exception:
        pass
    return None

def _find_class_subkey(guid: str):
    """Return (reg_path, subkey_name) for the adapter class key matching guid."""
    reg_path = r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path,
                            access=winreg.KEY_READ) as cls_key:
            idx = 0
            while True:
                try:
                    sub = winreg.EnumKey(cls_key, idx); idx += 1
                    sub_path = f"{reg_path}\\{sub}"
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub_path,
                                            access=winreg.KEY_READ) as sk:
                            ni, _ = winreg.QueryValueEx(sk, "NetCfgInstanceId")
                            if ni.lower() == guid.lower():
                                return sub_path
                    except OSError:
                        pass
                except OSError:
                    break
    except Exception:
        pass
    return None

def set_mac_registry(guid: str, new_mac: str) -> bool:
    mac_plain = new_mac.replace(":", "").upper()
    sub_path = _find_class_subkey(guid)
    if not sub_path:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub_path,
                            access=winreg.KEY_READ | winreg.KEY_WRITE) as sk:
            winreg.SetValueEx(sk, "NetworkAddress", 0, winreg.REG_SZ, mac_plain)
            return True
    except Exception:
        return False

def delete_mac_registry(guid: str) -> bool:
    """Delete NetworkAddress value to restore hardware MAC."""
    sub_path = _find_class_subkey(guid)
    if not sub_path:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub_path,
                            access=winreg.KEY_READ | winreg.KEY_WRITE) as sk:
            winreg.DeleteValue(sk, "NetworkAddress")
            return True
    except FileNotFoundError:
        return True   # already gone — that's fine
    except Exception:
        return False

def disable_enable_adapter(name: str):
    subprocess.call(["netsh", "interface", "set", "interface", name, "admin=disable"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["netsh", "interface", "set", "interface", name, "admin=enable"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_current_mac_for(name: str) -> str:
    for iface in get_interfaces():
        if iface["name"].lower() == name.lower():
            return iface["mac"]
    return "unknown"


# ── GUI ───────────────────────────────────────────────────────────────────────

class MacChangerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MAC Changer  —  Windows 11")
        self.resizable(False, False)
        self.configure(bg=BG)
        self._interfaces: list = []
        self._original_mac: str = ""          # saved before first change

        # auto-rotate timer state
        self._timer_running  = False
        self._timer_thread   = None
        self._timer_stop_evt = threading.Event()
        self._next_change_at = 0.0            # epoch seconds

        self._build_ui()
        self._refresh_interfaces()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if not is_admin():
            self._log("⚠  Not running as Administrator — registry writes will fail.", "err")
            self._log("   Right-click → Run as administrator.", "err")

    # ─── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        # ── header ──
        hdr = tk.Frame(self, bg=BG, pady=16)
        hdr.pack(fill="x", padx=28)
        tk.Label(hdr, text="◈  MAC Changer", font=(SANS, 17, "bold"),
                 bg=BG, fg=ACCENT).pack(anchor="w")
        tk.Label(hdr, text="Spoof your adapter's MAC address on Windows 11",
                 font=(SANS, 9), bg=BG, fg=MUTED).pack(anchor="w", pady=(2, 0))
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x")

        # ── main card ──
        card = tk.Frame(self, bg=SURFACE, padx=24, pady=18)
        card.pack(fill="both", padx=20, pady=14)

        # interface row
        self._lbl(card, "Interface").grid(row=0, column=0, sticky="w", pady=6)
        irow = tk.Frame(card, bg=SURFACE)
        irow.grid(row=0, column=1, sticky="ew", pady=6, padx=(10, 0))
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(irow, textvariable=self.iface_var,
                                        width=28, state="readonly")
        self.iface_combo.pack(side="left")
        self.iface_combo.bind("<<ComboboxSelected>>", lambda _: self._on_iface_select())
        tk.Button(irow, text="↺", command=self._refresh_interfaces,
                  bg=SURFACE, fg=MUTED, relief="flat", font=(SANS, 11),
                  activebackground=BORDER, cursor="hand2").pack(side="left", padx=(6, 0))

        # current MAC
        self._lbl(card, "Current MAC").grid(row=1, column=0, sticky="w", pady=6)
        self.cur_mac_var = tk.StringVar(value="—")
        tk.Label(card, textvariable=self.cur_mac_var, font=(MONO, 10),
                 bg=SURFACE, fg=MUTED).grid(row=1, column=1, sticky="w", padx=(10, 0))

        # original MAC
        self._lbl(card, "Original MAC").grid(row=2, column=0, sticky="w", pady=4)
        self.orig_mac_var = tk.StringVar(value="—")
        tk.Label(card, textvariable=self.orig_mac_var, font=(MONO, 10),
                 bg=SURFACE, fg=MUTED).grid(row=2, column=1, sticky="w", padx=(10, 0))

        # adapter desc
        self._lbl(card, "Adapter").grid(row=3, column=0, sticky="w", pady=4)
        self.desc_var = tk.StringVar(value="—")
        tk.Label(card, textvariable=self.desc_var, font=(SANS, 9),
                 bg=SURFACE, fg=MUTED, wraplength=280, justify="left"
                 ).grid(row=3, column=1, sticky="w", padx=(10, 0))

        # new MAC entry
        self._lbl(card, "New MAC").grid(row=4, column=0, sticky="w", pady=8)
        ef = tk.Frame(card, bg=ACCENT)
        ef.grid(row=4, column=1, sticky="ew", pady=8, padx=(10, 0))
        self.mac_entry = tk.Entry(ef, font=(MONO, 11), width=24,
                                  bg=SURFACE, fg=TEXT, insertbackground=ACCENT,
                                  relief="flat", bd=6)
        self.mac_entry.pack(fill="both")
        self.mac_entry.insert(0, "AA:BB:CC:DD:EE:FF")
        self.mac_entry.bind("<FocusIn>", self._clear_placeholder)

        # random button
        tk.Button(card, text="⚡ Random MAC", command=self._insert_random_mac,
                  bg=BORDER, fg=TEXT, relief="flat", font=(SANS, 9),
                  activebackground="#444c56", cursor="hand2", padx=8, pady=4
                  ).grid(row=5, column=1, sticky="w", padx=(10, 0), pady=(0, 6))

        tk.Frame(card, height=1, bg=BORDER).grid(
            row=6, column=0, columnspan=2, sticky="ew", pady=8)

        # ── action buttons row ──
        btn_row = tk.Frame(card, bg=SURFACE)
        btn_row.grid(row=7, column=0, columnspan=2, sticky="ew")

        self.apply_btn = tk.Button(
            btn_row, text="Apply Change", command=self._apply,
            bg=ACCENT, fg="#0d1117", relief="flat",
            font=(SANS, 10, "bold"), padx=12, pady=9,
            activebackground="#79c0ff", cursor="hand2"
        )
        self.apply_btn.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.restore_btn = tk.Button(
            btn_row, text="⟲ Restore Original", command=self._restore,
            bg=BORDER, fg=WARN, relief="flat",
            font=(SANS, 9, "bold"), padx=10, pady=9,
            activebackground="#444c56", cursor="hand2"
        )
        self.restore_btn.pack(side="left", fill="x", expand=True)

        card.columnconfigure(1, weight=1)

        # ── auto-rotate section ──
        tk.Frame(self, height=1, bg=BORDER).pack(fill="x", padx=20)
        rot = tk.Frame(self, bg=SURFACE, padx=24, pady=14)
        rot.pack(fill="both", padx=20, pady=(0, 8))

        tk.Label(rot, text="Auto-Rotate MAC", font=(SANS, 10, "bold"),
                 bg=SURFACE, fg=TEXT).grid(row=0, column=0, columnspan=4,
                                            sticky="w", pady=(0, 8))

        tk.Label(rot, text="Change every", font=(SANS, 9),
                 bg=SURFACE, fg=MUTED).grid(row=1, column=0, sticky="w")

        self.interval_var = tk.StringVar(value="30")
        iv = tk.Frame(rot, bg=ACCENT)
        iv.grid(row=1, column=1, padx=(8, 4))
        tk.Entry(iv, textvariable=self.interval_var,
                 font=(MONO, 10), width=6,
                 bg=SURFACE, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=4).pack()

        self.unit_var = tk.StringVar(value="seconds")
        unit_combo = ttk.Combobox(rot, textvariable=self.unit_var, width=9,
                                  state="readonly",
                                  values=["seconds", "minutes", "hours"])
        unit_combo.grid(row=1, column=2, padx=(0, 10))

        self.timer_btn = tk.Button(
            rot, text="▶ Start", command=self._toggle_timer,
            bg=SUCCESS, fg="#0d1117", relief="flat",
            font=(SANS, 9, "bold"), padx=10, pady=5,
            activebackground="#56d364", cursor="hand2"
        )
        self.timer_btn.grid(row=1, column=3)

        # countdown display
        self.countdown_var = tk.StringVar(value="")
        tk.Label(rot, textvariable=self.countdown_var,
                 font=(MONO, 9), bg=SURFACE, fg=ACCENT
                 ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(6, 0))

        # ── admin badge ──
        badge_color = SUCCESS if is_admin() else DANGER
        badge_text  = "✔ Administrator" if is_admin() else "✘ Not Administrator"
        tk.Label(self, text=badge_text, font=(SANS, 8, "bold"),
                 bg=BG, fg=badge_color).pack(anchor="e", padx=22, pady=(4, 2))

        # ── log ──
        lf = tk.Frame(self, bg=BG, padx=20)
        lf.pack(fill="both", padx=0, pady=(0, 14))
        tk.Label(lf, text="Log", font=(SANS, 8, "bold"),
                 bg=BG, fg=MUTED).pack(anchor="w")
        self.log_box = tk.Text(lf, height=7, bg="#010409", fg=TEXT,
                               font=(MONO, 9), relief="flat", bd=0,
                               state="disabled")
        self.log_box.pack(fill="both")
        self.log_box.tag_config("ok",  foreground=SUCCESS)
        self.log_box.tag_config("err", foreground=DANGER)
        self.log_box.tag_config("inf", foreground=ACCENT)
        self.log_box.tag_config("warn", foreground=WARN)

        self.update_idletasks()
        self.minsize(480, self.winfo_reqheight())

    def _lbl(self, parent, text):
        return tk.Label(parent, text=text, font=(SANS, 10),
                        bg=SURFACE, fg=MUTED, anchor="w", width=13)

    # ─── helpers ──────────────────────────────────────────────────────────────

    def _log(self, msg, tag=""):
        self.log_box.config(state="normal")
        self.log_box.insert("end", msg + "\n", tag)
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def _refresh_interfaces(self):
        self._interfaces = get_interfaces()
        names = [i["name"] for i in self._interfaces]
        self.iface_combo["values"] = names
        if names:
            self.iface_combo.set(names[0])
            self._on_iface_select()
            self._log(f"Found {len(names)} adapter(s).", "inf")
        else:
            self._log("No adapters detected.", "err")

    def _on_iface_select(self):
        name = self.iface_var.get()
        for iface in self._interfaces:
            if iface["name"] == name:
                self.cur_mac_var.set(iface["mac"])
                self.desc_var.set(iface["description"])
                # snapshot original MAC first time we see this adapter
                if not self._original_mac:
                    self._original_mac = iface["mac"]
                    self.orig_mac_var.set(iface["mac"])
                return

    def _clear_placeholder(self, _e):
        if self.mac_entry.get() in ("AA:BB:CC:DD:EE:FF", ""):
            self.mac_entry.delete(0, "end")

    def _insert_random_mac(self):
        self.mac_entry.delete(0, "end")
        self.mac_entry.insert(0, random_mac())

    def _get_interval_seconds(self):
        try:
            val = int(self.interval_var.get())
            if val <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid interval",
                                 "Enter a positive whole number for the interval.")
            return None
        unit = self.unit_var.get()
        multiplier = {"seconds": 1, "minutes": 60, "hours": 3600}.get(unit, 1)
        return val * multiplier

    # ─── core change logic (shared) ───────────────────────────────────────────

    def _do_change(self, name: str, new_mac: str, silent=False):
        """Blocking — call from a worker thread. Returns (before, after)."""
        before = get_current_mac_for(name)
        guid = get_adapter_guid(name)
        if not guid:
            return before, "no-guid"
        if not set_mac_registry(guid, new_mac):
            return before, "reg-fail"
        disable_enable_adapter(name)
        time.sleep(1.5)
        after = get_current_mac_for(name)
        return before, after

    # ─── apply button ─────────────────────────────────────────────────────────

    def _apply(self):
        name    = self.iface_var.get()
        new_mac = self.mac_entry.get().strip().replace("-", ":").lower()
        if not name:
            messagebox.showerror("Error", "Select a network adapter first.")
            return
        if not is_valid_mac(new_mac):
            messagebox.showerror("Error", "Invalid MAC format.\n\nUse:  AA:BB:CC:DD:EE:FF")
            return
        if not is_admin():
            messagebox.showerror("Administrator required",
                "Please right-click the script and choose\n'Run as administrator'.")
            return

        # snapshot original if not yet saved
        if not self._original_mac:
            self._original_mac = self.cur_mac_var.get()
            self.orig_mac_var.set(self._original_mac)

        self.apply_btn.config(state="disabled", text="Applying…")
        self._log(f"→ {name}  |  new MAC: {new_mac}", "inf")
        threading.Thread(target=self._apply_worker,
                         args=(name, new_mac), daemon=True).start()

    def _apply_worker(self, name, new_mac):
        before, after = self._do_change(name, new_mac)
        self.after(0, self._apply_done, before, after, name)

    def _apply_done(self, before, after, name):
        self._refresh_current_mac(name)
        if after in ("no-guid", "reg-fail", "unknown") or before == after:
            self._log(f"[!!] Failed — MAC unchanged ({after}).", "err")
            messagebox.showwarning("May not have applied",
                "MAC address may not have changed.\n\n"
                "Some adapters require enabling 'Locally Administered Address'\n"
                "in Device Manager → Adapter Properties → Advanced tab.")
        else:
            self._log(f"[+] Done!  {before}  →  {after}", "ok")
        self.apply_btn.config(state="normal", text="Apply Change")

    # ─── restore button ───────────────────────────────────────────────────────

    def _restore(self):
        name = self.iface_var.get()
        if not name:
            messagebox.showerror("Error", "Select a network adapter first.")
            return
        if not is_admin():
            messagebox.showerror("Administrator required",
                "Please right-click the script and choose\n'Run as administrator'.")
            return
        if not self._original_mac:
            messagebox.showinfo("Nothing to restore",
                "No original MAC was recorded.\n"
                "The adapter may already have its hardware MAC.")
            return

        self.restore_btn.config(state="disabled", text="Restoring…")
        self._log(f"Restoring original MAC on {name}…", "warn")
        threading.Thread(target=self._restore_worker,
                         args=(name,), daemon=True).start()

    def _restore_worker(self, name):
        guid = get_adapter_guid(name)
        ok = False
        if guid:
            ok = delete_mac_registry(guid)
            if ok:
                disable_enable_adapter(name)
                time.sleep(1.5)
        self.after(0, self._restore_done, name, ok)

    def _restore_done(self, name, ok):
        self._refresh_current_mac(name)
        if ok:
            self._log(f"[+] Original MAC restored on {name}.", "ok")
        else:
            self._log("[!!] Restore failed — could not delete registry value.", "err")
        self.restore_btn.config(state="normal", text="⟲ Restore Original")

    # ─── auto-rotate timer ────────────────────────────────────────────────────

    def _toggle_timer(self):
        if self._timer_running:
            self._stop_timer()
        else:
            self._start_timer()

    def _start_timer(self):
        name = self.iface_var.get()
        if not name:
            messagebox.showerror("Error", "Select a network adapter first.")
            return
        if not is_admin():
            messagebox.showerror("Administrator required",
                "Please right-click the script and choose\n'Run as administrator'.")
            return
        secs = self._get_interval_seconds()
        if secs is None:
            return

        # snapshot original before first auto-change
        if not self._original_mac:
            self._original_mac = self.cur_mac_var.get()
            self.orig_mac_var.set(self._original_mac)

        self._timer_running  = True
        self._timer_stop_evt = threading.Event()
        self._next_change_at = time.time() + secs
        self.timer_btn.config(text="■ Stop", bg=DANGER, activebackground="#ff7b72")
        self._log(f"Auto-rotate started — every {self.interval_var.get()} "
                  f"{self.unit_var.get()}.", "inf")

        self._timer_thread = threading.Thread(
            target=self._timer_worker, args=(name, secs), daemon=True)
        self._timer_thread.start()
        self._tick_countdown()

    def _stop_timer(self):
        self._timer_running = False
        self._timer_stop_evt.set()
        self.timer_btn.config(text="▶ Start", bg=SUCCESS, activebackground="#56d364")
        self.countdown_var.set("")
        self._log("Auto-rotate stopped.", "warn")

    def _timer_worker(self, name: str, interval: int):
        """Background thread: change MAC every `interval` seconds."""
        while not self._timer_stop_evt.wait(timeout=interval):
            if not self._timer_running:
                break
            mac = random_mac()
            self.after(0, self._log, f"[timer] Rotating to {mac} …", "inf")
            before, after = self._do_change(name, mac)
            if after not in ("no-guid", "reg-fail", "unknown") and before != after:
                self.after(0, self._log, f"[timer] ✔  {before}  →  {after}", "ok")
                self.after(0, self._refresh_current_mac, name)
                self.after(0, lambda a=after: self.cur_mac_var.set(a))
            else:
                self.after(0, self._log, f"[timer] ✘  Change failed ({after}).", "err")
            # reset countdown for next cycle
            self._next_change_at = time.time() + interval

    def _tick_countdown(self):
        """Update countdown label every second while timer is running."""
        if not self._timer_running:
            return
        remaining = max(0, int(self._next_change_at - time.time()))
        h, rem  = divmod(remaining, 3600)
        m, s    = divmod(rem, 60)
        if h:
            label = f"Next change in  {h}h {m:02d}m {s:02d}s"
        elif m:
            label = f"Next change in  {m}m {s:02d}s"
        else:
            label = f"Next change in  {s}s"
        self.countdown_var.set(label)
        self.after(1000, self._tick_countdown)

    # ─── utilities ────────────────────────────────────────────────────────────

    def _refresh_current_mac(self, name: str):
        self._interfaces = get_interfaces()
        for iface in self._interfaces:
            if iface["name"] == name:
                self.cur_mac_var.set(iface["mac"])
                return

    def _on_close(self):
        """Stop timer thread cleanly before exit."""
        if self._timer_running:
            self._timer_stop_evt.set()
            self._timer_running = False
        self.destroy()


# ── ttk dark style ────────────────────────────────────────────────────────────

def _style_ttk():
    s = ttk.Style()
    s.theme_use("default")
    for widget in ("TCombobox",):
        s.configure(widget,
                    fieldbackground=SURFACE, background=SURFACE,
                    foreground=TEXT, selectbackground=ACCENT,
                    bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                    arrowcolor=MUTED)


if __name__ == "__main__":
    app = MacChangerApp()
    _style_ttk()
    app.mainloop()
