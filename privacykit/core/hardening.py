"""
Windows privacy hardening: telemetry, advertising ID, activity history, and
the hosts-file blackhole.

Every item here is expressed as a :class:`Tweak` with an explicit read, apply,
and revert path, plus an honest ``impact`` string. That structure exists
because privacy hardening advice on the internet is full of changes that break
things without saying so — disabling a service that Windows Update depends on,
or blocking a domain that also serves activation. Each tweak here states what
it actually costs.

The hosts blackhole writes to ``%SystemRoot%\\System32\\drivers\\etc\\hosts``.
The original file is backed up first, byte for byte, and the entries are
wrapped in clearly marked begin/end blocks so removal never damages entries the
user or another tool added.
"""

from __future__ import annotations

import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import journal, shell, sysinfo

if sysinfo.IS_WINDOWS:
    import winreg
else:
    winreg = None  # type: ignore

HOSTS_PATH = Path(shell.expand(r"%SystemRoot%\System32\drivers\etc\hosts"))
BLOCK_BEGIN = "# ===== PrivacyKit telemetry blocklist BEGIN — do not edit inside ====="
BLOCK_END = "# ===== PrivacyKit telemetry blocklist END ====="


# ──────────────────────────────────────────────────────────────────────────────
# Registry tweak framework
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Tweak:
    key: str                    # stable identifier
    title: str
    hive: str                   # "HKCU" or "HKLM"
    path: str
    value_name: str
    private_value: int          # value that improves privacy
    description: str
    impact: str = "No functional impact."
    value_type: str = "dword"
    admin_required: bool = False

    def _hive(self):
        return (winreg.HKEY_CURRENT_USER if self.hive == "HKCU"
                else winreg.HKEY_LOCAL_MACHINE)

    def read(self) -> Optional[int]:
        if not sysinfo.IS_WINDOWS or winreg is None:
            return None
        try:
            with winreg.OpenKey(self._hive(), self.path) as k:
                val, _ = winreg.QueryValueEx(k, self.value_name)
                return int(val)
        except Exception:
            return None

    @property
    def is_private(self) -> bool:
        return self.read() == self.private_value

    def apply(self) -> tuple:
        if not sysinfo.IS_WINDOWS or winreg is None:
            return False, "Windows-only."
        if self.admin_required and not sysinfo.is_admin():
            return False, "Administrator rights are required for this setting."
        prior = self.read()
        if prior == self.private_value:
            return True, "Already set."
        journal.record(
            module="hardening",
            action=f"Privacy tweak: {self.title}",
            undo={"kind": "hardening.registry_restore", "hive": self.hive,
                  "path": self.path, "name": self.value_name, "prior": prior},
            before={self.value_name: prior},
        )
        try:
            k = winreg.CreateKeyEx(self._hive(), self.path, 0,
                                   winreg.KEY_READ | winreg.KEY_WRITE)
            winreg.SetValueEx(k, self.value_name, 0, winreg.REG_DWORD,
                              self.private_value)
            winreg.CloseKey(k)
            return True, f"{self.title} — applied."
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"


@journal.register_undo("hardening.registry_restore")
def _undo_registry(payload: dict) -> tuple:
    if not sysinfo.IS_WINDOWS or winreg is None:
        return False, "Windows-only."
    hive = (winreg.HKEY_CURRENT_USER if payload.get("hive") == "HKCU"
            else winreg.HKEY_LOCAL_MACHINE)
    path, name = payload.get("path", ""), payload.get("name", "")
    prior = payload.get("prior")
    try:
        k = winreg.CreateKeyEx(hive, path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
        if prior is None:
            # The value did not exist before; deleting restores that exactly.
            try:
                winreg.DeleteValue(k, name)
            except FileNotFoundError:
                pass
            msg = f"removed {name} (was not previously set)"
        else:
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(prior))
            msg = f"restored {name} = {prior}"
        winreg.CloseKey(k)
        return True, msg
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


#: The curated tweak set. Each one is reversible and states its real cost.
TWEAKS: List[Tweak] = [
    Tweak("advertising_id", "Disable the advertising ID", "HKCU",
          r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0,
          "Stops apps using a per-user advertising identifier to build a profile "
          "across everything you install.",
          "Ads still appear, but are no longer personalised by this ID."),
    Tweak("telemetry_level", "Set telemetry to the minimum allowed", "HKLM",
          r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0,
          "Requests the lowest diagnostic-data level. On Home and Pro editions "
          "Microsoft treats 0 as 'Basic' rather than truly off.",
          "Some Feedback Hub and diagnostic features stop working.",
          admin_required=True),
    Tweak("activity_feed", "Disable activity history (Timeline)", "HKLM",
          r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0,
          "Stops Windows recording which apps and documents you open for the "
          "Timeline feature.",
          "Task View no longer shows past activity.", admin_required=True),
    Tweak("publish_activities", "Stop publishing activity history", "HKLM",
          r"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0,
          "Prevents local activity data being published for cross-device sync.",
          "Picking up where you left off on another device stops working.",
          admin_required=True),
    Tweak("upload_activities", "Stop uploading activity history to Microsoft", "HKLM",
          r"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", 0,
          "Blocks upload of activity history to your Microsoft account.",
          "Cross-device Timeline stops working.", admin_required=True),
    Tweak("tailored_experiences", "Disable tailored experiences", "HKCU",
          r"Software\Microsoft\Windows\CurrentVersion\Privacy",
          "TailoredExperiencesWithDiagnosticDataEnabled", 0,
          "Stops Microsoft using your diagnostic data to personalise tips, ads, "
          "and recommendations.",
          "Suggestions in Start and Settings become generic."),
    Tweak("app_launch_tracking", "Stop tracking app launches", "HKCU",
          r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
          "Start_TrackProgs", 0,
          "Windows stops recording which programs you launch to order the Start "
          "menu's 'most used' list.",
          "The 'Most used' list in Start stops updating."),
    Tweak("location_tracking_apps", "Disable app access to location", "HKLM",
          r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager"
          r"\ConsentStore\location", "Value", 0,
          "Denies Store apps access to the location service.",
          "Maps, Weather, and Find My Device stop knowing where you are.",
          admin_required=True),
    Tweak("feedback_frequency", "Stop Windows asking for feedback", "HKCU",
          r"Software\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", 0,
          "Suppresses the periodic 'How likely are you to recommend Windows' "
          "prompts, which are tied to your diagnostic data.",
          "No feedback prompts."),
    Tweak("cortana_search", "Disable Cortana in search", "HKLM",
          r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
          "AllowCortana", 0,
          "Turns off Cortana integration in the search box.",
          "Voice assistant features stop working.", admin_required=True),
    Tweak("web_search", "Disable web results in Start menu search", "HKCU",
          r"Software\Microsoft\Windows\CurrentVersion\Search",
          "BingSearchEnabled", 0,
          "Stops everything you type into the Start menu being sent to Bing.",
          "Start menu search only finds local files and apps.",
          ),
    Tweak("wifi_sense", "Disable Wi-Fi Sense hotspot reporting", "HKLM",
          r"SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting",
          "Value", 0,
          "Stops Windows reporting open hotspots it sees back to Microsoft.",
          "No impact on normal Wi-Fi use.", admin_required=True),
    Tweak("inking_typing", "Disable inking and typing personalisation", "HKCU",
          r"Software\Microsoft\InputPersonalization",
          "RestrictImplicitTextCollection", 1,
          "Stops Windows collecting samples of what you type and write to build "
          "a personal language model.",
          "Typing suggestions become less tailored."),
    Tweak("error_reporting", "Disable Windows Error Reporting", "HKLM",
          r"SOFTWARE\Microsoft\Windows\Windows Error Reporting", "Disabled", 1,
          "Stops crash dumps — which can contain fragments of open documents — "
          "being sent to Microsoft.",
          "Crashes are no longer reported; troubleshooting is harder.",
          admin_required=True),
]

TWEAKS_BY_KEY: Dict[str, Tweak] = {t.key: t for t in TWEAKS}


def audit() -> List[dict]:
    """Report every tweak's current state for the hardening tab."""
    out = []
    for t in TWEAKS:
        out.append({
            "key": t.key, "title": t.title, "private": t.is_private,
            "current": t.read(), "description": t.description,
            "impact": t.impact, "admin": t.admin_required,
        })
    return out


def apply_tweaks(keys: List[str],
                 progress: Optional[Callable[[str, bool], None]] = None) -> dict:
    ok_count, fail = 0, []
    for key in keys:
        t = TWEAKS_BY_KEY.get(key)
        if not t:
            continue
        ok, msg = t.apply()
        if progress:
            progress(f"{t.title}: {msg}", ok)
        if ok:
            ok_count += 1
        else:
            fail.append(f"{t.title} — {msg}")
    return {"applied": ok_count, "failed": fail}


# ──────────────────────────────────────────────────────────────────────────────
# Telemetry services and scheduled tasks
# ──────────────────────────────────────────────────────────────────────────────

#: Services whose sole job is diagnostics/telemetry.
TELEMETRY_SERVICES = {
    "DiagTrack": ("Connected User Experiences and Telemetry",
                  "The main Windows telemetry service.",
                  "Disabling it is the single biggest telemetry reduction. Some "
                  "enterprise management features rely on it."),
    "dmwappushservice": ("Device Management WAP Push",
                         "Routes WAP push messages used by device management.",
                         "Safe to disable on a personal machine."),
    "diagnosticshub.standardcollector.service": (
        "Diagnostics Hub Standard Collector",
        "Collects diagnostic traces for Visual Studio tooling.",
        "Only matters if you profile applications with Visual Studio."),
    "WerSvc": ("Windows Error Reporting Service",
               "Sends crash reports to Microsoft.",
               "Crashes stop being reported; local troubleshooting is harder."),
    "RetailDemo": ("Retail Demo Service",
                   "Supports store demonstration mode.",
                   "No impact whatsoever outside a retail display unit."),
}


def service_state(name: str) -> dict:
    if not sysinfo.IS_WINDOWS:
        return {"exists": False}
    res = shell.run_powershell(
        f"$s=Get-Service -Name '{name}' -ErrorAction SilentlyContinue;"
        "if($s){$w=Get-CimInstance Win32_Service -Filter \"Name='" + name + "'\";"
        "\"$($s.Status)|$($w.StartMode)\"}else{'MISSING'}", timeout=25)
    txt = res.out.strip()
    if not txt or txt == "MISSING":
        return {"exists": False}
    parts = txt.split("|")
    return {"exists": True, "status": parts[0],
            "start_mode": parts[1] if len(parts) > 1 else ""}


def set_service(name: str, disable: bool) -> tuple:
    """
    Disable or re-enable a service, journalling its prior start mode.

    Prior mode is recorded rather than assumed: restoring DiagTrack to
    "Automatic" when it was "Manual" would be a change in its own right.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required to change services."

    state = service_state(name)
    if not state.get("exists"):
        return False, f"Service '{name}' is not present on this system."

    prior_mode = state.get("start_mode", "Auto")
    journal.record(
        module="hardening",
        action=f"{'Disabled' if disable else 'Enabled'} service '{name}'",
        undo={"kind": "hardening.service_restore", "service": name,
              "prior_mode": prior_mode, "prior_status": state.get("status", "")},
        before=state,
    )

    if disable:
        shell.run(["sc", "stop", name], check_rc=False, timeout=40)
        res = shell.run(["sc", "config", name, "start=", "disabled"],
                        check_rc=False, timeout=30)
    else:
        res = shell.run(["sc", "config", name, "start=", "auto"],
                        check_rc=False, timeout=30)
        shell.run(["sc", "start", name], check_rc=False, timeout=40)

    ok = res.code == 0
    return ok, (f"Service '{name}' {'disabled' if disable else 'enabled'}."
                if ok else res.text[:200])


@journal.register_undo("hardening.service_restore")
def _undo_service(payload: dict) -> tuple:
    name = payload.get("service", "")
    mode = (payload.get("prior_mode") or "Auto").lower()
    mode_arg = {"auto": "auto", "automatic": "auto", "manual": "demand",
                "disabled": "disabled"}.get(mode, "demand")
    res = shell.run(["sc", "config", name, "start=", mode_arg],
                    check_rc=False, timeout=30)
    if payload.get("prior_status", "").lower() == "running":
        shell.run(["sc", "start", name], check_rc=False, timeout=40)
    return res.code == 0, f"'{name}' start mode restored to {mode_arg}"


TELEMETRY_TASKS = [
    r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    r"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    r"\Microsoft\Windows\Application Experience\StartupAppTask",
    r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    r"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    r"\Microsoft\Windows\Feedback\Siuf\DmClient",
    r"\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
    r"\Microsoft\Windows\Windows Error Reporting\QueueReporting",
    r"\Microsoft\Windows\Autochk\Proxy",
]


def task_state(path: str) -> str:
    if not sysinfo.IS_WINDOWS:
        return "unknown"
    res = shell.run(["schtasks", "/query", "/tn", path, "/fo", "list"],
                    check_rc=False, timeout=25)
    if "ERROR" in res.text.upper() or not res.out.strip():
        return "missing"
    m = re.search(r"Status:\s*(.+)", res.out)
    return m.group(1).strip() if m else "unknown"


def set_task(path: str, disable: bool) -> tuple:
    """Disable or re-enable a scheduled task (never deletes — deletion is not undoable)."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."
    state = task_state(path)
    if state == "missing":
        return False, "Task not present on this system."

    journal.record(
        module="hardening",
        action=f"{'Disabled' if disable else 'Enabled'} scheduled task {path.split(chr(92))[-1]}",
        undo={"kind": "hardening.task_restore", "task": path, "prior": state},
        before={"status": state},
    )
    res = shell.run(["schtasks", "/change", "/tn", path,
                     "/disable" if disable else "/enable"], check_rc=False, timeout=25)
    ok = res.code == 0 or "SUCCESS" in res.out.upper()
    return ok, (f"Task {'disabled' if disable else 'enabled'}." if ok else res.text[:180])


@journal.register_undo("hardening.task_restore")
def _undo_task(payload: dict) -> tuple:
    path = payload.get("task", "")
    prior = (payload.get("prior") or "").lower()
    flag = "/disable" if "disabled" in prior else "/enable"
    res = shell.run(["schtasks", "/change", "/tn", path, flag],
                    check_rc=False, timeout=25)
    return (res.code == 0 or "SUCCESS" in res.out.upper()), "scheduled task restored"


# ──────────────────────────────────────────────────────────────────────────────
# Hosts-file blackhole
# ──────────────────────────────────────────────────────────────────────────────

#: Telemetry and tracking endpoints. Deliberately conservative — domains that
#: also carry activation, updates, or licensing are excluded, because blocking
#: those breaks Windows in ways that are hard to diagnose later.
TELEMETRY_DOMAINS = [
    "vortex.data.microsoft.com", "vortex-win.data.microsoft.com",
    "telecommand.telemetry.microsoft.com", "telemetry.microsoft.com",
    "watson.telemetry.microsoft.com", "watson.ppe.telemetry.microsoft.com",
    "telemetry.appex.bing.net", "telemetry.urs.microsoft.com",
    "settings-sandbox.data.microsoft.com", "vortex-sandbox.data.microsoft.com",
    "survey.watson.microsoft.com", "watson.live.com",
    "oca.telemetry.microsoft.com", "sqm.telemetry.microsoft.com",
    "redir.metaservices.microsoft.com", "choice.microsoft.com",
    "df.telemetry.microsoft.com", "reports.wes.df.telemetry.microsoft.com",
    "services.wes.df.telemetry.microsoft.com", "sqm.df.telemetry.microsoft.com",
    "telemetry.remoteapp.windows.com", "wes.df.telemetry.microsoft.com",
    "feedback.windows.com", "feedback.microsoft-hohm.com",
    "feedback.search.microsoft.com", "diagnostics.support.microsoft.com",
    "corp.sts.microsoft.com", "statsfe1.ws.microsoft.com",
    "statsfe2.ws.microsoft.com", "statsfe2.update.microsoft.com.akadns.net",
    "cs1.wpc.v0cdn.net", "a-0001.a-msedge.net",
    # Third-party advertising and analytics
    "doubleclick.net", "www.doubleclick.net", "googleadservices.com",
    "pagead2.googlesyndication.com", "googlesyndication.com",
    "google-analytics.com", "www.google-analytics.com", "ssl.google-analytics.com",
    "scorecardresearch.com", "b.scorecardresearch.com",
    "adnxs.com", "ib.adnxs.com", "criteo.com", "static.criteo.net",
    "taboola.com", "cdn.taboola.com", "outbrain.com", "widgets.outbrain.com",
    "app-measurement.com", "graph.facebook.com", "connect.facebook.net",
    "analytics.twitter.com", "ads-twitter.com",
    "mixpanel.com", "api.mixpanel.com", "amplitude.com", "api.amplitude.com",
    "hotjar.com", "static.hotjar.com", "fullstory.com",
    "segment.io", "api.segment.io", "cdn.segment.com",
    "branch.io", "api.branch.io", "adjust.com", "app.adjust.com",
    "flurry.com", "data.flurry.com", "inmobi.com",
    "chartbeat.com", "static.chartbeat.com", "quantserve.com",
    "moatads.com", "rubiconproject.com", "pubmatic.com", "openx.net",
    "bluekai.com", "demdex.net", "everesttech.net", "omtrdc.net",
]


def hosts_blocked_count() -> int:
    """How many domains PrivacyKit currently blocks in the hosts file."""
    try:
        text = HOSTS_PATH.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    block = _extract_block(text)
    return len([l for l in block.splitlines() if l.strip() and not l.startswith("#")])


def _extract_block(text: str) -> str:
    if BLOCK_BEGIN not in text or BLOCK_END not in text:
        return ""
    return text.split(BLOCK_BEGIN, 1)[1].split(BLOCK_END, 1)[0]


def _strip_block(text: str) -> str:
    if BLOCK_BEGIN not in text or BLOCK_END not in text:
        return text
    head, rest = text.split(BLOCK_BEGIN, 1)
    _, tail = rest.split(BLOCK_END, 1)
    return (head.rstrip("\n") + "\n" + tail.lstrip("\n")).rstrip() + "\n"


def apply_hosts_blocklist(domains: Optional[List[str]] = None) -> tuple:
    """
    Add the telemetry blocklist to the hosts file.

    The whole original file is copied to the backups folder first and the path
    recorded in the journal, so undo restores it byte for byte rather than
    trying to surgically reverse an edit.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required to edit the hosts file."

    domains = domains or TELEMETRY_DOMAINS
    try:
        original = HOSTS_PATH.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return False, f"Cannot read the hosts file: {exc}"

    backup = sysinfo.backups_dir() / f"hosts.{int(time.time())}.bak"
    try:
        shutil.copy2(HOSTS_PATH, backup)
    except Exception as exc:
        return False, f"Refusing to edit the hosts file — backup failed: {exc}"

    journal.record(
        module="hardening",
        action=f"Blocked {len(domains)} telemetry domains in the hosts file",
        undo={"kind": "hardening.hosts_restore", "backup": str(backup)},
        before={"backup": str(backup), "had_block": BLOCK_BEGIN in original},
    )

    body = _strip_block(original).rstrip() + "\n\n" + BLOCK_BEGIN + "\n"
    body += f"# Added {time.strftime('%Y-%m-%d %H:%M')} — remove via PrivacyKit\n"
    for d in sorted(set(domains)):
        body += f"0.0.0.0 {d}\n"
    body += BLOCK_END + "\n"

    try:
        HOSTS_PATH.write_text(body, encoding="utf-8")
    except Exception as exc:
        return False, f"Could not write the hosts file: {exc}"

    shell.run(["ipconfig", "/flushdns"], check_rc=False)
    return True, (f"{len(set(domains))} telemetry domains blocked. "
                  f"Original hosts file backed up to {backup.name}.")


def remove_hosts_blocklist() -> tuple:
    """Remove only PrivacyKit's block, leaving other hosts entries untouched."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."
    try:
        text = HOSTS_PATH.read_text(encoding="utf-8", errors="replace")
        if BLOCK_BEGIN not in text:
            return True, "No PrivacyKit block found in the hosts file."
        HOSTS_PATH.write_text(_strip_block(text), encoding="utf-8")
        shell.run(["ipconfig", "/flushdns"], check_rc=False)
        for e in journal.pending():
            if e.undo.get("kind") == "hardening.hosts_restore":
                journal.mark_undone(e.id)
        return True, "Telemetry blocklist removed from the hosts file."
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


@journal.register_undo("hardening.hosts_restore")
def _undo_hosts(payload: dict) -> tuple:
    backup = payload.get("backup", "")
    if backup and Path(backup).exists():
        try:
            shutil.copy2(backup, HOSTS_PATH)
            shell.run(["ipconfig", "/flushdns"], check_rc=False)
            return True, "hosts file restored from backup"
        except Exception as exc:
            return False, f"restore failed: {exc}"
    # No backup — fall back to stripping our marked block, which is still safe.
    return remove_hosts_blocklist()


def snapshot() -> dict:
    return {
        "tweaks": {t.key: t.read() for t in TWEAKS},
        "services": {n: service_state(n) for n in TELEMETRY_SERVICES},
        "hosts_blocked": hosts_blocked_count(),
    }
