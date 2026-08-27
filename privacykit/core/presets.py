"""
One-click profiles that apply a coherent set of changes at once.

The value of a preset is not saving clicks — it is that the individual settings
interact. Arming a kill switch without starting Tor just breaks your internet;
spoofing a MAC while leaving the hostname untouched barely helps. A preset is a
combination that makes sense together.

Each preset declares exactly what it will do so the confirmation dialog can
list it before anything runs, and every step it takes is journalled
individually, so Panic Restore unwinds a preset the same way it unwinds manual
changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class Step:
    label: str
    run: Callable[[], tuple]
    requires_admin: bool = True
    optional: bool = False       # failure does not fail the preset


@dataclass
class Preset:
    key: str
    name: str
    icon: str
    tagline: str
    description: str
    changes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    accent: str = "#58a6ff"


PRESETS = {
    "public_wifi": Preset(
        "public_wifi", "Public Wi-Fi", "☕",
        "Café, airport, hotel — an untrusted network",
        "Hardens the machine for a network where you do not trust the other "
        "people on it. Focuses on not being identifiable and not being "
        "reachable, without breaking normal browsing.",
        changes=[
            "Spoof the MAC address of your active adapter (vendor-realistic)",
            "Switch DNS to Cloudflare with DNS-over-HTTPS",
            "Disable LLMNR (blocks credential-harvesting on shared networks)",
            "Block inbound SMB/NetBIOS file-sharing ports",
            "Isolate the machine from the local subnet",
            "Flush the DNS cache",
        ],
        warnings=["Network printers and shared drives stop working until you "
                  "switch back."],
        accent="#58a6ff",
    ),
    "max_privacy": Preset(
        "max_privacy", "Maximum Privacy", "🛡",
        "Everything on — expect things to break",
        "The strongest posture this toolkit can apply. Routes traffic through "
        "Tor with a kill switch behind it, so a Tor failure stops traffic "
        "rather than leaking it.",
        changes=[
            "Spoof MAC address and randomise the computer name",
            "Switch DNS to Mullvad with DNS-over-HTTPS",
            "Route system traffic through Tor",
            "Arm the outbound kill switch",
            "Disable IPv6 on the active adapter (prevents tunnel bypass)",
            "Disable LLMNR and block SMB",
            "Apply all Windows privacy tweaks and the telemetry blocklist",
        ],
        warnings=[
            "Renaming the computer needs a restart to take full effect.",
            "The kill switch will break any application that ignores the proxy.",
            "Tor must already be running or nothing will reach the internet.",
        ],
        accent="#f85149",
    ),
    "everyday": Preset(
        "everyday", "Everyday Sensible", "🏠",
        "Better defaults with nothing broken",
        "The changes worth leaving on permanently. Nothing here interferes with "
        "printers, games, video calls, or corporate VPNs.",
        changes=[
            "Switch DNS to Quad9 with DNS-over-HTTPS",
            "Apply the low-impact Windows privacy tweaks",
            "Block telemetry and ad domains in the hosts file",
            "Disable the advertising ID and activity history",
            "Flush the DNS cache",
        ],
        warnings=[],
        accent="#3fb950",
    ),
    "clean_exit": Preset(
        "clean_exit", "Clean Exit", "🧹",
        "Wipe today's traces and hand the machine back",
        "Clears the artefacts that reveal what you did on this machine, then "
        "reverts every network change PrivacyKit made. Useful on a shared or "
        "borrowed computer.",
        changes=[
            "Clear temp files, Recent documents, jump lists, and thumbnails",
            "Clear the DNS cache, clipboard, and Run dialog history",
            "Clear PowerShell command history and crash dumps",
            "Restore all network settings to their originals",
        ],
        warnings=["Cleaning deletes files permanently — this part cannot be undone."],
        accent="#e3b341",
    ),
}

PRESET_ORDER = ["everyday", "public_wifi", "max_privacy", "clean_exit"]


def build_steps(key: str, adapter: str = "") -> List[Step]:
    """Assemble the concrete step list for a preset."""
    from . import (cleaner, dnsconf, firewall, hardening, hostname,
                   journal, mac, proxy, tor)

    steps: List[Step] = []

    def mac_step(mode: str = "vendor"):
        def run():
            new_mac, _desc = mac.generate(mode)
            res = mac.set_mac(adapter, new_mac)
            return res.ok, res.message
        return run

    if key == "public_wifi":
        if adapter:
            steps.append(Step(f"Spoof MAC on '{adapter}'", mac_step()))
            steps.append(Step("DNS → Cloudflare with DoH",
                              lambda: dnsconf.set_provider(adapter, "cloudflare", True)))
        steps.append(Step("Disable LLMNR", lambda: firewall.set_llmnr(False)))
        steps.append(Step("Block SMB/NetBIOS", lambda: firewall.block_smb(True)))
        steps.append(Step("Isolate from local network", lambda: firewall.block_lan(True)))
        steps.append(Step("Flush DNS cache", dnsconf.flush_cache, requires_admin=False))

    elif key == "max_privacy":
        if adapter:
            steps.append(Step(f"Spoof MAC on '{adapter}'", mac_step()))
            steps.append(Step("DNS → Mullvad with DoH",
                              lambda: dnsconf.set_provider(adapter, "mullvad", True)))
            steps.append(Step("Disable IPv6 on the adapter",
                              lambda: firewall.set_ipv6(adapter, False)))
        steps.append(Step("Randomise computer name",
                          lambda: hostname.set_hostname(hostname.generate("windows"))))

        def route_tor():
            st = tor.detect()
            if not st.running:
                return False, ("Tor is not running — start Tor Browser or the Tor "
                               "service first, then re-run this preset.")
            return proxy.route_through_tor(st.socks_port)
        steps.append(Step("Route system traffic through Tor", route_tor))

        def arm():
            st = tor.detect()
            return firewall.arm_killswitch(st.socks_port or 9050)
        steps.append(Step("Arm the kill switch", arm))
        steps.append(Step("Disable LLMNR", lambda: firewall.set_llmnr(False)))
        steps.append(Step("Block SMB/NetBIOS", lambda: firewall.block_smb(True)))

        def all_tweaks():
            r = hardening.apply_tweaks([t.key for t in hardening.TWEAKS])
            return r["applied"] > 0, f"{r['applied']} privacy tweak(s) applied"
        steps.append(Step("Apply all Windows privacy tweaks", all_tweaks))
        steps.append(Step("Block telemetry domains",
                          lambda: hardening.apply_hosts_blocklist(), optional=True))

    elif key == "everyday":
        if adapter:
            steps.append(Step("DNS → Quad9 with DoH",
                              lambda: dnsconf.set_provider(adapter, "quad9", True)))

        low_impact = ["advertising_id", "tailored_experiences", "app_launch_tracking",
                      "feedback_frequency", "web_search", "inking_typing",
                      "activity_feed", "publish_activities", "upload_activities"]

        def tweaks():
            r = hardening.apply_tweaks(low_impact)
            return r["applied"] > 0, f"{r['applied']} privacy tweak(s) applied"
        steps.append(Step("Apply low-impact privacy tweaks", tweaks))
        steps.append(Step("Block telemetry and ad domains",
                          lambda: hardening.apply_hosts_blocklist(), optional=True))
        steps.append(Step("Flush DNS cache", dnsconf.flush_cache, requires_admin=False))

    elif key == "clean_exit":
        def do_clean():
            r = cleaner.clean(cleaner.SAFE_DEFAULTS)
            return True, f"{r['files']} file(s) removed, {r['human']} freed"
        steps.append(Step("Clear local traces", do_clean, requires_admin=False))

        def restore_all():
            r = journal.panic_restore(modules=["mac", "ip", "dns", "proxy",
                                               "firewall", "hostname", "hardening"])
            return True, (f"{r['restored']} change(s) reverted"
                          + (f", {r['failed']} failed" if r['failed'] else ""))
        steps.append(Step("Restore all network settings", restore_all))

    return steps


def apply(key: str, adapter: str = "",
          progress: Optional[Callable[[str, bool], None]] = None) -> dict:
    """
    Run a preset.

    A failing step does not abort the run: if Tor is not available, the DNS and
    firewall hardening in the same preset are still worth having. The summary
    reports exactly what succeeded so the user is never misled about which
    protections are actually active.
    """
    steps = build_steps(key, adapter)
    done, failed, details = 0, 0, []

    for step in steps:
        if progress:
            progress(f"→ {step.label}…", True)
        try:
            ok, msg = step.run()
        except Exception as exc:
            ok, msg = False, f"{type(exc).__name__}: {exc}"
        line = f"{'OK  ' if ok else 'FAIL'}  {step.label}" + (f" — {msg}" if msg else "")
        details.append(line)
        if progress:
            progress(line, ok)
        if ok:
            done += 1
        elif not step.optional:
            failed += 1

    return {"preset": key, "steps": len(steps), "succeeded": done,
            "failed": failed, "details": details}
