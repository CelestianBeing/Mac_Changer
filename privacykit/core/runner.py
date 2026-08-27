"""
Executes the action lists that make up a custom profile.

Kept separate from :mod:`privacykit.core.presets` because a preset is a fixed
sequence written by us, whereas a custom profile is data the user assembled in
the editor. Both end up here so they behave identically: every step journalled,
a failing step never aborting the rest.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple


def _dispatch(action: str, args: dict, adapter: str) -> Tuple[bool, str]:
    from . import (cleaner, dnsconf, firewall, geo, hardening, hostname,
                   ipconf, journal, mac, noise, proxy, tor)

    if action == "mac.spoof":
        if not adapter:
            return False, "no adapter selected"
        new_mac, desc = mac.generate(args.get("mode", "vendor"))
        res = mac.set_mac(adapter, new_mac)
        return res.ok, res.message
    if action == "mac.restore":
        res = mac.restore_mac(adapter)
        return res.ok, res.message
    if action == "dns.provider":
        return dnsconf.set_provider(adapter, args.get("provider", "cloudflare"),
                                    bool(args.get("doh", True)))
    if action == "dns.automatic":
        return dnsconf.set_automatic(adapter)
    if action == "dns.flush":
        return dnsconf.flush_cache()
    if action == "hostname.randomise":
        return hostname.set_hostname(hostname.generate(args.get("style", "windows")))
    if action == "ip.renew":
        return ipconf.release_renew(adapter)
    if action == "tor.route":
        st = tor.detect()
        if not st.running:
            return False, "Tor is not running"
        return proxy.route_through_tor(st.socks_port)
    if action == "tor.newnym":
        return tor.new_identity()
    if action == "proxy.off":
        return proxy.disable_proxy()
    if action == "firewall.killswitch":
        st = tor.detect()
        return firewall.arm_killswitch(st.socks_port or 9050,
                                       bool(args.get("allow_lan", False)))
    if action == "firewall.disarm":
        return firewall.disarm_killswitch()
    if action == "firewall.lan":
        return firewall.block_lan(True)
    if action == "firewall.smb":
        return firewall.block_smb(True)
    if action == "firewall.llmnr":
        return firewall.set_llmnr(False)
    if action == "firewall.ipv6":
        return firewall.set_ipv6(adapter, False)
    if action == "geo.match":
        from . import leaks
        info = leaks.public_ip(via_tor=tor.is_running(),
                               socks_port=tor.detect().socks_port or 9050)
        country = (info.get("country") or "").lower()
        if not country:
            return False, "could not determine the country of your exit IP"
        result = geo.apply_country(country)
        return result["ok"], result["message"]
    if action == "geo.country":
        result = geo.apply_country(args.get("country", ""))
        return result["ok"], result["message"]
    if action == "noise.rotate":
        r = noise.rotate_all()
        return r["rotated"] > 0, f"{r['rotated']} identifier(s) rotated"
    if action == "noise.start":
        return noise.generator.start()
    if action == "hardening.tweaks":
        keys = ([t.key for t in hardening.TWEAKS] if args.get("set") == "all"
                else ["advertising_id", "tailored_experiences",
                      "app_launch_tracking", "feedback_frequency", "web_search",
                      "inking_typing", "activity_feed"])
        r = hardening.apply_tweaks(keys)
        return r["applied"] > 0, f"{r['applied']} tweak(s) applied"
    if action == "hardening.hosts":
        return hardening.apply_hosts_blocklist()
    if action == "clean.traces":
        keys = ([t.key for t in cleaner.TARGETS] if args.get("set") == "all"
                else cleaner.SAFE_DEFAULTS)
        r = cleaner.clean(keys)
        return True, f"{r['files']} file(s) removed, {r['human']} freed"
    if action == "restore.all":
        r = journal.panic_restore()
        return True, f"{r['restored']} change(s) reverted"

    return False, f"unknown action '{action}'"


def run_actions(actions: List[Dict], adapter: str = "",
                progress: Optional[Callable[[str, bool], None]] = None) -> dict:
    """
    Run a list of ``{"action": key, "args": {...}}`` steps.

    Failures are recorded and skipped rather than aborting: a profile that half
    applies is more useful than one that stops at the first unavailable feature,
    and the summary makes clear exactly which protections are actually live.
    """
    from . import licensing
    from .settings import ACTIONS_BY_KEY

    done, failed, details = 0, 0, []

    for step in actions:
        key = step.get("action", "")
        args = step.get("args", {}) or {}
        spec = ACTIONS_BY_KEY.get(key)
        label = spec["title"] if spec else key

        if spec and not licensing.has_feature(spec.get("feature", "")):
            line = f"SKIP  {label} — not included in your edition"
            details.append(line)
            if progress:
                progress(line, False)
            continue

        try:
            ok, msg = _dispatch(key, args, adapter)
        except Exception as exc:
            ok, msg = False, f"{type(exc).__name__}: {exc}"

        line = f"{'OK  ' if ok else 'FAIL'}  {label}" + (f" — {msg}" if msg else "")
        details.append(line)
        if progress:
            progress(line, ok)
        if ok:
            done += 1
        else:
            failed += 1

    return {"steps": len(actions), "succeeded": done, "failed": failed,
            "details": details}
