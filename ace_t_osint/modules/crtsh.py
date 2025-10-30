"""
crt.sh OSINT Module
------------------
Monitors new domain registrations related to a trigger pattern.
TODO: Implement actual scraping logic for crt.sh.
"""
import time
import logging
from ace_t_osint.utils import utils

def monitor_crtsh(triggers, interval=180):
    print("[crtsh] monitor_crtsh started")
    """Stub: Monitor crt.sh for new domain registrations matching triggers."""
    # TODO: Implement actual scraping logic
    try:
        while True:
            # Simulate domain registration monitoring
            domain = "example.com"
            # Support multiple trigger formats. Triggers may be a list of dicts
            # with keys like 'pattern' or 'include', or legacy format.
            for trig in triggers:
                try:
                    # Normalize trigger to a dict-like structure
                    if isinstance(trig, str):
                        patterns = [trig]
                        severity = "medium"
                        trigger_id = trig
                        context = ""
                    elif isinstance(trig, dict):
                        # patterns can be a single 'pattern' or a list under 'include'
                        if "pattern" in trig:
                            patterns = [trig.get("pattern")]
                        elif "include" in trig and isinstance(trig.get("include"), list):
                            patterns = trig.get("include")
                        else:
                            patterns = []
                        severity = str(trig.get("severity", trig.get("level", "medium")))
                        trigger_id = trig.get("trigger_id", trig.get("id", "unknown"))
                        context = trig.get("context", trig.get("description", ""))
                    else:
                        # Unknown trigger type; skip
                        continue

                    # Check patterns against the observed domain
                    matched = False
                    for p in patterns:
                        if not p:
                            continue
                        # simple substring match; regex support could be added
                        if p in domain:
                            matched = True
                            break
                    if matched:
                        meta = {
                            "title": f"crt.sh domain {domain}",
                            "domain": domain,
                            "source": "crtsh"
                        }
                        utils.log_signal(
                            source="crtsh",
                            signal_type="triggered_content",
                            severity=severity,
                            trigger_id=trigger_id,
                            context=f"crt.sh domain {domain}: {context}",
                            extra_data=meta
                        )
                        print("[crtsh] Alert logged!")
                except Exception:
                    # Isolate trigger-level errors and continue
                    logging.exception("[crtsh] Failed processing trigger")
            time.sleep(interval)
    except Exception as e:
        logging.error(f"[crtsh] Error: {e}")
