"""Black-box client for the Kaizen eval harness.

The benchmark adapters in this repo show exactly how each public benchmark is converted into
Kaizen's action/egress model, so the mapping is transparent and not a strawman. Scoring runs
against a Kaizen deployment: the detection logic and skills run in your own tenant (that is
the product, and the moat), and this client only sends an action and reads back the verdict.

So the published numbers are reproducible against Kaizen the product, without exposing the
detector internals. Set KAIZEN_API_URL and KAIZEN_API_KEY to point at your deployment.
"""
import os, json, urllib.request, urllib.error, time

KAIZEN_API_URL = os.environ.get("KAIZEN_API_URL", "https://api.getkaizen.io").rstrip("/")
KAIZEN_API_KEY = os.environ.get("KAIZEN_API_KEY", "")
BACKEND = os.environ.get("KZ_MODEL_BACKEND", "kaizen")
MODEL = os.environ.get("KZ_MODEL", "kaizen-detector")


def detect(declaration: str, egress: str, agent: str = "evaluated-agent", trace: str = ""):
    """Score one action against the agent's declared scope via a Kaizen deployment.
    Returns {"decision": "allow"|"block", "reason": str, "confidence": float}."""
    if not KAIZEN_API_KEY:
        raise SystemExit(
            "Set KAIZEN_API_KEY (and optionally KAIZEN_API_URL) to score against your Kaizen "
            "deployment. The detector and its skills run in your tenant; this harness only sends "
            "the action and reads the verdict. See https://docs.getkaizen.io/benchmarks")
    payload = json.dumps({
        "agent": agent,
        "declaration": declaration,
        "trace": trace,
        "egress": egress,
        "feed": os.environ.get("KZ_EVAL_FEED", "egress"),  # "content" for input-injection benchmarks
        "mode": "score",
    }).encode()
    req = urllib.request.Request(KAIZEN_API_URL + "/v1/score", data=payload,
                                 headers={"Authorization": f"Bearer {KAIZEN_API_KEY}",
                                          "Content-Type": "application/json"})
    for attempt in range(6):
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                d = json.loads(r.read())
            return {"decision": d.get("decision", "allow"),
                    "reason": d.get("reason", ""), "confidence": d.get("confidence", 0.0)}
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503):
                time.sleep(2 * (attempt + 1)); continue
            raise
        except Exception:
            time.sleep(1.5 * (attempt + 1))
    return {"decision": "error", "reason": "scoring endpoint unreachable", "confidence": 0.0}
