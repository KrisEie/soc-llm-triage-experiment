# export_suricata_alerts_proxy.py
import os
import json
import argparse
import base64
from typing import List, Dict, Any, Tuple

import requests
from dotenv import load_dotenv

# ---------- Konfig ----------

load_dotenv()

MALCOLM_URL = os.getenv("MALCOLM_URL")       # f.eks. https://10.225.211.201
MALCOLM_USER = os.getenv("MALCOLM_USER")
MALCOLM_PASS = os.getenv("MALCOLM_PASS")

for k, v in {
    "MALCOLM_URL": MALCOLM_URL,
    "MALCOLM_USER": MALCOLM_USER,
    "MALCOLM_PASS": MALCOLM_PASS,
}.items():
    if not v:
        raise RuntimeError(f"Mangler env var: {k} (legg i .env)")

# Selvsignert TLS i lab
requests.packages.urllib3.disable_warnings()
VERIFY_TLS = False


def make_session() -> requests.Session:
    """
    Session med Basic Auth (samme som nettleser-popup) og headers for Dashboards-proxy.
    """
    s = requests.Session()
    s.verify = VERIFY_TLS
    s.auth = (MALCOLM_USER, MALCOLM_PASS)  # Basic Auth
    s.headers.update({
        "Content-Type": "application/json",
        "osd-xsrf": "true",
        "securitytenant": "global",
    })
    return s


def login_dashboards(s: requests.Session) -> None:
    """
    NO-OP her: Dashboards bruker Basic Auth via nginx.
    """
    return


# ---------- Hjelper: kall OpenSearch via Dashboards-proxy ----------

def os_proxy_search(s: requests.Session, body: Dict[str, Any]) -> Dict[str, Any]:
    """
    _search mot arkime_sessions3-* via Dashboards-proxy.
    """
    url = f"{MALCOLM_URL}/dashboards/api/console/proxy"
    params = {
        "path": "arkime_sessions3-*/_search",
        "method": "POST",
    }
    r = s.post(url, params=params, data=json.dumps(body), timeout=60)
    if r.status_code != 200:
        raise RuntimeError(
            f"OpenSearch proxy-kall feilet: HTTP {r.status_code}, body={r.text[:500]}"
        )
    return r.json()


# ---------- Payload-dekoding ----------

def decode_payload(b64: str | None) -> str:
    if not b64:
        return ""
    try:
        raw = base64.b64decode(b64)
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return raw.decode("latin-1", errors="replace")
    except Exception:
        return ""


# ---------- Query mot OpenSearch ----------

def query_suricata_alerts(
    start_iso: str | None,
    end_iso: str | None,
    size: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Henter Suricata alerts:
      - event.module = "suricata"
      - event.kind   = "alert" ELLER event.dataset = "alert"
      - @timestamp   mellom start_iso og end_iso (hvis satt)

    Returnerer fullverdige hits (med _id og _source) for dedupe.
    """
    s = make_session()
    login_dashboards(s)

    must_clauses: List[Dict[str, Any]] = [
        {"term": {"event.module": "suricata"}},
        {
            "bool": {
                "should": [
                    {"term": {"event.kind": "alert"}},
                    {"term": {"event.dataset": "alert"}}
                ],
                "minimum_should_match": 1
            }
        }
    ]

    # Tidsfilter på @timestamp
    if start_iso or end_iso:
        rng: Dict[str, Any] = {"range": {"@timestamp": {}}}
        if start_iso:
            rng["range"]["@timestamp"]["gte"] = start_iso
        if end_iso:
            rng["range"]["@timestamp"]["lte"] = end_iso
        must_clauses.append(rng)

    body = {
        "size": size,
        "_source": [
            "@timestamp",
            "event.*",
            "rule.*",
            "source.*",
            "destination.*",
            "network.*",
            "host.*",
            "suricata.*",
        ],
        "sort": [
            {"@timestamp": {"order": "asc"}}
        ],
        "query": {
            "bool": {
                "must": must_clauses
            }
        }
    }

    js = os_proxy_search(s, body)
    hits = (js.get("hits") or {}).get("hits") or []
    return hits  # behold _id for dedupe


def build_row(src: Dict[str, Any], docid: str | None) -> Dict[str, Any]:
    ev   = src.get("event") or {}
    rule = src.get("rule") or {}
    srcip = src.get("source") or {}
    dstip = src.get("destination") or {}
    net  = src.get("network") or {}
    host = src.get("host") or {}
    suri = src.get("suricata") or {}
    http = suri.get("http") if isinstance(suri, dict) else None

    payload_b64 = suri.get("payload") if isinstance(suri, dict) else None
    payload_text = decode_payload(payload_b64)

    # event.id kan komme som liste
    ev_id = ev.get("id")
    if isinstance(ev_id, list) and ev_id:
        ev_id = ev_id[0]

    return {
        "_id": docid,
        "@timestamp": src.get("@timestamp"),
        "event": {
            "id": ev_id,
            "kind": ev.get("kind"),
            "dataset": ev.get("dataset"),
            "module": ev.get("module"),
            "severity": ev.get("severity"),
            "risk_score": ev.get("risk_score"),
            "risk_score_norm": ev.get("risk_score_norm"),
            "severity_tags": ev.get("severity_tags"),
        },
        "rule": {
            "id": rule.get("id"),
            "name": rule.get("name"),
            "category": rule.get("category"),
        },
        "source": {
            "ip": srcip.get("ip"),
            "port": srcip.get("port"),
        },
        "destination": {
            "ip": dstip.get("ip"),
            "port": dstip.get("port"),
        },
        "network": {
            "protocol": net.get("protocol"),
            "transport": net.get("transport"),
            "application": net.get("application"),
            "bytes": net.get("bytes"),
            "packets": net.get("packets"),
            "direction": net.get("direction"),
        },
        "host": {
            "name": host.get("name"),
            "ip": host.get("ip"),
            "os": host.get("os"),
        },
        "suricata": {
            "alert": (suri.get("alert") if isinstance(suri.get("alert"), dict) else suri.get("alert")),
            "http": http,
            "payload_base64": payload_b64,
            "payload_text": payload_text,
            "flow": suri.get("flow"),
            "flow_id": suri.get("flow_id"),
            "timestamp": suri.get("timestamp"),
            "direction": suri.get("direction"),
        },
    }


def dedupe_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Fjern duplikater på dokument-ID og i tillegg på logisk nøkkel:
      (@timestamp, rule.name, suricata.flow_id, source.ip, destination.ip)
    """
    seen_docids = set()
    seen_keys: set[Tuple[Any, Any, Any, Any, Any]] = set()
    out: List[Dict[str, Any]] = []
    for r in rows:
        docid = r.get("_id")
        if docid:
            if docid in seen_docids:
                continue
            seen_docids.add(docid)

        key = (
            r.get("@timestamp"),
            (r.get("rule") or {}).get("name"),
            (r.get("suricata") or {}).get("flow_id"),
            (r.get("source") or {}).get("ip"),
            (r.get("destination") or {}).get("ip"),
        )
        if key in seen_keys:
            continue
        seen_keys.add(key)
        out.append(r)
    return out


# ---------- Main: eksporter til JSONL ----------

def main():
    ap = argparse.ArgumentParser(
        description="Eksporter Suricata Alerts (arkime_sessions3-*) via Dashboards proxy til JSONL."
    )
    ap.add_argument(
        "--start",
        type=str,
        required=True,
        help='Start-tid (UTC ISO8601), f.eks. "2025-11-11T11:09:42.692Z".'
    )
    ap.add_argument(
        "--end",
        type=str,
        required=True,
        help='Slutt-tid (UTC ISO8601), f.eks. "2025-11-11T11:47:40.630Z".'
    )
    ap.add_argument(
        "--size",
        type=int,
        default=5000,
        help="Maks antall alerts som hentes (default: 5000)."
    )
    ap.add_argument(
        "--out",
        type=str,
        default="suricata_alerts_proxy.jsonl",
        help="Filnavn for JSONL-output (overskrives)."
    )

    args = ap.parse_args()

    print("[INFO] Henter Suricata Alerts fra OpenSearch via Dashboards-proxy...")
    hits = query_suricata_alerts(
        start_iso=args.start,
        end_iso=args.end,
        size=args.size,
    )
    print(f"[INFO] Råtreff: {len(hits)}")

    # Flatten + dedupe før skriving
    rows: List[Dict[str, Any]] = []
    for h in hits:
        src = h.get("_source", {}) or {}
        docid = h.get("_id")
        rows.append(build_row(src, docid))

    rows = dedupe_rows(rows)
    print(f"[INFO] Etter dedupe: {len(rows)} alerts.")

    out_path = args.out
    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            # fjern _id i output hvis du ikke vil ha den med i fila
            r_out = dict(r)
            r_out.pop("_id", None)
            f.write(json.dumps(r_out, ensure_ascii=False) + "\n")

    print(f"[INFO] Skrev {len(rows)} alerts til: {out_path}")


if __name__ == "__main__":
    main()
