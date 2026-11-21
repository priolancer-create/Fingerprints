#!/usr/bin/env python3
# CYBERX OSINT INTELLIGENCE V3.0
# Authorized, public-source OSINT helper for Android Termux / Linux.
# No password discovery, private-account access, breach dumps, or covert collection.

import argparse
import hashlib
import html
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests
from flask import Flask, jsonify, request, render_template_string

APP_NAME = "CYBERX OSINT INTELLIGENCE"
VERSION = "3.0"
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
REPORT_DIR = ROOT / "reports"
DB_PATH = DATA_DIR / "cyberx.db"
DATA_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

TIMEOUT = 12
HEADERS = {
    "User-Agent": "CYBERX-OSINT-Community/3.0 (public-source research; contact: admin@example.invalid)",
    "Accept": "application/json, text/plain, */*",
}
app = Flask(__name__)

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            query_type TEXT NOT NULL,
            query_value TEXT NOT NULL,
            result_json TEXT NOT NULL
        )""")

def save_search(kind, value, result):
    with db() as conn:
        conn.execute(
            "INSERT INTO searches(created_at,query_type,query_value,result_json) VALUES(?,?,?,?)",
            (now_iso(), kind, value, json.dumps(result, ensure_ascii=False))
        )

def clean_input(value, max_len=254):
    value = str(value or "").strip()
    if not value or len(value) > max_len:
        raise ValueError(f"Input must be 1-{max_len} characters.")
    if any(ord(c) < 32 for c in value):
        raise ValueError("Control characters are not allowed.")
    return value

def email_intel(email):
    email = clean_input(email, 254).lower()
    result = {"type": "email", "query": email, "checked_at": now_iso(), "findings": [], "warnings": []}
    pattern = r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$"
    if not re.match(pattern, email, re.I):
        raise ValueError("Invalid email address format.")
    local, domain = email.rsplit("@", 1)
    result["format_valid"] = True
    result["domain"] = domain
    result["findings"].append({"source": "Email syntax", "status": "valid", "detail": "Address has a valid-looking email format."})
    result["public_links"] = [
        {"name": "Google search", "url": "https://www.google.com/search?q=" + quote('"' + email + '"')},
        {"name": "DuckDuckGo search", "url": "https://duckduckgo.com/?q=" + quote('"' + email + '"')},
    ]
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=TIMEOUT)
        mx = sorted([(int(a.preference), str(a.exchange).rstrip(".")) for a in answers])
        result["mx_records"] = [{"priority": p, "host": h} for p, h in mx]
        result["findings"].append({"source": "DNS MX", "status": "found", "detail": f"{len(mx)} mail exchanger record(s) found."})
    except ImportError:
        result["warnings"].append("dnspython is not installed; MX lookup skipped.")
    except Exception as exc:
        result["mx_records"] = []
        result["findings"].append({"source": "DNS MX", "status": "not_found_or_unavailable", "detail": str(exc)[:180]})
    try:
        import dns.resolver
        for record_type in ("SPF", "TXT"):
            if record_type == "SPF":
                # SPF is published as a TXT record.
                txts = [str(x).strip('"') for x in dns.resolver.resolve(domain, "TXT", lifetime=TIMEOUT)]
                spf = [x for x in txts if x.lower().startswith("v=spf1")]
                result["spf_records"] = spf
            else:
                txts = [str(x).strip('"') for x in dns.resolver.resolve("_dmarc." + domain, "TXT", lifetime=TIMEOUT)]
                result["dmarc_records"] = [x for x in txts if "v=dmarc1" in x.lower()]
    except Exception:
        result.setdefault("spf_records", [])
        result.setdefault("dmarc_records", [])
    result["note"] = "This checks address syntax and domain mail configuration; it does not confirm that the mailbox exists or belongs to a person."
    return result

def domain_intel(domain):
    domain = clean_input(domain, 253).lower().strip(".")
    if "/" in domain or "@" in domain or " " in domain:
        raise ValueError("Enter a domain only, e.g. example.com.")
    if not re.match(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", domain):
        raise ValueError("Invalid domain format.")
    result = {"type": "domain", "query": domain, "checked_at": now_iso(), "findings": [], "warnings": []}
    try:
        ip = socket.getaddrinfo(domain, None)[0][4][0]
        result["dns_ip"] = ip
        result["findings"].append({"source": "DNS", "status": "resolved", "detail": f"Domain resolves to {ip}."})
    except Exception as exc:
        result["findings"].append({"source": "DNS", "status": "unavailable", "detail": str(exc)[:160]})
    try:
        response = requests.get(f"https://rdap.org/domain/{quote(domain)}", headers=HEADERS, timeout=TIMEOUT)
        if response.ok:
            data = response.json()
            events = data.get("events", [])
            result["rdap"] = {
                "ldh_name": data.get("ldhName"),
                "status": data.get("status", []),
                "events": [{"action": e.get("eventAction"), "date": e.get("eventDate")} for e in events],
                "nameservers": [n.get("ldhName") for n in data.get("nameservers", []) if n.get("ldhName")],
            }
            result["findings"].append({"source": "RDAP", "status": "found", "detail": "Public domain registration data retrieved."})
        else:
            result["warnings"].append(f"RDAP service returned HTTP {response.status_code}.")
    except requests.RequestException as exc:
        result["warnings"].append("RDAP lookup unavailable: " + str(exc)[:140])
    result["public_links"] = [
        {"name": "Google search", "url": "https://www.google.com/search?q=" + quote(domain)},
        {"name": "Certificate Transparency", "url": "https://crt.sh/?q=" + quote("%." + domain)},
        {"name": "DNS lookup", "url": "https://dns.google/resolve?name=" + quote(domain) + "&type=A"},
    ]
    return result

def username_intel(username):
    username = clean_input(username, 39).lstrip("@")
    if not re.match(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$", username):
        raise ValueError("Use a simple username (letters, numbers, and hyphens).")
    result = {"type": "username", "query": username, "checked_at": now_iso(), "findings": [], "profiles": [], "warnings": []}
    # GitHub's documented public user endpoint; one request, no scraping.
    try:
        r = requests.get("https://api.github.com/users/" + quote(username), headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            u = r.json()
            result["profiles"].append({
                "platform": "GitHub", "username": u.get("login"),
                "display_name": u.get("name"), "bio": u.get("bio"),
                "location": u.get("location"), "public_repos": u.get("public_repos"),
                "followers": u.get("followers"), "profile_url": u.get("html_url"),
                "avatar_url": u.get("avatar_url"),
            })
            result["findings"].append({"source": "GitHub public API", "status": "found", "detail": "A matching public GitHub profile was returned."})
        elif r.status_code == 404:
            result["findings"].append({"source": "GitHub public API", "status": "not_found", "detail": "No GitHub user found for this exact username."})
        elif r.status_code == 403:
            result["warnings"].append("GitHub API rate limit or access restriction. Try again later.")
        else:
            result["warnings"].append(f"GitHub API returned HTTP {r.status_code}.")
    except requests.RequestException as exc:
        result["warnings"].append("GitHub lookup unavailable: " + str(exc)[:140])
    result["manual_search_links"] = [
        {"name": "Google exact username search", "url": "https://www.google.com/search?q=" + quote('"' + username + '"')},
        {"name": "DuckDuckGo", "url": "https://duckduckgo.com/?q=" + quote('"' + username + '"')},
        {"name": "GitHub", "url": "https://github.com/" + quote(username)},
        {"name": "Reddit search", "url": "https://www.reddit.com/search/?q=" + quote(username)},
    ]
    result["note"] = "A profile match is not proof that two accounts belong to the same person. Manual verification is required."
    return result

def phone_intel(number, region="BD"):
    number = clean_input(number, 32)
    result = {"type": "phone", "query": number, "region_hint": region, "checked_at": now_iso(), "findings": [], "warnings": []}
    try:
        import phonenumbers
        parsed = phonenumbers.parse(number, region or None)
        result["possible"] = phonenumbers.is_possible_number(parsed)
        result["valid"] = phonenumbers.is_valid_number(parsed)
        result["international"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        result["e164"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        result["country_code"] = parsed.country_code
        result["national_number"] = str(parsed.national_number)
        try:
            from phonenumbers import geocoder, carrier
            result["country_or_region"] = geocoder.description_for_number(parsed, "en")
            result["carrier_hint"] = carrier.name_for_number(parsed, "en") or None
        except Exception:
            pass
        result["findings"].append({"source": "libphonenumber metadata", "status": "valid" if result["valid"] else "invalid_or_unassigned", "detail": "Number format and numbering-plan metadata checked."})
        result["note"] = "Phone metadata may be incomplete or outdated. It does not reveal a subscriber's identity or live location."
    except ImportError:
        raise ValueError("Install phonenumbers first: pip install phonenumbers")
    except Exception as exc:
        raise ValueError("Could not parse phone number. Include country code or set region. " + str(exc)[:120])
    return result

def analyze(kind, value, region="BD"):
    if kind == "email":
        result = email_intel(value)
    elif kind == "domain":
        result = domain_intel(value)
    elif kind == "username":
        result = username_intel(value)
    elif kind == "phone":
        result = phone_intel(value, region)
    else:
        raise ValueError("Type must be email, domain, username, or phone.")
    # Conservative score: counts evidence items, not identity certainty.
    found = sum(1 for x in result.get("findings", []) if x.get("status") in ("found", "valid", "resolved"))
    result["evidence_score"] = min(100, found * 25)
    result["score_explanation"] = "Heuristic source-coverage indicator only; not an identity or ownership probability."
    save_search(kind, value, result)
    return result

def write_report(result, fmt="json"):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(result.get("query", "query")))[:45]
    if fmt == "json":
        path = REPORT_DIR / f"{safe}_{stamp}.json"
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        path = REPORT_DIR / f"{safe}_{stamp}.html"
        path.write_text(render_report(result), encoding="utf-8")
    return str(path)

def render_report(data):
    body = html.escape(json.dumps(data, indent=2, ensure_ascii=False))
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYBERX Report</title><style>
body{{background:#0b1220;color:#e5edf9;font:15px system-ui;margin:0;padding:22px}}
main{{max-width:900px;margin:auto}}h1{{color:#60a5fa}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#111c30;padding:18px;border:1px solid #263852;border-radius:12px}}
small{{color:#9fb0c8}}</style></head><body><main><h1>CYBERX OSINT Report</h1>
<small>Generated {html.escape(now_iso())} · Public-source research only</small><pre>{body}</pre></main></body></html>"""

DASHBOARD = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYBERX OSINT INTELLIGENCE</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#080e19;color:#e7eefb;font:15px system-ui}
header{padding:20px 5%;border-bottom:1px solid #20304a;background:#0c1525;display:flex;justify-content:space-between;gap:12px;align-items:center}
.logo{font-weight:800;letter-spacing:1px;color:#60a5fa;font-size:20px}.tag{color:#9aabc4;font-size:12px}
main{max-width:1100px;margin:28px auto;padding:0 16px}.panel{background:#101b2d;border:1px solid #263a57;border-radius:15px;padding:20px;margin-bottom:18px}
h2{margin:0 0 14px;font-size:18px}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
button,.tab{background:#1d4ed8;color:white;border:0;padding:11px 16px;border-radius:9px;font-weight:650;cursor:pointer}
.tab{background:#1b2a42;color:#c8d6eb}.tab.active{background:#2563eb;color:white}
input,select{background:#081322;border:1px solid #344966;color:white;padding:13px;border-radius:9px;width:100%;font-size:15px}
.row{display:grid;grid-template-columns:1fr 140px;gap:10px}.muted{color:#9aabc4;font-size:13px}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.stat{padding:14px;background:#0a1424;border-radius:10px;border:1px solid #20324d}.stat b{font-size:23px;color:#60a5fa;display:block}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#07111f;padding:15px;border-radius:10px;max-height:550px;overflow:auto}
a{color:#7db5ff} .links{display:flex;gap:12px;flex-wrap:wrap}.status{margin:12px 0;color:#a8bad3}
@media(max-width:600px){header{padding:16px}.row{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}main{margin-top:16px}}
</style></head><body>
<header><div><div class="logo">⌁ CYBERX OSINT</div><div class="tag">INTELLIGENCE PLATFORM · V3.0</div></div><div class="tag">TERMUX LOCAL SERVER</div></header>
<main>
<section class="panel"><h2>New Intelligence Search</h2>
<div class="tabs">
<button class="tab active" data-kind="email">Email</button><button class="tab" data-kind="username">Username</button>
<button class="tab" data-kind="phone">Phone</button><button class="tab" data-kind="domain">Domain</button></div>
<div class="row"><input id="query" placeholder="Enter email address" autocomplete="off"><select id="region"><option value="BD">Bangladesh (+880)</option><option value="US">United States (+1)</option><option value="GB">United Kingdom (+44)</option><option value="IN">India (+91)</option></select></div>
<p class="muted">Only public records and documented APIs are queried. Results may be incomplete.</p>
<button id="run">Run Intelligence Search</button><div class="status" id="status">Ready.</div></section>
<section class="panel"><h2>Search Overview</h2><div class="stats"><div class="stat"><b id="score">—</b><span class="muted">Evidence score</span></div><div class="stat"><b id="type">—</b><span class="muted">Search type</span></div><div class="stat"><b id="time">—</b><span class="muted">Last search</span></div></div></section>
<section class="panel"><h2>Intelligence Results</h2><div class="links" id="links"></div><pre id="result">Your results will appear here.</pre><button id="json" disabled>Download JSON</button></section>
<section class="panel"><h2>Recent Search History</h2><div id="history" class="muted">Loading…</div></section>
<p class="muted">CYBERX is an open-source educational utility. A match is not proof of identity. Respect privacy, laws, API limits and website terms.</p>
</main>
<script>
let kind='email', latest=null;
const placeholders={email:'Enter email address',username:'Enter username',phone:'Enter phone number (e.g. +8801XXXXXXXXX)',domain:'Enter domain (example.com)'};
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));b.classList.add('active');kind=b.dataset.kind;document.querySelector('#query').placeholder=placeholders[kind];document.querySelector('#region').style.display=kind==='phone'?'block':'none';});
document.querySelector('#region').style.display='none';
async function history(){try{let r=await fetch('/api/history');let d=await r.json();document.querySelector('#history').innerHTML=d.items.length?d.items.map(x=>`<div style="padding:8px 0;border-bottom:1px solid #263a57">${x.created_at} · <b>${x.query_type}</b> · ${esc(x.query_value)}</div>`).join(''):'No searches yet.'}catch(e){document.querySelector('#history').textContent='History unavailable.'}}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
document.querySelector('#run').onclick=async()=>{let q=document.querySelector('#query').value.trim();if(!q){document.querySelector('#status').textContent='Enter a search value.';return}
document.querySelector('#status').textContent='Searching public sources…';document.querySelector('#run').disabled=true;
try{let r=await fetch('/api/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:kind,value:q,region:document.querySelector('#region').value})});let d=await r.json();if(!r.ok)throw new Error(d.error||'Search failed');latest=d;document.querySelector('#result').textContent=JSON.stringify(d,null,2);document.querySelector('#score').textContent=d.evidence_score+'%';document.querySelector('#type').textContent=d.type;document.querySelector('#time').textContent=new Date().toLocaleTimeString();document.querySelector('#links').innerHTML=(d.public_links||d.manual_search_links||[]).map(x=>`<a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.name)}</a>`).join('');document.querySelector('#json').disabled=false;document.querySelector('#status').textContent='Search complete.';history()}catch(e){document.querySelector('#status').textContent=e.message}finally{document.querySelector('#run').disabled=false}};
document.querySelector('#json').onclick=()=>{if(!latest)return;let a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(latest,null,2)],{type:'application/json'}));a.download='cyberx-report.json';a.click();URL.revokeObjectURL(a.href)};
history();
</script></body></html>"""

@app.get("/")
def home():
    return render_template_string(DASHBOARD)

@app.post("/api/search")
def api_search():
    data = request.get_json(silent=True) or {}
    try:
        kind = clean_input(data.get("type", ""), 20).lower()
        value = clean_input(data.get("value", ""), 254)
        result = analyze(kind, value, data.get("region", "BD"))
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": "Unexpected error: " + str(exc)[:180]}), 500

@app.get("/api/history")
def api_history():
    with db() as conn:
        rows = conn.execute("SELECT id,created_at,query_type,query_value FROM searches ORDER BY id DESC LIMIT 20").fetchall()
    return jsonify({"items": [dict(r) for r in rows]})

@app.get("/health")
def health():
    return jsonify({"status": "ok", "app": APP_NAME, "version": VERSION})

def print_banner():
    print("\033[96m" + r"""
   ____ __   __ ____  _______  __  __
  / ___|\ \ / /|  _ \| ____\ \/ /
 | |     \ V / | |_) |  _|  \  /
 | |___   | |  |  _ <| |___ /  \
  \____|  |_|  |_| \_\_____/_/\_\
""" + "\033[0m")
    print(f"{APP_NAME} V{VERSION} | Public-source OSINT\n")

def terminal_mode():
    print_banner()
    while True:
        print("\n[1] Email  [2] Username  [3] Phone  [4] Domain  [5] Web Dashboard  [0] Exit")
        choice = input("CYBERX> ").strip()
        if choice == "0":
            break
        if choice == "5":
            print("Open http://127.0.0.1:5000 on this device.")
            threading.Thread(target=lambda: app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False), daemon=True).start()
            continue
        kinds = {"1": "email", "2": "username", "3": "phone", "4": "domain"}
        if choice not in kinds:
            print("Invalid option.")
            continue
        value = input("Enter value: ").strip()
        region = input("Phone region [BD]: ").strip().upper() or "BD" if choice == "3" else "BD"
        try:
            result = analyze(kinds[choice], value, region)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            fmt = input("Save report? [j=json / h=html / enter=skip]: ").strip().lower()
            if fmt in ("j", "h"):
                print("Saved:", write_report(result, "json" if fmt == "j" else "html"))
        except Exception as exc:
            print("ERROR:", exc)

def main():
    init_db()
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--web", action="store_true", help="Start mobile web dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address; default is local device only")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--type", choices=["email", "username", "phone", "domain"])
    parser.add_argument("--value", help="Value to investigate")
    parser.add_argument("--region", default="BD", help="Phone parsing region, default BD")
    parser.add_argument("--report", choices=["json", "html"], help="Save report for CLI search")
    args = parser.parse_args()
    if args.web:
        print_banner()
        print(f"Dashboard: http://{args.host}:{args.port}")
        if args.host not in ("127.0.0.1", "localhost"):
            print("WARNING: Exposing the dashboard to a network. Use only on a trusted network.")
        app.run(host=args.host, port=args.port, debug=False)
    elif args.type and args.value:
        try:
            result = analyze(args.type, args.value, args.region)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            if args.report:
                print("Report saved:", write_report(result, args.report))
        except Exception as exc:
            print("ERROR:", exc)
            sys.exit(1)
    else:
        terminal_mode()

if __name__ == "__main__":
    main()
