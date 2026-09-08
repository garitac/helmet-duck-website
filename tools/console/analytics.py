"""Helmet Duck Console: read-only evidence adapters and pure aggregation.

Collection and presentation stay separate. This module reads what already exists:
the live page, CloudWatch metrics for the distribution, the private access-log
bucket (mirrored to a local, ignored folder), the brake's state, the edge
blocklist, the alarm, the watchers' last runs and the mail account. It never
enables anything, changes AWS, or sends visitor data anywhere.

What the numbers mean, stated once so the page can repeat it:
  - A "browser-grade visitor" is a source address that fetched the site's
    stylesheet during the window and is neither a declared bot nor a suspicious
    source. IP is not a person: a warm cache undercounts, a careful scraper
    overcounts. Raw requests, probes and declared bots stay visibly separate.
  - "Country" is the country of the CloudFront edge that served the request, an
    approximation of where the visitor was. The legacy access-log format carries
    no visitor country field.
  - Every suspicious request lands in exactly one outcome bucket; the page shows
    a warning if the buckets ever fail to add up. HTTP 2xx means the edge answered,
    not that anything was accessed or changed; on this static site a 2xx for a
    probe path would be a contradiction worth reading.
  - No address is ever displayed. Grouping by address happens in memory only.

    python3 tools/console/analytics.py --selftest      offline, synthetic records
"""
import gzip
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import sentry  # noqa: E402  the same log parser and probe patterns the sentry uses

CACHE_ROOT = ROOT / ".console-cache"
LOG_MIRROR = CACHE_ROOT / "logs"
REGION = "us-east-1"
SITE_URL = "https://helmetduck.com/"
UA = "helmet-duck-console/1 (local, read-only)"
AWS_TIMEOUT = 40

BOT = re.compile(r"bot|crawl|spider|slurp|preview|curl|wget|python-|go-http|node-fetch|axios|okhttp|java/|libwww|headless"
                 r"|monitor|uptime|pingdom|statuscake|site24x7|helmet-duck-sentinel|facebookexternal|whatsapp|telegram|discord|slack", re.I)
SCANNER_UA = re.compile(r"acunetix|dirbuster|ffuf|gobuster|masscan|metasploit|nikto|nmap|nuclei|nessus|sqlmap|wpscan|zgrab|wfuzz|nessus", re.I)
STYLESHEET = re.compile(r"^/[A-Za-z0-9_-]+\.[0-9a-f]{10}\.css$")
NON_PAGE = re.compile(r"\.(?!html?$)[a-z0-9]{1,8}$", re.I)
NON_PAGE_NAME = re.compile(r"^/(?:favicon\.svg|robots\.txt|sitemap\.xml)$", re.I)

# Declared automation, by user agent. Order matters: the first match wins.
BENIGN = [
    ("search-crawler", "Search crawler", "A declared search-engine crawler indexed public pages.",
     re.compile(r"googlebot|bingbot|duckduckbot|yandex|baiduspider|applebot|petalbot|seznambot|naverbot", re.I)),
    ("ai-crawler", "AI crawler", "A declared AI dataset, answer-engine or assistant crawler fetched public content.",
     re.compile(r"gptbot|oai-searchbot|chatgpt-user|claudebot|anthropic|perplexitybot|ccbot|bytespider|amazonbot|google-extended|meta-externalagent|cohere|youbot", re.I)),
    ("link-preview", "Link preview", "A social or messaging service fetched a public link preview.",
     re.compile(r"facebookexternalhit|twitterbot|slackbot|discordbot|telegrambot|whatsapp|linkedinbot|skypeuripreview|embedly", re.I)),
    ("monitoring-tool", "Monitoring tool", "A declared availability or health-check client tested the public site.",
     re.compile(r"uptime|pingdom|statuscake|site24x7|helmet-duck-sentinel|betteruptime|freshping|updown", re.I)),
    ("seo-audit", "SEO audit crawler", "A declared SEO or site-audit crawler inspected public pages.",
     re.compile(r"ahrefs|semrush|mj12bot|dotbot|screaming frog|sitebulb|serpstat|dataforseo", re.I)),
    ("developer-tool", "Developer or scripted client", "A generic HTTP library or command-line client, declared as such.",
     re.compile(r"curl|wget|python-|go-http-client|node-fetch|axios|okhttp|java/|libwww|httpx|postman|insomnia", re.I)),
]
SUSPICIOUS = [
    ("vulnerability-scanner", "Vulnerability scanner", "A declared security-scanner user agent tested the site."),
    ("exploit-injection", "Exploit or injection probe", "The path resembles traversal, injection, CGI or remote-code-execution reconnaissance."),
    ("sensitive-file-discovery", "Sensitive-file discovery", "The request searched for secrets, source-control data, backups or configuration files."),
    ("cms-admin-probe", "CMS or admin probe", "The request searched for common CMS, database-admin or control-panel paths."),
    ("credential-probe", "Login or credential probe", "The request tested a login, authentication or management endpoint."),
    ("unsafe-method-probe", "Write-method probe", "A non-read HTTP method was sent to this static site."),
    ("high-volume-path-scan", "High-volume path scan", "One source tested many distinct paths, mostly receiving rejection responses."),
]
SUSPICIOUS_INFO = {sid: (label, desc) for sid, label, desc in SUSPICIOUS}
EXPLOIT = re.compile(r"\.\./|%2e%2e|/cgi-bin|/shell|/cmd\b|/eval|\$\{|<script|union\s+select|/etc/passwd|/_ignition|/actuator|/solr|/jenkins|/boaform|/telescope|/debug", re.I)
SENSITIVE = re.compile(r"\.env\b|\.git\b|\.svn\b|\.aws\b|\.ssh\b|\.htaccess|\.htpasswd|credential|passwd|\.sql\b|\.bak\b|\.old\b|\.zip\b|\.tar\b|\.tgz\b|\.7z\b|\.rar\b|/backup|/config\b|\.ya?ml\b|\.ini\b|\.log\b|\.pem\b|id_rsa", re.I)
CMS = re.compile(r"wp-|wordpress|xmlrpc|phpmyadmin|/pma\b|/mysql|/admin\b|/administrator|/manager/html|/console\b|\.php\b|\.asp\b|\.aspx\b|\.jsp\b|/vendor/|/owa/|/ecp/|/autodiscover", re.I)
CREDENTIAL = re.compile(r"/login\b|/signin\b|/auth\b|/oauth|/api/|/user\b|/account\b|/setup\b|/install\b|/graphql", re.I)

# CloudFront edge locations are named after airports. The country of the edge that
# served a request approximates the visitor's country; it is not the visitor's country.
EDGE_COUNTRY = {
    "NRT": ("JP", "Japan"), "KIX": ("JP", "Japan"), "HND": ("JP", "Japan"), "ICN": ("KR", "South Korea"),
    "TPE": ("TW", "Taiwan"), "HKG": ("HK", "Hong Kong"), "SIN": ("SG", "Singapore"), "KUL": ("MY", "Malaysia"),
    "BKK": ("TH", "Thailand"), "MNL": ("PH", "Philippines"), "CGK": ("ID", "Indonesia"), "JKT": ("ID", "Indonesia"),
    "HAN": ("VN", "Vietnam"), "SGN": ("VN", "Vietnam"), "BOM": ("IN", "India"), "DEL": ("IN", "India"),
    "MAA": ("IN", "India"), "BLR": ("IN", "India"), "HYD": ("IN", "India"), "CCU": ("IN", "India"), "PNQ": ("IN", "India"),
    "SYD": ("AU", "Australia"), "MEL": ("AU", "Australia"), "PER": ("AU", "Australia"), "BNE": ("AU", "Australia"),
    "AKL": ("NZ", "New Zealand"),
    "IAD": ("US", "United States"), "DFW": ("US", "United States"), "SFO": ("US", "United States"), "SEA": ("US", "United States"),
    "ORD": ("US", "United States"), "JFK": ("US", "United States"), "LAX": ("US", "United States"), "ATL": ("US", "United States"),
    "MIA": ("US", "United States"), "BOS": ("US", "United States"), "EWR": ("US", "United States"), "IAH": ("US", "United States"),
    "PHX": ("US", "United States"), "DEN": ("US", "United States"), "MSP": ("US", "United States"), "SLC": ("US", "United States"),
    "PDX": ("US", "United States"), "PHL": ("US", "United States"), "DTW": ("US", "United States"), "CMH": ("US", "United States"),
    "JAX": ("US", "United States"), "TPA": ("US", "United States"), "MCI": ("US", "United States"), "STL": ("US", "United States"),
    "CLT": ("US", "United States"), "MSY": ("US", "United States"), "SJC": ("US", "United States"), "HIO": ("US", "United States"),
    "LAS": ("US", "United States"), "SAN": ("US", "United States"), "PIT": ("US", "United States"), "IND": ("US", "United States"),
    "BNA": ("US", "United States"), "RIC": ("US", "United States"), "AUS": ("US", "United States"), "DUS": ("DE", "Germany"),
    "YTO": ("CA", "Canada"), "YUL": ("CA", "Canada"), "YVR": ("CA", "Canada"), "YYZ": ("CA", "Canada"),
    "QRO": ("MX", "Mexico"), "MEX": ("MX", "Mexico"), "GRU": ("BR", "Brazil"), "GIG": ("BR", "Brazil"), "FOR": ("BR", "Brazil"),
    "CNF": ("BR", "Brazil"), "EZE": ("AR", "Argentina"), "SCL": ("CL", "Chile"), "BOG": ("CO", "Colombia"), "LIM": ("PE", "Peru"),
    "LHR": ("GB", "United Kingdom"), "LON": ("GB", "United Kingdom"), "MAN": ("GB", "United Kingdom"), "DUB": ("IE", "Ireland"),
    "CDG": ("FR", "France"), "MRS": ("FR", "France"), "PAR": ("FR", "France"), "FRA": ("DE", "Germany"), "MUC": ("DE", "Germany"),
    "HAM": ("DE", "Germany"), "TXL": ("DE", "Germany"), "BER": ("DE", "Germany"), "AMS": ("NL", "Netherlands"), "BRU": ("BE", "Belgium"),
    "ZRH": ("CH", "Switzerland"), "MXP": ("IT", "Italy"), "MIL": ("IT", "Italy"), "FCO": ("IT", "Italy"), "PMO": ("IT", "Italy"),
    "MAD": ("ES", "Spain"), "BCN": ("ES", "Spain"), "LIS": ("PT", "Portugal"), "ARN": ("SE", "Sweden"), "STO": ("SE", "Sweden"),
    "CPH": ("DK", "Denmark"), "HEL": ("FI", "Finland"), "OSL": ("NO", "Norway"), "WAW": ("PL", "Poland"), "PRG": ("CZ", "Czechia"),
    "VIE": ("AT", "Austria"), "BUD": ("HU", "Hungary"), "ATH": ("GR", "Greece"), "SOF": ("BG", "Bulgaria"), "OTP": ("RO", "Romania"),
    "BUH": ("RO", "Romania"), "ZAG": ("HR", "Croatia"), "TLV": ("IL", "Israel"), "IST": ("TR", "Turkey"),
    "JNB": ("ZA", "South Africa"), "CPT": ("ZA", "South Africa"), "NBO": ("KE", "Kenya"), "LOS": ("NG", "Nigeria"),
    "DXB": ("AE", "United Arab Emirates"), "BAH": ("BH", "Bahrain"), "FJR": ("AE", "United Arab Emirates"), "MCT": ("OM", "Oman"),
    "SELF": ("--", "Synthetic test"),
}


# ------------------------------------------------------------------ contract and AWS
def load_contract(root=ROOT):
    """The few values the console needs from environments/prod.env.yaml, read without a YAML library."""
    text = (root / "environments" / "prod.env.yaml").read_text(encoding="utf-8")
    grab = lambda key: (re.search(r'^\s*%s:\s*"([^"]*)"' % key, text, re.M) or [None, ""])[1]  # noqa: E731
    return {"distributionId": grab("cloudfront_distribution"), "bucket": grab("bucket"), "logBucket": grab("log_bucket"),
            "site": grab("site"), "accountId": grab("account_id"), "mail": grab("provider")}


def aws_profile():
    return os.environ.get("HELMET_DUCK_ADMIN_PROFILE", "kanjishisho-bootstrap-admin")


def run_aws(args, timeout=AWS_TIMEOUT, parse=True):
    """Run one read-only AWS CLI call with the console's profile. Raises RuntimeError with the CLI's words."""
    cmd = [os.environ.get("HELMET_DUCK_AWS_BIN", "aws"), *args, "--profile", aws_profile(), "--output", "json"]
    if "--region" not in args and args[0] not in ("s3",):
        cmd += ["--region", REGION]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("aws %s: %s" % (args[0], exc))
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip().splitlines()[-1][:200] if (r.stderr or r.stdout).strip() else "aws %s failed" % args[0])
    return json.loads(r.stdout) if parse and r.stdout.strip() else {}


def aws_session():
    """Who the console is, or the words to fix it."""
    try:
        me = run_aws(["sts", "get-caller-identity"])
        return {"available": True, "arn": me.get("Arn", ""), "profile": aws_profile()}
    except RuntimeError as exc:
        return {"available": False, "profile": aws_profile(), "error": str(exc),
                "hint": "aws sso login --profile %s" % aws_profile()}


# ------------------------------------------------------------------ live health and edge metrics
def fetch_health(site_url=SITE_URL):
    try:
        req = urllib.request.Request(site_url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=8) as r:
            html = r.read().decode("utf-8", "replace")
            m = re.search(r'name="helmet-duck-revision" content="([0-9a-f]+)"', html)
            return {"available": True, "ok": r.status == 200, "status": r.status, "revision": m.group(1) if m else ""}
    except urllib.error.HTTPError as exc:
        return {"available": True, "ok": False, "status": exc.code, "revision": ""}
    except (urllib.error.URLError, OSError) as exc:
        return {"available": False, "ok": False, "status": 0, "revision": "", "error": str(exc)[:120]}


def _metric(distribution_id, name, statistic, days):
    end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    start = end - timedelta(days=days)
    data = run_aws(["cloudwatch", "get-metric-statistics", "--namespace", "AWS/CloudFront", "--metric-name", name,
                    "--dimensions", "Name=DistributionId,Value=%s" % distribution_id, "Name=Region,Value=Global",
                    "--start-time", start.strftime("%Y-%m-%dT%H:%M:%SZ"), "--end-time", end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "--period", "86400", "--statistics", statistic])
    return sorted(((p["Timestamp"], p.get(statistic, 0)) for p in data.get("Datapoints", [])), key=lambda x: x[0])


def fetch_edge_metrics(contract, days):
    try:
        dist = contract["distributionId"]
        requests_ = _metric(dist, "Requests", "Sum", days)
        bytes_ = _metric(dist, "BytesDownloaded", "Sum", days)
        e4 = _metric(dist, "4xxErrorRate", "Average", days)
        e5 = _metric(dist, "5xxErrorRate", "Average", days)
        total = sum(v for _, v in requests_)
        avg = lambda pts: (sum(v for _, v in pts) / len(pts)) if pts else 0.0  # noqa: E731
        return {"available": True, "requests": int(total), "bytes": int(sum(v for _, v in bytes_)),
                "error4xxPct": round(avg(e4), 2), "error5xxPct": round(avg(e5), 3),
                "trend": [{"at": t, "requests": int(v)} for t, v in requests_]}
    except RuntimeError as exc:
        return {"available": False, "error": str(exc)}


# ------------------------------------------------------------------ the log mirror
def mirror_logs(contract, max_age_s=50):
    """Sync the private log bucket into the local, ignored mirror, at most once per max_age_s."""
    LOG_MIRROR.mkdir(parents=True, exist_ok=True)
    stamp = CACHE_ROOT / "mirror.json"
    now = time.time()
    if stamp.exists():
        try:
            last = json.loads(stamp.read_text())
            if now - last.get("at", 0) < max_age_s:
                return last
        except ValueError:
            pass
    try:
        run_aws(["s3", "sync", "s3://%s/cloudfront/" % contract["logBucket"], str(LOG_MIRROR),
                 "--exclude", "*selftest*", "--only-show-errors"], timeout=120, parse=False)
        state = {"at": now, "ok": True}
    except RuntimeError as exc:
        state = {"at": now, "ok": False, "error": str(exc)}
    stamp.write_text(json.dumps(state))
    return state


def mirror_files():
    return sorted(p for p in LOG_MIRROR.rglob("*.gz") if p.is_file())


# ------------------------------------------------------------------ classification
def record_time(rec):
    try:
        return sentry.parse_ts(rec)
    except (KeyError, ValueError):
        return 0


def edge_country(rec):
    code = re.match(r"[A-Z]+", rec.get("x-edge-location", "") or "")
    return EDGE_COUNTRY.get(code.group(0) if code else "", ("??", "Unknown edge"))


def classify(rec):
    """(intent, category id) for one record: suspicious / benign / None (undeclared)."""
    ua = urllib.parse.unquote(rec.get("cs(User-Agent)", "") or "")
    path = urllib.parse.unquote(rec.get("cs-uri-stem", "") or "")
    method = rec.get("cs-method", "GET")
    if SCANNER_UA.search(ua):
        return "suspicious", "vulnerability-scanner"
    if method not in ("GET", "HEAD", "OPTIONS"):
        return "suspicious", "unsafe-method-probe"
    if EXPLOIT.search(path):
        return "suspicious", "exploit-injection"
    if SENSITIVE.search(path):
        return "suspicious", "sensitive-file-discovery"
    if CMS.search(path):
        return "suspicious", "cms-admin-probe"
    if CREDENTIAL.search(path):
        return "suspicious", "credential-probe"
    for cid, _, _, rx in BENIGN:
        if rx.search(ua):
            return "benign", cid
    return None, None


def outcome(status):
    s = str(status or "")
    if s.startswith("2"):
        return "success"
    if s.startswith("3"):
        return "redirected"
    if s.startswith("4"):
        return "rejected"
    if s.startswith("5"):
        return "serverError"
    return "unknown"


def is_page(path):
    return not (NON_PAGE.search(path) or NON_PAGE_NAME.match(path)) or path.endswith((".html", "/"))


def evidence_window(days, now, oldest, newest):
    start = now - days * 86400
    covered_from = max(start, oldest) if oldest else 0
    available_days = round(max(0.0, (newest - covered_from) / 86400), 1) if newest and covered_from else 0.0
    iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if t else ""  # noqa: E731
    return {"requestedDays": days, "availableDays": min(float(days), available_days),
            "complete": bool(oldest) and oldest <= start + 3600, "from": iso(covered_from), "through": iso(newest)}


# ------------------------------------------------------------------ aggregation
def aggregate(records, days=7, now=None):
    """Pure: records -> the visitors and non-human sections. Addresses live only in local memory."""
    now = now or time.time()
    since = now - days * 86400
    rows = [r for r in records if record_time(r) >= since]
    by_ip = defaultdict(list)
    for r in rows:
        by_ip[r.get("c-ip", "-")].append(r)

    ip_kind = {}                       # ip -> "human" | "bot" | "suspicious" | "unconfirmed"
    ip_categories = defaultdict(set)   # ip -> category ids
    for ip, recs in by_ip.items():
        kinds = Counter()
        for r in recs:
            intent, cid = classify(r)
            if intent:
                kinds[intent] += 1
                ip_categories[ip].add(cid)
        paths = {urllib.parse.unquote(r.get("cs-uri-stem", "")) for r in recs}
        rejected = sum(1 for r in recs if outcome(r.get("sc-status")) == "rejected")
        if (len(paths) >= 8 and rejected >= len(recs) * 0.6) or (len(recs) >= 20 and rejected >= len(recs) * 0.8):
            kinds["suspicious"] += 1
            ip_categories[ip].add("high-volume-path-scan")
        fetched_css = any(STYLESHEET.match(urllib.parse.unquote(r.get("cs-uri-stem", ""))) for r in recs)
        if kinds["suspicious"]:
            ip_kind[ip] = "suspicious"
        elif kinds["benign"]:
            ip_kind[ip] = "bot"
        elif fetched_css:
            ip_kind[ip] = "human"
        else:
            ip_kind[ip] = "unconfirmed"

    # visitors by edge country, with the pages they viewed successfully
    countries = defaultdict(lambda: {"humans": set(), "nonBotIPs": set(), "pages": Counter()})
    pages_all = Counter()
    for ip, recs in by_ip.items():
        kind = ip_kind[ip]
        for r in recs:
            code, name = edge_country(r)
            c = countries[(code, name)]
            if kind in ("human", "unconfirmed"):
                c["nonBotIPs"].add(ip)
            if kind == "human":
                c["humans"].add(ip)
                path = urllib.parse.unquote(r.get("cs-uri-stem", ""))
                if r.get("cs-method", "GET") == "GET" and outcome(r.get("sc-status")) == "success" and is_page(path):
                    c["pages"][path] += 1
                    pages_all[path] += 1
    humans_total = sum(1 for k in ip_kind.values() if k == "human")
    country_rows = []
    for (code, name), c in countries.items():
        if not c["humans"]:
            continue
        country_rows.append({"code": code, "name": name, "humans": len(c["humans"]), "nonBotIPs": len(c["nonBotIPs"]),
                             "sharePct": round(100.0 * len(c["humans"]) / humans_total, 1) if humans_total else 0.0,
                             "pages": [{"path": p, "visits": n} for p, n in c["pages"].most_common(6)]})
    country_rows.sort(key=lambda x: (-x["humans"], x["name"]))

    # non-human traffic: categories, outcomes, targets; never an address
    def category_block(cids_by_intent):
        cats = {}
        for ip, recs in by_ip.items():
            for cid in ip_categories[ip]:
                if cid not in cids_by_intent:
                    continue
                cat = cats.setdefault(cid, {"id": cid, "intent": cids_by_intent[cid][0], "label": cids_by_intent[cid][1],
                                            "description": cids_by_intent[cid][2], "actors": set(), "requests": 0,
                                            "outcomes": Counter(), "targets": Counter()})
                cat["actors"].add(ip)
                for r in recs:
                    intent, rcid = classify(r)
                    if rcid != cid and not (cid == "high-volume-path-scan" and intent is None):
                        continue
                    cat["requests"] += 1
                    cat["outcomes"][outcome(r.get("sc-status"))] += 1
                    cat["targets"][sentry.defang(r.get("cs-uri-stem", ""), 80)] += 1
        out = []
        for cat in cats.values():
            out.append({**cat, "actors": len(cat["actors"]),
                        "outcomes": {k: cat["outcomes"].get(k, 0) for k in ("success", "redirected", "rejected", "serverError", "unknown")},
                        "targets": [{"path": p, "requests": n} for p, n in cat["targets"].most_common(5)]})
        out.sort(key=lambda x: -x["requests"])
        return out
    sus_info = {sid: ("suspicious", label, desc) for sid, label, desc in SUSPICIOUS}
    ben_info = {cid: ("benign", label, desc) for cid, label, desc, _ in BENIGN}
    suspicious_cats = category_block(sus_info)
    benign_cats = category_block(ben_info)
    sus_ips = [ip for ip, k in ip_kind.items() if k == "suspicious"]
    sus_requests = [r for ip in sus_ips for r in by_ip[ip]]
    outcomes = Counter(outcome(r.get("sc-status")) for r in sus_requests)
    attempts = len(sus_requests)
    total_out = sum(outcomes.values())
    unconfirmed_ips = [ip for ip, k in ip_kind.items() if k == "unconfirmed"]
    unconfirmed_targets = Counter(sentry.defang(r.get("cs-uri-stem", ""), 80) for ip in unconfirmed_ips for r in by_ip[ip])
    bot_ips = [ip for ip, k in ip_kind.items() if k == "bot"]

    times = [record_time(r) for r in rows]
    return {
        "available": True, "humans": humans_total, "probes": len(unconfirmed_ips), "botIPs": len(bot_ips),
        "suspiciousIPs": len(sus_ips), "requests": len(rows), "sources": len(by_ip),
        "window": evidence_window(days, now, min(times) if times else 0, max(times) if times else 0),
        "countryBasis": "country of the CloudFront edge that served the request, not the visitor's own",
        "countries": country_rows,
        "pages": [{"path": p, "visits": n} for p, n in pages_all.most_common(10)],
        "nonHuman": {
            "actors": len(sus_ips) + len(bot_ips) + len(unconfirmed_ips),
            "requests": sum(len(by_ip[ip]) for ip in sus_ips + bot_ips + unconfirmed_ips),
            "protection": {
                "suspiciousAttempts": attempts, "httpSuccess": outcomes.get("success", 0), "redirected": outcomes.get("redirected", 0),
                "rejected": outcomes.get("rejected", 0), "serverError": outcomes.get("serverError", 0), "unknown": outcomes.get("unknown", 0),
                "outcomeTotal": total_out, "reconciled": total_out == attempts,
                "note": "HTTP 2xx means the edge returned a response; on this static site a 2xx for a probe path is a contradiction to read, not proof of access.",
            },
            "suspicious": {"actors": len(sus_ips), "requests": attempts, "categories": suspicious_cats},
            "benign": {"actors": len(bot_ips), "requests": sum(len(by_ip[ip]) for ip in bot_ips), "categories": benign_cats},
            "unconfirmed": {"actors": len(unconfirmed_ips), "requests": sum(len(by_ip[ip]) for ip in unconfirmed_ips),
                            "targets": [{"path": p, "requests": n} for p, n in unconfirmed_targets.most_common(8)],
                            "note": "Undeclared sources that fetched no stylesheet. A warm-cache person can look the same; a quiet scanner can too."},
        },
    }


# ------------------------------------------------------------------ the guard panel
def fetch_guard(contract):
    guard = {}
    try:
        p = run_aws(["ssm", "get-parameter", "--name", "/helmet-duck/prod/brake"])
        st = json.loads(p["Parameter"]["Value"])
        guard["brake"] = {"available": True, "off": bool(st.get("off")), "count": st.get("count", 0),
                          "until": st.get("until", 0), "engaged": bool(st.get("until")) and st["until"] > time.time()}
    except (RuntimeError, KeyError, ValueError) as exc:
        guard["brake"] = {"available": False, "error": str(exc)[:120]}
    try:
        out = CACHE_ROOT / "edge-function.js"
        run_aws(["cloudfront", "get-function", "--name", "helmet-duck-prod-edge-router", "--stage", "LIVE", str(out)], parse=False)
        code = out.read_text(encoding="utf-8", errors="replace")
        listed = json.loads((re.search(r"/\*BLOCKLIST\*/(.*?)/\*END\*/", code, re.S) or [None, "{}"])[1] or "{}")
        now = time.time()
        active = [t for t in listed.values() if t > now]
        guard["blocklist"] = {"available": True, "listed": len(listed), "active": len(active),
                              "nextExpiry": min(active) if active else 0}
    except (RuntimeError, ValueError, OSError) as exc:
        guard["blocklist"] = {"available": False, "error": str(exc)[:120]}
    try:
        a = run_aws(["cloudwatch", "describe-alarms", "--alarm-names", "helmet-duck-prod-request-flood"])
        alarm = (a.get("MetricAlarms") or [{}])[0]
        guard["alarm"] = {"available": bool(alarm), "state": alarm.get("StateValue", "none"),
                          "threshold": alarm.get("Threshold", 0), "updatedAt": alarm.get("StateUpdatedTimestamp", "")}
    except RuntimeError as exc:
        guard["alarm"] = {"available": False, "error": str(exc)[:120]}
    try:
        m = run_aws(["sesv2", "get-account"])
        guard["mail"] = {"available": True, "production": bool(m.get("ProductionAccessEnabled")), "sendingEnabled": bool(m.get("SendingEnabled")),
                         "sentLast24h": int((m.get("SendQuota") or {}).get("SentLast24Hours", 0)),
                         "quota24h": int((m.get("SendQuota") or {}).get("Max24HourSend", 0))}
    except RuntimeError as exc:
        guard["mail"] = {"available": False, "error": str(exc)[:120]}
    guard["watchers"] = fetch_watchers()
    return guard


def fetch_watchers():
    gh = os.environ.get("HELMET_DUCK_GH_BIN", "gh")
    out = {}
    for wf in ("sentinel", "sentry", "ci", "deploy"):
        try:
            r = subprocess.run([gh, "run", "list", "-R", "garitac/helmet-duck-website", "--workflow", "%s.yml" % wf, "--limit", "1",
                                "--json", "conclusion,status,updatedAt,url"], capture_output=True, text=True, timeout=20)
            runs = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else []
            out[wf] = runs[0] if runs else {"conclusion": "none"}
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            out[wf] = {"conclusion": "unavailable", "error": str(exc)[:80]}
    try:
        r = subprocess.run([gh, "pr", "list", "-R", "garitac/helmet-duck-website", "--json", "number"], capture_output=True, text=True, timeout=20)
        out["openPullRequests"] = len(json.loads(r.stdout)) if r.returncode == 0 and r.stdout.strip() else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        out["openPullRequests"] = None
    return out


# ------------------------------------------------------------------ the snapshot
def build_snapshot(days=7):
    contract = load_contract()
    now = time.time()
    snap = {"generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "contract": contract,
            "aws": aws_session(), "health": fetch_health(SITE_URL if contract["site"] == "helmetduck.com" else "https://%s/" % contract["site"])}
    if snap["aws"]["available"]:
        snap["edge"] = fetch_edge_metrics(contract, days)
        mirror = mirror_logs(contract)
        rows, files, skipped = sentry.read_logs(mirror_files(), now - 31 * 86400)
        snap["visitors"] = aggregate(rows, days, now)
        snap["visitors"].update({"mirrorUpdatedAt": datetime.fromtimestamp(mirror.get("at", now), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                 "mirrorOk": mirror.get("ok", False), "mirrorError": mirror.get("error", ""),
                                 "files": files, "skippedLines": skipped, "source": "private CloudFront access-log mirror"})
        snap["guard"] = fetch_guard(contract)
    else:
        snap["edge"] = {"available": False, "error": snap["aws"]["error"]}
        snap["visitors"] = {"available": False, "error": snap["aws"]["error"]}
        snap["guard"] = {"available": False, "error": snap["aws"]["error"], "watchers": fetch_watchers()}
    return snap


# ------------------------------------------------------------------ selftest
def _synthetic_records(now):
    def rec(ip, path, status="200", ua="Mozilla/5.0 (Macintosh) Safari", edge="NRT20-P7", method="GET", minutes_ago=5):
        t = datetime.fromtimestamp(now - minutes_ago * 60, timezone.utc)
        return {"date": t.strftime("%Y-%m-%d"), "time": t.strftime("%H:%M:%S"), "x-edge-location": edge, "sc-bytes": "9000",
                "c-ip": ip, "cs-method": method, "cs(Host)": "d.cloudfront.net", "cs-uri-stem": path, "sc-status": status,
                "cs(User-Agent)": urllib.parse.quote(ua)}
    css = "/styles.0123456789.css"
    rows = []
    rows += [rec("203.0.113.1", "/"), rec("203.0.113.1", css), rec("203.0.113.1", "/risks.html")]                 # human, Tokyo edge
    rows += [rec("203.0.113.2", "/", edge="IAD89-C1"), rec("203.0.113.2", css, edge="IAD89-C1")]                    # human, Virginia edge
    rows += [rec("203.0.113.3", "/")]                                                                              # unconfirmed: no stylesheet
    rows += [rec("203.0.113.4", "/", ua="Mozilla/5.0 (compatible; Googlebot/2.1)")]                                # benign crawler
    rows += [rec("203.0.113.5", "/wp-login.php", "404"), rec("203.0.113.5", "/.env", "404"), rec("203.0.113.5", css)]  # suspicious despite css
    rows += [rec("203.0.113.6", "/p%d" % i, "404") for i in range(9)]                                             # high-volume path scan
    rows += [rec("203.0.113.7", "/", "200", method="POST")]                                                         # write-method probe, answered 200
    return rows


def selftest():
    now = time.time()
    v = aggregate(_synthetic_records(now), days=7, now=now)
    checks = [
        ("two browser-grade visitors", v["humans"] == 2),
        ("one unconfirmed probe source", v["probes"] == 1),
        ("one declared bot", v["botIPs"] == 1),
        ("three suspicious sources (scan, probe, write-method)", v["suspiciousIPs"] == 3),
        ("stylesheet does not launder a probing source", all(c["humans"] <= 2 for c in v["countries"])),
        ("countries: Japan and United States, by edge", sorted(c["code"] for c in v["countries"]) == ["JP", "US"]),
        ("pages ranked for humans only", {p["path"] for p in v["pages"]} == {"/", "/risks.html"}),
        ("outcomes reconcile: 3 + 9 + 1 suspicious requests", v["nonHuman"]["protection"]["reconciled"] and v["nonHuman"]["protection"]["suspiciousAttempts"] == 13),
        ("2xx to suspicious sources counted, not hidden (stylesheet and POST)", v["nonHuman"]["protection"]["httpSuccess"] == 2),
        ("no address in the output", "203.0.113" not in json.dumps(v)),
        ("window covers the records", v["window"]["through"] != "" and v["window"]["availableDays"] >= 0),
        ("high-volume scan category present", any(c["id"] == "high-volume-path-scan" for c in v["nonHuman"]["suspicious"]["categories"])),
    ]
    for name, ok in checks:
        print("  %-5s %s" % ("ok" if ok else "FAIL", name))
    ok = all(c[1] for c in checks)
    print("\n%s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    days = int(sys.argv[sys.argv.index("--days") + 1]) if "--days" in sys.argv else 7
    print(json.dumps(build_snapshot(days), indent=1))
