#!/usr/bin/env python3
"""sentinel: the live-surface watcher for helmetduck.com. Standard library only.

It runs where the owner's laptop cannot reach (GitHub Actions, on a schedule) and
needs no credentials: everything it checks is visible to any visitor. It rebuilds
the revision the live site declares and compares every published file byte for
byte, then checks the redirects, the security headers, the honest 404, that the
bucket is private, the TLS floor, the certificate, the DNS delegation and the
hygiene records, and the registrar lock.

It never acts. It reports, and the exit code is the verdict:
  0  every law held; amber findings are printed, not fatal
  2  a red finding: the site, its pipeline, its DNS or its registration may be
     compromised or degraded

    python3 tools/sentinel.py          # table
    python3 tools/sentinel.py --md     # markdown, for the standing issue

Third parties consulted, read-only, over HTTPS: dns.google (cloudflare-dns.com as
the fallback) for DNS answers and rdap.verisign.com for the registration. A third
party being unreachable is amber, never red: their outage is not our incident.
"""
import argparse
import io
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = "helmetduck.com"
BASE = "https://%s/" % SITE
BUCKET = "helmet-duck-prod-site-244206438585"
UA = "helmet-duck-sentinel/1 (+https://helmetduck.com/)"
TIMEOUT = 20

EXPECT = {
    # the registry delegation and the live NS answer must both be exactly this set
    "nameservers": {"ns-1590.awsdns-06.co.uk", "ns-481.awsdns-60.com",
                    "ns-660.awsdns-18.net", "ns-1512.awsdns-61.org"},
    "csp": "default-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
           "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
    "caa_issuers": {"amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"},
    "spf": "v=spf1 -all",
    "dmarc_policy": "p=reject",
    # Until tools/apply.sh has created the hygiene records and set the registrar
    # lock, their absence is amber. Flip both to True after the apply: then absence
    # is red, because something that existed has gone.
    "dns_hygiene_required": False,
    "transfer_lock_required": False,
    "cert_amber_days": 30,
    "cert_red_days": 14,
    "expiry_amber_days": 60,
    "expiry_red_days": 30,
}
RRTYPE = {"NS": 2, "MX": 15, "TXT": 16, "CAA": 257}
TAMPER = re.compile(r"<script\b|<iframe\b|<form\b|<object\b|<embed\b|\son[a-z]+\s*=|javascript:", re.I)


# ------------------------------------------------------------------ plumbing
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url, follow=False, timeout=TIMEOUT):
    """(status, lower-cased headers, body). A redirect is returned, not followed,
    unless follow=True. One retry after five seconds for transport errors."""
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    err = None
    for attempt in (1, 2):
        try:
            with opener.open(req, timeout=timeout) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
        except (urllib.error.URLError, OSError) as e:
            err = e
            if attempt == 1:
                time.sleep(5)
    raise RuntimeError("%s: %s" % (url, err))


def doh(name, rtype):
    """Answer strings for name/type over DNS-over-HTTPS. Raises when both resolvers fail."""
    errs = []
    for url, extra in (("https://dns.google/resolve?name=%s&type=%s" % (name, rtype), {}),
                       ("https://cloudflare-dns.com/dns-query?name=%s&type=%s" % (name, rtype),
                        {"Accept": "application/dns-json"})):
        try:
            req = urllib.request.Request(url, headers=dict({"User-Agent": UA}, **extra))
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                data = json.loads(r.read())
            if data.get("Status") not in (0, 3):          # 3 = no such name: an empty, valid answer
                raise RuntimeError("rcode %s" % data.get("Status"))
            return [a["data"] for a in data.get("Answer", []) if a.get("type") == RRTYPE[rtype]]
        except Exception as e:                           # noqa: BLE001  a resolver failing is data here
            errs.append("%s: %s" % (url.split("/")[2], e))
    raise RuntimeError("; ".join(errs))


def unquote_txt(s):
    """dns-json returns TXT data as one or more quoted strings; join them."""
    return "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', s)) if '"' in s else s


class Findings:
    def __init__(self):
        self.rows = []

    def add(self, name, level, detail=""):
        self.rows.append((name, level, detail))

    def ok(self, name, detail=""):
        self.add(name, "ok", detail)

    def amber(self, name, detail=""):
        self.add(name, "amber", detail)

    def red(self, name, detail=""):
        self.add(name, "red", detail)

    def verdict(self, name, ok, detail="", fail="red"):
        self.add(name, "ok" if ok else fail, detail)

    def count(self, level):
        return sum(1 for r in self.rows if r[1] == level)


# ------------------------------------------------------------------ the laws
def check_pages(f):
    """The live tree must be the tree built from the revision it declares, and that
    revision must be a commit on this branch. Returns the home page headers."""
    st, hdr, body = fetch(BASE)
    if st != 200:
        f.red("home page", "status %d" % st)
        return hdr
    html = body.decode("utf-8", "replace")
    m = re.search(r'name="helmet-duck-revision" content="([0-9a-f]{7,40})"', html)
    if not m:
        f.red("revision marker", "the live home page carries no revision marker")
        return hdr
    rev = m.group(1)
    git = lambda *a: subprocess.run(["git", *a], cwd=str(ROOT), capture_output=True)  # noqa: E731
    if git("cat-file", "-e", rev + "^{commit}").returncode != 0:
        f.red("live revision", "%s is not a commit in this repository" % rev)
        return hdr
    on_branch = git("merge-base", "--is-ancestor", rev, "HEAD").returncode == 0
    f.verdict("live revision", on_branch, "%s %s" % (rev, "is on this branch" if on_branch else "is NOT an ancestor of HEAD"))

    with tempfile.TemporaryDirectory() as d:
        tree = pathlib.Path(d) / "tree"
        tree.mkdir()
        tar = git("archive", rev, "site").stdout
        with tarfile.open(fileobj=io.BytesIO(tar)) as t:
            try:
                t.extractall(tree, filter="data")
            except TypeError:                            # Python before 3.12
                t.extractall(tree)
        dist = pathlib.Path(d) / "dist"
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "build.py"), "--site", str(tree / "site"),
                            "--out", str(dist)], env=dict(os.environ, HELMET_DUCK_REVISION=rev),
                           capture_output=True, text=True)
        if r.returncode != 0:
            f.red("rebuild of %s" % rev, (r.stderr or r.stdout).strip()[-200:])
            return hdr
        same, diff, live_html = 0, [], {}
        for p in sorted(x for x in dist.rglob("*") if x.is_file()):
            rel = str(p.relative_to(dist)).replace("\\", "/")
            st2, _, live = fetch(BASE + rel)
            if rel.endswith(".html"):
                live_html[rel] = live.decode("utf-8", "replace")
            if st2 == 200 and live == p.read_bytes():
                same += 1
            else:
                diff.append("%s (%s)" % (rel, "status %d" % st2 if st2 != 200 else "bytes differ"))
        if body != (dist / "index.html").read_bytes():
            diff.append("/ (differs from index.html)")
        f.verdict("live files == build of %s" % rev, not diff,
                  "; ".join(diff)[:300] if diff else "%d files identical, plus /" % same)
        # the tamper invariant stands on its own: the site ships no script, frame or form
        tampered = sorted(rel for rel, text in live_html.items() if TAMPER.search(text))
        f.verdict("no script, frame, form or handler in any live page", not tampered, ", ".join(tampered))
        # an unknown path must be an honest 404 with the 404 page, never a masked home page
        st3, _, body3 = fetch(BASE + "no-such-page-%d" % int(time.time()))
        f.verdict("unknown path is an honest 404", st3 == 404 and body3 == (dist / "404.html").read_bytes(),
                  "status %d, %s" % (st3, "the 404 page" if body3 == (dist / "404.html").read_bytes() else "a different body"))
    return hdr


def check_redirects(f):
    st, hdr, _ = fetch("http://%s/" % SITE)
    loc = hdr.get("location", "")
    f.verdict("http redirects to https", st in (301, 308) and loc == BASE, "status %d, location %s" % (st, loc or "-"))
    st, hdr, _ = fetch("https://www.%s/" % SITE)
    loc = hdr.get("location", "")
    f.verdict("www redirects to the apex", st in (301, 308) and loc == BASE, "status %d, location %s" % (st, loc or "-"))


def check_headers(f, hdr):
    hsts = hdr.get("strict-transport-security", "").lower()
    age = re.search(r"max-age=(\d+)", hsts)
    rules = (
        ("content-security-policy", hdr.get("content-security-policy") == EXPECT["csp"]),
        ("strict-transport-security", bool(age) and int(age.group(1)) >= 31536000
         and "includesubdomains" in hsts and "preload" in hsts),
        ("x-content-type-options", hdr.get("x-content-type-options", "").lower() == "nosniff"),
        ("x-frame-options", hdr.get("x-frame-options", "").upper() == "DENY"),
        ("referrer-policy", bool(hdr.get("referrer-policy"))),
        ("permissions-policy", bool(hdr.get("permissions-policy"))),
    )
    bad = [name for name, held in rules if not held]
    f.verdict("security headers", not bad, "missing or changed: " + ", ".join(bad) if bad else "%d headers as expected" % len(rules))


def check_bucket(f):
    st, _, _ = fetch("https://%s.s3.amazonaws.com/index.html" % BUCKET)
    if st == 200:
        f.red("origin bucket is private", "the bucket answers directly with 200")
    elif st in (403, 404):
        f.ok("origin bucket is private", "direct request answered %d" % st)
    else:
        f.amber("origin bucket is private", "direct request answered %d" % st)


def check_tls(f):
    curl = shutil.which("curl")
    if not curl:
        f.amber("TLS 1.1 refused", "curl is not available here")
        return
    r = subprocess.run([curl, "-sS", "--tls-max", "1.1", "--max-time", "20", "-o", os.devnull, BASE],
                       capture_output=True, text=True)
    err = r.stderr.strip()
    if r.returncode == 0:
        f.red("TLS 1.1 refused", "the edge accepted a TLS 1.1 handshake")
    elif "no protocols available" in err or "unsupported protocol" in err.lower():
        f.amber("TLS 1.1 refused", "this client cannot speak TLS 1.1, so the floor was not tested")
    elif r.returncode == 35:
        f.ok("TLS 1.1 refused", "handshake refused by the edge")
    else:
        f.amber("TLS 1.1 refused", "curl exit %d: %s" % (r.returncode, err[:100]))


def check_certificate(f):
    ctx = ssl.create_default_context()
    with socket.create_connection((SITE, 443), timeout=TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=SITE) as tls:
        cert, proto = tls.getpeercert(), tls.version()
    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (exp - datetime.now(timezone.utc)).days
    names = {v for k, v in cert.get("subjectAltName", ()) if k == "DNS"}
    issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "?")
    level = "red" if days < EXPECT["cert_red_days"] else "amber" if days < EXPECT["cert_amber_days"] else "ok"
    f.add("certificate", level, "%s, %d days left, %s" % (issuer, days, proto))
    f.verdict("certificate covers apex and www", {SITE, "www." + SITE} <= names, ", ".join(sorted(names)))


def check_dns(f):
    required = EXPECT["dns_hygiene_required"]
    absent = "red" if required else "amber"
    try:
        ns = {a.rstrip(".").lower() for a in doh(SITE, "NS")}
        f.verdict("NS delegation", ns == EXPECT["nameservers"], ", ".join(sorted(ns)) or "no answer")

        caa = doh(SITE, "CAA")
        issuers = {unquote_txt(m.group(1)) for m in (re.search(r'issue\s+(\S+)', a) for a in caa) if m}
        if not caa:
            f.add("CAA record", absent, "none: any CA may issue for this name")
        else:
            f.verdict("CAA record", issuers == EXPECT["caa_issuers"], "issue " + ", ".join(sorted(issuers)))

        txt = [unquote_txt(a) for a in doh(SITE, "TXT")]
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        if not spf:
            f.add("SPF record", absent, "none: any server may send mail as this domain")
        else:
            f.verdict("SPF record", spf[0].strip() == EXPECT["spf"], spf[0])

        dm = [unquote_txt(a) for a in doh("_dmarc." + SITE, "TXT")]
        dm = [t for t in dm if t.lower().startswith("v=dmarc1")]
        if not dm:
            f.add("DMARC record", absent, "none")
        else:
            f.verdict("DMARC record", EXPECT["dmarc_policy"] in dm[0].replace(" ", "").lower(), dm[0])

        mx = [a.strip() for a in doh(SITE, "MX")]
        if not mx or mx == ["0 ."]:
            f.ok("MX", "no mail is received here" + (" (null MX)" if mx else ""))
        else:
            f.amber("MX", "mail is configured: %s. Update the sentinel's expectations if this is yours." % ", ".join(mx))
    except RuntimeError as e:
        f.amber("DNS not checked", "resolvers unreachable: %s" % str(e)[:160])


def check_registration(f):
    try:
        st, _, body = fetch("https://rdap.verisign.com/com/v1/domain/%s" % SITE)
    except RuntimeError as e:
        f.amber("registration not checked", "RDAP unreachable: %s" % str(e)[:120])
        return
    if st != 200:
        f.amber("registration not checked", "RDAP answered %d" % st)
        return
    data = json.loads(body)
    status = {s.lower() for s in data.get("status", [])}
    locked = "client transfer prohibited" in status
    f.verdict("registrar transfer lock", locked, ", ".join(sorted(status)) or "no status",
              fail="red" if EXPECT["transfer_lock_required"] else "amber")
    danger = status & {"pending delete", "redemption period", "client hold", "server hold", "inactive"}
    if danger:
        f.red("registration status", ", ".join(sorted(danger)))
    ns = {n.get("ldhName", "").lower().rstrip(".") for n in data.get("nameservers", [])}
    f.verdict("registry delegation", ns == EXPECT["nameservers"], ", ".join(sorted(ns)) or "none listed")
    exp = next((e.get("eventDate") for e in data.get("events", []) if e.get("eventAction") == "expiration"), None)
    if exp:
        when = datetime.strptime(exp[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        days = (when - datetime.now(timezone.utc)).days
        level = "red" if days < EXPECT["expiry_red_days"] else "amber" if days < EXPECT["expiry_amber_days"] else "ok"
        f.add("registration expiry", level, "%s, %d days" % (exp[:10], days))


# ------------------------------------------------------------------ output
def render(f, md):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    reds, ambers, oks = f.count("red"), f.count("amber"), f.count("ok")
    verdict = "RED" if reds else "held"
    if md:
        lines = ["| law | verdict | detail |", "| --- | --- | --- |"]
        for name, level, detail in f.rows:
            lines.append("| %s | %s | %s |" % (name, level.upper(), detail.replace("|", "\\|")))
        lines += ["", "**Live-surface laws %s** at %s: %d red, %d amber, %d ok. "
                  "The sentinel reports only; it never deploys." % (verdict, now, reds, ambers, oks)]
        return "\n".join(lines) + "\n"
    width = max(len(r[0]) for r in f.rows)
    out = ["helmetduck.com sentinel, %s" % now]
    for name, level, detail in f.rows:
        out.append("  %-5s %-*s %s" % (level.upper(), width, name, detail))
    out.append("\n%s: %d red, %d amber, %d ok" % (verdict, reds, ambers, oks))
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--md", action="store_true", help="markdown output for the standing issue")
    a = ap.parse_args()
    f = Findings()
    hdr = {}
    for name, fn in (("pages", check_pages), ("redirects", check_redirects), ("bucket", check_bucket),
                     ("tls", check_tls), ("certificate", check_certificate),
                     ("dns", check_dns), ("registration", check_registration)):
        try:
            result = fn(f)
            if name == "pages" and result is not None:
                hdr = result
        except Exception as e:                           # noqa: BLE001  a crashed law is a finding, not a crash
            f.red("%s check failed" % name, "%s: %s" % (type(e).__name__, str(e)[:160]))
    try:
        check_headers(f, hdr)
    except Exception as e:                               # noqa: BLE001
        f.red("headers check failed", str(e)[:160])
    sys.stdout.write(render(f, a.md))
    return 2 if f.count("red") else 0


if __name__ == "__main__":
    sys.exit(main())
