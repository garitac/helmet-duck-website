/* Helmet Duck Console, presentation only. Everything shown comes from /api/snapshot. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const n = (v) => (v == null ? "n/a" : Number(v).toLocaleString("en-US"));
  const pct = (v) => (v == null ? "n/a" : Number(v).toFixed(v < 1 ? 2 : 1) + "%");
  const when = (iso) => (iso ? new Date(iso).toLocaleString("en-GB", { hour12: false }) : "n/a");
  const bytes = (b) => {
    if (b == null) return "n/a";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0; let v = Number(b);
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return v.toFixed(v < 10 && i > 0 ? 1 : 0) + " " + units[i];
  };
  const card = (label, value, hint, tone) =>
    `<div class="card ${tone || ""}"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div>${hint ? `<div class="hint">${esc(hint)}</div>` : ""}</div>`;
  const table = (head, rows) =>
    `<table><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="${head.length}" class="empty">nothing in this window</td></tr>`}</tbody></table>`;

  let timer = null;

  function renderOverview(s) {
    const h = s.health || {};
    const e = s.edge || {};
    const v = s.visitors || {};
    const cards = [
      card("Live site", h.available ? (h.ok ? "up, HTTP " + h.status : "HTTP " + h.status) : "unreachable", h.revision ? "revision " + h.revision : (h.error || ""), h.ok ? "good" : "bad"),
      card("Console", (s.console || {}).version || "", "running revision " + String((s.console || {}).revision || "").slice(0, 12)),
      card("Requests", e.available ? n(e.requests) : "n/a", e.available ? "edge, selected window" : (e.error || "")),
      card("Bytes served", e.available ? bytes(e.bytes) : "n/a", "edge, selected window"),
      card("4xx rate", e.available ? pct(e.error4xxPct) : "n/a", "daily average", e.available && e.error4xxPct > 50 ? "warn" : ""),
      card("5xx rate", e.available ? pct(e.error5xxPct) : "n/a", "daily average", e.available && e.error5xxPct > 0.5 ? "warn" : ""),
      card("Browser-grade visitors", v.available ? n(v.humans) : "n/a", v.available ? `${n(v.sources)} source(s), ${n(v.requests)} logged request(s)` : (v.error || "")),
    ];
    $("overview-cards").innerHTML = cards.join("");
    const trend = (e.trend || []);
    const max = Math.max(1, ...trend.map((t) => t.requests));
    $("trend").innerHTML = trend.length
      ? trend.map((t) => `<div class="bar" title="${esc(t.at.slice(0, 10))}: ${n(t.requests)}"><div class="fill" style="height:${Math.max(2, Math.round(100 * t.requests / max))}%"></div><span>${esc(t.at.slice(5, 10))}</span></div>`).join("")
      : `<p class="empty">${esc(e.error || "no metric points yet")}</p>`;
    const aws = s.aws || {};
    $("overview-note").textContent = aws.available
      ? `AWS read as ${aws.arn}.`
      : `AWS not reachable with profile ${aws.profile || ""}: ${aws.error || ""}. ${aws.hint || ""}`;
  }

  function renderVisitors(s) {
    const v = s.visitors || {};
    if (!v.available) { $("visitor-cards").innerHTML = card("Visitors", "n/a", v.error || "", "bad"); $("countries").innerHTML = ""; $("pages").innerHTML = ""; return; }
    const w = v.window || {};
    $("visitor-cards").innerHTML = [
      card("Browser-grade visitors", n(v.humans), "sources with a stylesheet fetch, not bots, not suspicious", "good"),
      card("Unconfirmed probes", n(v.probes), "undeclared, no stylesheet fetch"),
      card("Declared bots", n(v.botIPs), "crawlers, previews, tools"),
      card("Suspicious sources", n(v.suspiciousIPs), "scanner signatures or path scans", v.suspiciousIPs ? "warn" : ""),
      card("Evidence window", `${w.availableDays} of ${w.requestedDays} day(s)`, w.complete ? "complete" : "partial: logs began after the window start", w.complete ? "" : "warn"),
    ].join("");
    $("countries").innerHTML = table(["Country (edge)", "Visitors", "Share", "Non-bot sources", "Pages viewed"],
      (v.countries || []).map((c) => [
        esc(`${c.name} (${c.code})`), n(c.humans), pct(c.sharePct), n(c.nonBotIPs),
        (c.pages || []).map((p) => `<code>${esc(p.path)}</code> ${n(p.visits)}`).join("<br>"),
      ]));
    $("pages").innerHTML = table(["Page", "Successful visits by browser-grade sources"], (v.pages || []).map((p) => [`<code>${esc(p.path)}</code>`, n(p.visits)]));
  }

  function categoryTable(cats) {
    return table(["Category", "Sources", "Requests", "2xx", "3xx", "4xx", "5xx", "?", "Top targets"],
      (cats || []).map((c) => [
        `<strong>${esc(c.label)}</strong><br><span class="dim">${esc(c.description)}</span>`, n(c.actors), n(c.requests),
        n(c.outcomes.success), n(c.outcomes.redirected), n(c.outcomes.rejected), n(c.outcomes.serverError), n(c.outcomes.unknown),
        (c.targets || []).map((t) => `<code>${esc(t.path)}</code> ${n(t.requests)}`).join("<br>"),
      ]));
  }

  function renderNonHuman(s) {
    const v = s.visitors || {};
    const nh = v.nonHuman || {};
    if (!v.available) { $("nonhuman-cards").innerHTML = card("Non-human traffic", "n/a", v.error || "", "bad"); ["protection", "suspicious", "benign", "unconfirmed"].forEach((id) => { $(id).innerHTML = ""; }); return; }
    const p = nh.protection || {};
    $("nonhuman-cards").innerHTML = [
      card("Non-human sources", n(nh.actors), `${n(nh.requests)} request(s)`),
      card("Suspicious attempts", n(p.suspiciousAttempts), "requests from suspicious sources", p.suspiciousAttempts ? "warn" : ""),
      card("Answered 2xx", n(p.httpSuccess), "read these: a probe path answered 2xx is a contradiction", p.httpSuccess ? "bad" : "good"),
      card("Rejected or failed", n((p.rejected || 0) + (p.serverError || 0)), "4xx and 5xx"),
      card("Outcomes reconcile", p.reconciled ? "yes" : "NO", p.reconciled ? `${n(p.outcomeTotal)} of ${n(p.suspiciousAttempts)}` : "the buckets do not add up; read the raw logs", p.reconciled ? "good" : "bad"),
    ].join("");
    $("protection").innerHTML = table(["2xx success", "3xx redirected", "4xx rejected", "5xx failed", "unknown", "total"],
      [[n(p.httpSuccess), n(p.redirected), n(p.rejected), n(p.serverError), n(p.unknown), n(p.outcomeTotal)]]) + `<p class="note">${esc(p.note || "")}</p>`;
    $("suspicious").innerHTML = categoryTable((nh.suspicious || {}).categories);
    $("benign").innerHTML = categoryTable((nh.benign || {}).categories);
    const u = nh.unconfirmed || {};
    $("unconfirmed").innerHTML = `<p>${n(u.actors)} source(s), ${n(u.requests)} request(s). ${esc(u.note || "")}</p>` +
      table(["Path", "Requests"], (u.targets || []).map((t) => [`<code>${esc(t.path)}</code>`, n(t.requests)]));
  }

  function renderGuard(s) {
    const g = s.guard || {};
    const b = g.brake || {}; const bl = g.blocklist || {}; const a = g.alarm || {}; const m = g.mail || {};
    $("guard-cards").innerHTML = [
      card("Brake", !b.available ? "n/a" : b.off ? "switched off" : b.engaged ? "ENGAGED" : "armed", b.available ? `${n(b.count)} alarm(s) in a row${b.engaged ? ", until " + when(b.until * 1000) : ""}` : (b.error || ""), b.engaged ? "bad" : b.off ? "warn" : "good"),
      card("Edge blocklist", bl.available ? `${n(bl.active)} active` : "n/a", bl.available ? `${n(bl.listed)} listed${bl.nextExpiry ? ", next expiry " + when(bl.nextExpiry * 1000) : ""}` : (bl.error || ""), bl.active ? "warn" : "good"),
      card("Flood alarm", a.available ? a.state : "n/a", a.available ? `threshold ${n(a.threshold)} requests per hour` : (a.error || ""), a.state === "ALARM" ? "bad" : "good"),
      card("Mail (SES)", m.available ? (m.production ? "production" : "sandbox") : "n/a", m.available ? `${n(m.sentLast24h)} sent in 24 h of ${n(m.quota24h)}` : (m.error || ""), m.available && m.sendingEnabled ? "good" : "warn"),
    ].join("");
    const w = g.watchers || {};
    const row = (name, r) => [esc(name), `<span class="badge ${r.conclusion === "success" ? "good" : r.conclusion === "failure" ? "bad" : ""}">${esc(r.conclusion || r.status || "none")}</span>`, when(r.updatedAt), r.url ? `<a href="${esc(r.url)}" rel="noreferrer noopener" target="_blank">run</a>` : ""];
    $("watchers").innerHTML = table(["Workflow", "Last conclusion", "When", ""],
      ["sentinel", "sentry", "ci", "deploy"].filter((k) => w[k]).map((k) => row(k, w[k])))
      + `<p class="note">Open pull requests: ${w.openPullRequests == null ? "n/a" : n(w.openPullRequests)}.</p>`;
  }

  function render(s) {
    $("identity").textContent = `checked ${when(s.generatedAt)}`;
    renderOverview(s); renderVisitors(s); renderNonHuman(s); renderGuard(s);
    const v = s.visitors || {};
    $("evidence").textContent = v.available
      ? `Log mirror updated ${when(v.mirrorUpdatedAt)}${v.mirrorOk ? "" : " (sync failed: " + (v.mirrorError || "") + ")"}, ${n(v.files)} file(s), newest event ${when((v.window || {}).through)}, ${v.skippedLines || 0} unreadable line(s). Source: ${v.source || ""}.`
      : "No log evidence: AWS is not reachable from this console.";
    $("status").textContent = "";
  }

  async function load(force) {
    const days = $("days").value;
    $("status").textContent = force ? "Refreshing..." : "Loading...";
    try {
      const r = await fetch(`/api/snapshot?days=${encodeURIComponent(days)}${force ? "&refresh=1" : ""}`, { cache: "no-store" });
      const body = await r.json();
      if (!r.ok) throw new Error(body.error || ("HTTP " + r.status));
      render(body);
    } catch (err) {
      $("status").textContent = "Snapshot failed: " + err.message;
    }
    clearTimeout(timer);
    timer = setTimeout(() => load(false), 60_000);
  }

  $("tabs").addEventListener("click", (ev) => {
    const b = ev.target.closest("button[data-tab]");
    if (!b) return;
    document.querySelectorAll(".tabs button").forEach((x) => x.classList.toggle("active", x === b));
    document.querySelectorAll("main .tab").forEach((x) => x.classList.toggle("active", x.id === b.dataset.tab));
  });
  $("days").addEventListener("change", () => load(true));
  $("refresh").addEventListener("click", () => load(true));
  load(false);
})();
