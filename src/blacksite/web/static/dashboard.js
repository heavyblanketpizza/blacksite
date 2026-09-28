// The dashboard ("Command center"): KPIs, incidents over time, outcomes, model and runtime,
// team activity from the audit ledger, and learning. Uses app.js helpers (el, t, api, S).
// Charts are hand-drawn SVG in theme colours; every chart has a hover layer, an aria-label,
// and a table view, so nothing depends on colour alone.
"use strict";

const DASH = { scope: null, range: 30, data: null, activity: null, timer: null, table: false, resizeTimer: null };
const SVG_NS = "http://www.w3.org/2000/svg";
const STAGES = ["new", "in progress", "guide", "closed"];

function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) if (value !== undefined && value !== null) node.setAttribute(key, value);
  for (const child of children.flat()) if (child) node.append(child);
  return node;
}

function tip() {
  let node = $(".viz-tip");
  if (!node) { node = el("div", { class: "viz-tip", role: "tooltip", hidden: true }); document.body.append(node); }
  return node;
}

function showTip(event, ...content) {
  const node = tip();
  node.replaceChildren(...content);
  node.hidden = false;
  const box = node.getBoundingClientRect();
  const x = Math.min(event.clientX + 14, innerWidth - box.width - 8);
  const y = event.clientY - box.height - 12 < 8 ? event.clientY + 16 : event.clientY - box.height - 12;
  node.style.left = `${x}px`;
  node.style.top = `${y}px`;
}

function hideTip() { const node = $(".viz-tip"); if (node) node.hidden = true; }

function stored_(key, fallback) { return stored(`blacksite.dash.${S.me.user.id}.${key}`, fallback); }

function pct(value) { return value === null || value === undefined ? "—" : `${Math.round(value * 100)}%`; }

function dur(seconds) { return seconds === null || seconds === undefined ? "—" : duration(seconds); }

function greeting() {
  const hour = new Date().getHours();
  const part = hour < 5 ? "evening" : hour < 12 ? "morning" : hour < 18 ? "afternoon" : "evening";
  return t(`dash.greeting.${part}`, { name: S.me.user.display_name });
}

async function renderDashboard() {
  const root = $("#view-dashboard");
  if (!DASH.scope) {
    DASH.scope = stored_("scope", isAdmin() ? "all" : "mine");
    if (DASH.scope === "all" && !isAdmin()) DASH.scope = "mine";
    DASH.range = Number(stored_("range", "30")) || 30;
  }
  if (!root.firstChild) root.replaceChildren(el("div", { class: "dash-loading faint", text: t("dash.loading") }));
  try {
    const [data, activity] = await Promise.all([
      api(`/api/dashboard?scope=${DASH.scope}&range=${DASH.range}`),
      api("/api/activity?limit=7"),
    ]);
    DASH.data = data;
    DASH.activity = activity;
  } catch (error) {
    root.replaceChildren(el("div", { class: "empty" }, el("h2", { text: t("error.server") }), el("p", { text: error.message })));
    return;
  }
  drawDashboard();
  if (!DASH.timer) {
    DASH.timer = setInterval(() => { if (S.view === "dashboard" && !document.hidden) renderDashboard(); }, 15000);
    addEventListener("resize", () => {
      clearTimeout(DASH.resizeTimer);
      DASH.resizeTimer = setTimeout(() => { if (S.view === "dashboard" && DASH.data) drawDashboard(); }, 150);
    });
  }
}

function drawDashboard() {
  const root = $("#view-dashboard");
  const data = DASH.data;
  const scroll = root.scrollTop;
  const scopes = isAdmin() ? ["mine", "shared", "all"] : ["mine", "shared"];
  const seg = (items, current, label, onpick) => el("div", { class: "seg compact", role: "group", "aria-label": label },
    items.map(([value, text]) => el("button", { type: "button", class: value === current ? "on" : "", "aria-pressed": String(value === current),
      text, onclick: () => onpick(value) })));
  const date = new Date().toLocaleDateString(LANG === "ko" ? "ko-KR" : "en-US", { weekday: "long", month: "long", day: "numeric" });
  const sub = [date, t("dash.attention", { count: data.attention })];
  if (data.running) sub.push(t("dash.running", { count: data.running }));
  const head = el("header", { class: "view-head" },
    el("div", {}, el("h1", { text: greeting() }), el("div", { class: "faint", text: sub.join(" · ") })),
    el("span", { class: "spacer" }),
    seg(scopes.map((scope) => [scope, t(`dash.scope.${scope}`)]), DASH.scope, t("dash.scopeLabel"), (scope) => {
      DASH.scope = scope; store(`blacksite.dash.${S.me.user.id}.scope`, scope); renderDashboard();
    }),
    seg([[7, t("dash.range", { days: 7 })], [30, t("dash.range", { days: 30 })], [90, t("dash.range", { days: 90 })]], DASH.range,
      t("dash.rangeLabel"), (range) => { DASH.range = range; store(`blacksite.dash.${S.me.user.id}.range`, String(range)); renderDashboard(); }));

  if (!data.incidents && DASH.scope !== "all") {
    root.replaceChildren(el("div", { class: "dash" }, head, emptyDashboard(), el("div", { class: "dash-row three" },
      runtimeCard(data), activityCard(), learningCard(data))));
    root.scrollTop = scroll;
    return;
  }
  root.replaceChildren(el("div", { class: "dash" }, head, kpiStrip(data),
    el("div", { class: "dash-row two" }, trendCard(data), outcomesCard(data)),
    el("div", { class: "dash-row three" }, runtimeCard(data), activityCard(), learningCard(data))));
  root.scrollTop = scroll;
}

function emptyDashboard() {
  return el("section", { class: "card pad dash-empty" },
    el("div", { class: "empty-mark", "aria-hidden": "true" }, el("span"), el("span"), el("span")),
    el("div", {},
      el("h2", { text: t(DASH.scope === "shared" ? "dash.emptyShared" : "dash.emptyTitle") }),
      el("p", { class: "muted", text: t(DASH.scope === "shared" ? "dash.emptySharedBody" : "dash.emptyBody") }),
      DASH.scope === "mine" ? el("button", { class: "btn primary", type: "button", text: t("empty.button"),
        onclick: () => { location.hash = "#/incidents"; setTimeout(openNewIncident, 50); } }) : null));
}

// KPI tiles ------------------------------------------------------------------------------

function sparkline(values, color, label) {
  const width = 104, height = 32, pad = 3;
  const points = values.map((value, index) => [index, value]).filter(([, value]) => value !== null && value !== undefined);
  const node = svg("svg", { class: "spark", width, height, viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": label });
  if (points.length < 2) {
    node.append(svg("line", { x1: 0, x2: width, y1: height - pad, y2: height - pad, class: "spark-base" }));
    return node;
  }
  const max = Math.max(...points.map(([, value]) => value)), min = Math.min(0, ...points.map(([, value]) => value));
  const x = (index) => (index / (values.length - 1)) * (width - 2 * pad) + pad;
  const y = (value) => height - pad - ((value - min) / (max - min || 1)) * (height - 2 * pad);
  const line = points.map(([index, value], order) => `${order ? "L" : "M"}${x(index).toFixed(1)} ${y(value).toFixed(1)}`).join(" ");
  const [lastIndex, lastValue] = points[points.length - 1];
  node.append(
    svg("path", { d: `${line} L${x(lastIndex).toFixed(1)} ${height - pad} L${x(points[0][0]).toFixed(1)} ${height - pad} Z`,
      fill: color, opacity: "0.12" }),
    svg("path", { d: line, fill: "none", stroke: color, "stroke-width": "2", "stroke-linejoin": "round", "stroke-linecap": "round" }),
    svg("circle", { cx: x(lastIndex), cy: y(lastValue), r: "3", fill: color, stroke: "var(--panel)", "stroke-width": "2" }));
  return node;
}

function delta(current, previous, better, format) {
  if (current === null || current === undefined || previous === null || previous === undefined) {
    return el("span", { class: "delta faint", text: t("dash.noComparison") });
  }
  const change = current - previous;
  if (Math.abs(change) < 1e-9) return el("span", { class: "delta faint", text: t("dash.same") });
  const good = better === "up" ? change > 0 : change < 0;
  return el("span", { class: `delta ${good ? "good" : "bad"}` },
    el("b", { text: `${change > 0 ? "▲" : "▼"} ${format(Math.abs(change))}` }), " ", t("dash.vsPrevious", { days: DASH.range }));
}

function kpiStrip(data) {
  const k = data.kpis;
  const tile = (label, value, detail, spark, color, sparkLabel) => el("section", { class: "card kpi" },
    el("div", { class: "kpi-label", text: label }),
    el("div", { class: "kpi-value" }, value),
    detail,
    sparkline(spark, color, sparkLabel));
  const time = k.time_to_guide.value;
  const timeValue = time === null ? el("span", { text: "—" })
    : el("span", {}, String(Math.floor(time / 60)), el("small", { text: t("dash.unitMinutes") }),
      String(Math.round(time % 60)).padStart(2, "0"), el("small", { text: t("dash.unitSeconds") }));
  return el("div", { class: "kpis" },
    tile(t("dash.kpi.open"), el("span", { text: number(k.open.value) }),
      el("span", { class: "delta faint" }, el("b", { text: `+${number(k.open.created)}` }), " ", t("dash.newInRange", { days: DASH.range })),
      k.open.spark, "var(--warn)", t("dash.spark.created", { days: DASH.range })),
    tile(t("dash.kpi.awaiting"), el("span", { text: number(k.awaiting.value) }),
      el("span", { class: "delta faint", text: t("dash.awaitingHint") }),
      k.awaiting.spark, "var(--accent)", t("dash.spark.guides", { days: DASH.range })),
    tile(t("dash.kpi.resolved"), k.resolved_rate.value === null ? el("span", { text: "—" })
      : el("span", {}, String(Math.round(k.resolved_rate.value * 100)), el("small", { text: "%" })),
      delta(k.resolved_rate.value, k.resolved_rate.previous, "up", (value) => t("dash.points", { n: Math.round(value * 100) })),
      k.resolved_rate.spark, "var(--ok)", t("dash.spark.resolved", { days: DASH.range })),
    tile(t("dash.kpi.timeToGuide"), timeValue,
      delta(time, k.time_to_guide.previous, "down", (value) => duration(value)),
      k.time_to_guide.spark, "var(--think)", t("dash.spark.time", { days: DASH.range })));
}

// Incidents over time --------------------------------------------------------------------

function roundedTop(x, y, width, height, radius) {
  const r = Math.min(radius, width / 2, height);
  return `M${x} ${y + height}V${y + r}Q${x} ${y} ${x + r} ${y}H${x + width - r}Q${x + width} ${y} ${x + width} ${y + r}V${y + height}Z`;
}

function trendCard(data) {
  const trend = data.trend;
  const days = trend.days;
  const totals = days.map((_, index) => STAGES.reduce((sum, stage) => sum + trend.series[stage][index], 0));
  const legend = el("div", { class: "legend" }, STAGES.map((stage, index) =>
    el("span", {}, el("i", { class: `swatch stage-${index + 1}` }), t(`dash.stage.${stage.replace(" ", "")}`))));
  const tableButton = el("button", { class: "btn ghost small", type: "button", "aria-pressed": String(DASH.table),
    text: t(DASH.table ? "dash.chart" : "dash.table"), onclick: () => { DASH.table = !DASH.table; drawDashboard(); } });
  const card = el("section", { class: "card pad chart-card" },
    el("div", { class: "card-head" }, el("h3", { text: t("dash.trend") }), el("span", { class: "spacer" }), legend, tableButton));
  const table = el("table", { class: "data-table" },
    el("caption", { class: "sr-only", text: t("dash.trend") }),
    el("thead", {}, el("tr", {}, el("th", { text: t("dash.day") }), STAGES.map((stage) => el("th", { text: t(`dash.stage.${stage.replace(" ", "")}`) })),
      el("th", { text: t("dash.total") }))),
    el("tbody", {}, days.map((day, index) => totals[index] || DASH.table ? el("tr", {}, el("td", { text: day }),
      STAGES.map((stage) => el("td", { text: String(trend.series[stage][index]) })), el("td", { text: String(totals[index]) })) : null)));
  if (DASH.table) { card.append(el("div", { class: "table-scroll" }, table)); return card; }

  const view = Math.min($("#view-dashboard").clientWidth, 1440);
  const width = Math.max(280, view > 1100 ? (view - 90) * 0.64 : view - 90), height = 190;
  const left = 30, right = 6, top = 8, bottom = 22;
  const max = Math.max(1, ...totals);
  const niceMax = max <= 4 ? max : Math.ceil(max / 4) * 4;
  const plotW = width - left - right, plotH = height - top - bottom;
  const slot = plotW / days.length;
  const barW = Math.max(3, Math.min(22, slot - (slot > 8 ? 4 : 2)));
  const chart = svg("svg", { class: "trend", width, height, viewBox: `0 0 ${width} ${height}`, role: "img",
    "aria-label": t("dash.trendLabel", { total: totals.reduce((a, b) => a + b, 0), days: days.length }) });
  const ticks = niceMax <= 4 ? niceMax : 4;
  for (let tick = 0; tick <= ticks; tick += 1) {
    const value = (niceMax / ticks) * tick;
    const y = top + plotH - (value / niceMax) * plotH;
    chart.append(svg("line", { x1: left, x2: width - right, y1: y, y2: y, class: tick ? "grid" : "baseline" }),
      svg("text", { x: left - 6, y: y + 3.5, "text-anchor": "end", class: "axis" }, document.createTextNode(String(Math.round(value)))));
  }
  const labelAt = [0, Math.floor((days.length - 1) / 2), days.length - 1];
  days.forEach((day, index) => {
    const x = left + index * slot + (slot - barW) / 2;
    let y = top + plotH;
    const segments = STAGES.map((stage, order) => ({ stage, order, value: trend.series[stage][index] })).filter((item) => item.value);
    segments.forEach((item, position) => {
      const h = (item.value / niceMax) * plotH;
      const gap = position < segments.length - 1 ? 2 : 0;  // a 2px surface gap between stacked fills
      y -= h;
      const drawn = Math.max(1, h - gap);
      chart.append(position === segments.length - 1
        ? svg("path", { d: roundedTop(x, y, barW, drawn, 3), class: `stage-${item.order + 1}` })
        : svg("rect", { x, y: y + gap, width: barW, height: drawn, class: `stage-${item.order + 1}` }));
    });
    if (labelAt.includes(index)) {
      chart.append(svg("text", { x: x + barW / 2, y: height - 6, "text-anchor": index === 0 ? "start" : index === days.length - 1 ? "end" : "middle",
        class: "axis" }, document.createTextNode(index === days.length - 1 ? t("dash.today") : day.slice(5))));
    }
    const hit = svg("rect", { x: left + index * slot, y: top, width: slot, height: plotH, class: "hit" });
    hit.addEventListener("pointermove", (event) => showTip(event,
      el("b", { text: new Date(`${day}T12:00:00`).toLocaleDateString(LANG === "ko" ? "ko-KR" : "en-US", { month: "short", day: "numeric", weekday: "short" }) }),
      ...STAGES.slice().reverse().map((stage) => el("div", { class: "tip-row" },
        el("i", { class: `swatch stage-${STAGES.indexOf(stage) + 1}` }), el("span", { text: t(`dash.stage.${stage.replace(" ", "")}`) }),
        el("b", { text: String(trend.series[stage][index]) }))),
      el("div", { class: "tip-row total" }, el("span", { text: t("dash.total") }), el("b", { text: String(totals[index]) }))));
    hit.addEventListener("pointerleave", hideTip);
    chart.append(hit);
  });
  card.append(el("div", { class: "chart-wrap" }, chart), el("div", { class: "sr-only" }, table));
  return card;
}

// Outcomes -------------------------------------------------------------------------------

function outcomesCard(data) {
  const outcomes = data.outcomes;
  const kinds = [["resolved", "ok", "✓"], ["partial", "warn", "!"], ["not_resolved", "bad", "✕"]];
  const total = kinds.reduce((sum, [kind]) => sum + outcomes[kind], 0);
  const card = el("section", { class: "card pad" },
    el("div", { class: "card-head" }, el("h3", { text: t("dash.outcomes") }), el("span", { class: "spacer" }),
      el("span", { class: "faint small", text: t("dash.recorded", { count: total }) })));
  if (!total) {
    card.append(el("p", { class: "faint", text: t("dash.noOutcomes") }));
    return card;
  }
  const bar = el("div", { class: "outcome-bar", role: "img",
    "aria-label": kinds.map(([kind]) => `${t(`outcome.${kind}`)} ${outcomes[kind]}`).join(", ") },
  kinds.filter(([kind]) => outcomes[kind]).map(([kind, tone]) => {
    const part = el("span", { class: `seg-${tone}`, style: `flex:${outcomes[kind]}` });
    part.addEventListener("pointermove", (event) => showTip(event, el("b", { text: t(`outcome.${kind}`) }),
      el("div", { text: `${outcomes[kind]} · ${pct(outcomes[kind] / total)}` })));
    part.addEventListener("pointerleave", hideTip);
    return part;
  }));
  card.append(bar, el("div", { class: "outcome-list" }, kinds.map(([kind, tone, mark]) => el("div", { class: "outcome-item" },
    el("span", { class: `status-mark ${tone}`, "aria-hidden": "true", text: mark }),
    el("span", { text: t(`outcome.${kind}`) }),
    el("b", { text: number(outcomes[kind]) }),
    el("span", { class: "faint small", text: pct(outcomes[kind] / total) })))),
  el("div", { class: "stat-line" }, el("span", { class: "faint", text: t("dash.turnsPerGuide") }),
    el("b", { text: outcomes.turns_per_guide === null ? "—" : String(outcomes.turns_per_guide) })));
  return card;
}

// Model and runtime ----------------------------------------------------------------------

function runtimeCard(data) {
  const runtime = data.runtime;
  const status = S.status;
  const state = !status ? "idle" : status.loaded ? "ok" : status.loading ? "warn" : status.reachable ? "warn" : "bad";
  const card = el("section", { class: "card pad" },
    el("div", { class: "card-head" }, el("h3", { text: t("dash.runtime") }), el("span", { class: "spacer" }),
      el("span", { class: "faint small", text: t("dash.lastRuns", { count: runtime.runs.length }) })),
    el("div", { class: "model-line" }, el("span", { class: `dot ${state}` }),
      el("span", { class: "mono name", text: status?.model || "—" }),
      el("span", { class: "faint small", text: status ? [status.backend, status.loaded ? t("dash.loaded") : status.detail || t("dash.notLoaded")].filter(Boolean).join(" · ") : "" })));
  if (runtime.runs.length) {
    const view = Math.min($("#view-dashboard").clientWidth, 1440);
    const width = Math.max(220, view > 1100 ? (view - 110) / 3 - 34 : view - 90), height = 64;
    const max = Math.max(...runtime.runs.map((run) => run.seconds), 1);
    const slot = width / runtime.runs.length;
    const barW = Math.max(4, Math.min(18, slot - 4));
    const chart = svg("svg", { class: "runs", width, height, viewBox: `0 0 ${width} ${height}`, role: "img",
      "aria-label": t("dash.runsLabel", { count: runtime.runs.length, median: dur(runtime.median_seconds) }) });
    runtime.runs.forEach((run, index) => {
      const h = Math.max(2, (run.seconds / max) * (height - 6));
      const x = index * slot + (slot - barW) / 2;
      chart.append(svg("path", { d: roundedTop(x, height - h, barW, h, 3),
        class: index === runtime.runs.length - 1 ? "run-bar last" : "run-bar" }));
      const hit = svg("rect", { x: index * slot, y: 0, width: slot, height, class: "hit" });
      hit.addEventListener("pointermove", (event) => showTip(event,
        el("b", { text: `${duration(run.seconds)}${run.guide ? "" : ` · ${t("dash.noGuide")}`}` }),
        el("div", { class: "tip-row" }, el("span", { text: t("dash.toolCalls") }), el("b", { text: String(run.tool_calls) })),
        el("div", { class: "tip-row" }, el("span", { text: t("dash.tokens") }), el("b", { text: `${number(run.input_tokens)} / ${number(run.output_tokens)}` })),
        run.citations_total ? el("div", { class: "tip-row" }, el("span", { text: t("dash.citations") }),
          el("b", { text: `${run.citations_ok}/${run.citations_total}` })) : null,
        el("div", { class: "faint small", text: `${run.model || ""} · ${(run.at || "").replace("T", " ").slice(0, 16)}` })));
      hit.addEventListener("pointerleave", hideTip);
      chart.append(hit);
    });
    if (runtime.median_seconds !== null) {
      const y = height - (runtime.median_seconds / max) * (height - 6);
      chart.append(svg("line", { x1: 0, x2: width, y1: y, y2: y, class: "median" }));
    }
    card.append(el("div", { class: "chart-wrap" }, chart),
      el("div", { class: "faint small median-note", text: t("dash.medianLine", { value: dur(runtime.median_seconds) }) }));
  } else {
    card.append(el("p", { class: "faint", text: t("dash.noRuns") }));
  }
  const stat = (value, label) => el("div", {}, el("b", { text: value }), el("span", { text: label }));
  card.append(el("div", { class: "stat-grid" },
    stat(dur(runtime.median_seconds), t("dash.medianRun")),
    stat(pct(runtime.citation_rate), t("dash.citationRate")),
    stat(runtime.tool_calls === null ? "—" : String(runtime.tool_calls), t("dash.toolCallsPerRun")),
    stat(runtime.tokens_in === null ? "—" : `${compact(runtime.tokens_in)} / ${compact(runtime.tokens_out)}`, t("dash.tokensInOut"))));
  return card;
}

function compact(n) {
  return new Intl.NumberFormat(LANG === "ko" ? "ko-KR" : "en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n || 0);
}

// Team activity --------------------------------------------------------------------------

function ledgerBadge(verification) {
  if (!verification) return el("span", { class: "chain unknown", title: t("dash.ledgerPendingTitle") }, icon("shield"), t("dash.ledgerPending"));
  if (!verification.ok) return el("span", { class: "chain bad", title: verification.reason }, icon("shield alert"),
    t("dash.ledgerBad", { seq: number(verification.first_bad) }));
  const at = verification.at ? new Date(verification.at).toLocaleString(LANG === "ko" ? "ko-KR" : "en-US", { dateStyle: "medium", timeStyle: "short" }) : "";
  return el("span", { class: "chain ok", title: t("dash.ledgerOkTitle", { at }) },
    icon("shield check"), t("dash.ledgerOk", { seq: number(verification.records) }));
}

function activitySentence(item) {
  const detail = item.detail || {};
  const vars = {
    actor: item.actor.name, incident: item.incident ? (item.incident.title || item.incident.id) : "",
    user: detail.user_name || item.target_name || "", outcome: detail.outcome ? t(`outcome.${detail.outcome}`) : "",
    count: detail.files ?? detail.sessions ?? detail.records ?? (detail.ids || []).length, turn: detail.turn ?? "",
    model: detail.model || "", role: detail.role ? t(`role.${detail.role}`) : "", drive: detail.drive || "",
  };
  const key = `activity.${item.action}`;
  return I18N.en[key] ? t(key, vars) : t("activity.other", { ...vars, action: item.action });
}

function activityItem(item) {
  const avatar = item.actor.kind === "user"
    ? el("span", { class: "avatar", style: `background:${avatarColor(item.actor.id)}`, text: initials(item.actor.name) })
    : el("span", { class: "avatar system", text: item.actor.kind === "cli" ? ">_" : "⏏" });
  const when = new Date(item.at);
  const sentence = el("div", { class: "act-text" }, el("b", { text: item.actor.name }), " ", activitySentence(item));
  if (item.incident && item.incident.title) {
    sentence.append(" ", el("a", { href: `#/incidents/${encodeURIComponent(item.incident.id)}`, text: item.incident.title }));
  }
  return el("li", { class: "act" }, avatar, sentence,
    el("div", { class: "act-meta" },
      el("time", { datetime: item.at, title: when.toLocaleString(LANG), text: relative(when) }),
      el("code", { title: t("dash.ledgerRecord"), text: `#${number(item.seq)}` })));
}

// "2 min. ago", "in 11 hr." — past or future, in the largest unit that fits.
function relative(date) {
  const seconds = (date.getTime() - Date.now()) / 1000;
  const size = Math.abs(seconds);
  const format = new Intl.RelativeTimeFormat(LANG === "ko" ? "ko" : "en", { numeric: "auto", style: "short" });
  if (size < 60) return format.format(Math.round(seconds), "second");
  if (size < 3600) return format.format(Math.round(seconds / 60), "minute");
  if (size < 86400) return format.format(Math.round(seconds / 3600), "hour");
  return format.format(Math.round(seconds / 86400), "day");
}

function activityCard() {
  const activity = DASH.activity || { items: [], verification: null };
  return el("section", { class: "card pad" },
    el("div", { class: "card-head" }, el("h3", { text: t("dash.activity") }), el("span", { class: "spacer" }), ledgerBadge(activity.verification)),
    activity.items.length
      ? el("ol", { class: "activity" }, activity.items.slice(0, 7).map(activityItem))
      : el("p", { class: "faint", text: t("dash.noActivity") }),
    isAdmin() ? el("div", { class: "card-foot" }, el("a", { class: "btn ghost small", href: "#/admin/audit", text: t("dash.fullLog") })) : null);
}

// Learning -------------------------------------------------------------------------------

function learningCard(data) {
  const learning = data.learning;
  const big = (value, label, tone = "") => el("div", { class: `big-stat ${tone}` }, el("b", { text: number(value) }), el("span", { text: label }));
  const card = el("section", { class: "card pad" },
    el("div", { class: "card-head" }, el("h3", { text: t("dash.learning") }), el("span", { class: "spacer" }),
      isAdmin() ? null : el("span", { class: "faint small", text: t("dash.learningCounts") })),
    el("div", { class: "big-stats" },
      isAdmin() ? big(learning.pending, t("dash.pending"), learning.pending ? "warn" : "") : null,
      big(learning.lessons, t("dash.lessons")), big(learning.cases, t("dash.cases"))));
  if (isAdmin()) {
    card.append(learning.recent.length
      ? el("ul", { class: "lessons" }, learning.recent.map((lesson) => el("li", {}, el("b", { text: t(`section.${lesson.section}`) }), ` · ${lesson.text}`)))
      : el("p", { class: "faint", text: t("learn.noLessons") }),
    el("div", { class: "card-foot" }, el("button", { class: `btn small ${learning.pending ? "primary" : ""}`, type: "button",
      text: learning.pending ? t("dash.review", { count: learning.pending }) : t("dash.openLearning"), onclick: openLearning })));
  } else {
    card.append(el("p", { class: "faint small", text: t("dash.learningMember") }));
  }
  return card;
}
