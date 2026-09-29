// blacksite://term — the operator console. A separate, keyboard-first interface over the same
// API as the default GUI: it signs in through /auth, reads /api, and streams investigations.
// Plain DOM, no dependencies, no inline scripts. Secrets never go into the URL or storage;
// command history lives in memory only.
"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const FX = window.FX;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined && child !== false) node.append(child instanceof Node ? child : String(child));
  }
  return node;
}

const S = {
  me: null, csrf: "", stage: null, cases: [], sel: 0, current: null, stream: null, live: null, status: null,
  history: [], back: -1, draft: "", heredoc: null, pendingFiles: null, ask: null, newTitle: null,
};

async function call(path, options = {}, retried = false) {
  const { json, form, method, raw } = options;
  const init = { credentials: "same-origin", headers: {}, method: method || (json !== undefined || form ? "POST" : "GET") };
  if (json !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(json); }
  if (form) init.body = form;
  if (init.method !== "GET" && S.csrf) init.headers["X-CSRF-Token"] = S.csrf;
  const response = await fetch(path, init);
  if (raw && response.ok) return response.blob();
  const data = await response.json().catch(() => ({}));
  // Sensitive admin actions want the password (and a code) again, as in the default GUI.
  if (response.status === 403 && data.confirm && !retried && S.me) {
    if (await confirmIdentity()) return call(path, options, true);
    throw new Error("not confirmed.");
  }
  if (data.csrf) S.csrf = data.csrf;
  if (!response.ok) {
    const error = new Error(data.error || `${response.status} ${response.statusText}`);
    error.status = response.status;
    error.login = Boolean(data.login);
    if (error.login && S.me) expired();
    throw error;
  }
  return data;
}

const pad = (n, w = 2) => String(n).padStart(w, "0");
const clock = (d = new Date()) => `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
const num = (n) => Number(n || 0).toLocaleString("en-US");
const idOf = (id) => encodeURIComponent(id);

const hhmm = (d) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
function tickClock() { for (const node of document.querySelectorAll("[data-clock]")) node.textContent = hhmm(new Date()); }
tickClock();
setInterval(tickClock, 5000);

// Access -----------------------------------------------------------------------------------
// A bare tty: prompts appear one at a time, Enter advances, Esc starts over, and nothing
// explains itself. Failures are a word. The sign-in steps are the default GUI's, unchanged.

function nope(word) {
  const box = $("#auth-error");
  box.hidden = !word;
  box.textContent = word || "";
}

// The server's reasons are for the ledger, not for whoever is guessing. Only a new passphrase
// that fails the policy gets its reason, because the operator has already proven who they are.
function oblique(error, explain) {
  const message = String(error.message || "");
  if (error.status === 429 || /\blocked\b|too many/i.test(message)) return error.login ? "again." : "wait.";
  if (explain && error.status === 400 && message) return `no. ${message.charAt(0).toLowerCase()}${message.slice(1)}`;
  return "no.";
}

function hello(text) { $("#hello").textContent = text; }

function show(...nodes) {
  nope("");
  $("#auth-step").replaceChildren(...nodes);
  $("#auth-step .row:not([hidden]) input")?.focus();
}

function tty(prompts, submit, { explain = false } = {}) {
  // No visible prompt: the block cursor is the prompt. Screen readers get the name.
  const rows = prompts.map(([name, attrs]) => {
    const input = el("input", { spellcheck: "false", autocapitalize: "none", autocomplete: "off", "aria-label": name, ...attrs });
    return { input, row: el("div", { class: "row" }, input) };
  });
  rows.slice(1).forEach((r) => { r.row.hidden = true; });
  let busy = false;
  const go = async (index) => {
    const current = rows[index];
    if (busy || !current || !current.input.value) return;
    if (index < rows.length - 1) {
      rows[index + 1].row.hidden = false;
      rows[index + 1].input.focus();
      return;
    }
    busy = true;
    nope("");
    try {
      await submit(rows.map((r) => r.input.value));
    } catch (error) {
      if (error.login) { S.csrf = ""; stagePassword(); nope(oblique(error, false)); return; }
      nope(oblique(error, explain));
      current.input.value = "";
      current.input.focus();
    } finally { busy = false; }
  };
  const form = el("form", { class: "tty-form", novalidate: true, onsubmit: (event) => { event.preventDefault(); go(rows.length - 1); } },
    rows.map((r) => r.row));
  form.addEventListener("keydown", (event) => {
    const index = rows.findIndex((r) => r.input === event.target);
    if (index < 0) return;
    if (event.key === "Enter") { event.preventDefault(); go(index); }
    if (event.key === "Escape") { event.preventDefault(); startOver(); }
  });
  return form;
}

async function startOver() {
  if (S.stage && S.stage !== "password") { try { await call("/auth/logout", { json: {} }); } catch { /* already gone */ } }
  S.csrf = "";
  stagePassword();
}

async function advance(stage) {
  S.stage = stage || "password";
  if (stage === "full") return granted();
  if (stage === "password_change") return stageRotate();
  if (stage === "totp_enroll") return stageEnroll();
  if (stage === "totp") return stageCode();
  return stagePassword();
}

function stagePassword() {
  S.stage = "password";
  hello("wake up, samurai.");
  show(tty([["user", { name: "username", autocomplete: "username" }], ["password", { name: "password", type: "password", autocomplete: "current-password" }]],
    async ([who, key]) => {
      const data = await call("/auth/login", { json: { username: who, password: key } });
      await advance(data.stage);
    }));
}

function stageRotate() {
  hello("key expired. set your own.");
  show(tty([["new password", { type: "password", autocomplete: "new-password" }], ["repeat new password", { type: "password", autocomplete: "new-password" }]],
    async ([fresh, again]) => {
      if (fresh !== again) throw Object.assign(new Error("They differ."), { status: 400 });
      const data = await call("/auth/password", { json: { new: fresh } });
      await advance(data.stage);
    }, { explain: true }));
}

async function stageEnroll() {
  hello("bind.");
  const setup = await call("/auth/totp/setup");
  show(el("div", { class: "qr-row" },
    el("img", { src: setup.qr, alt: "authenticator enrolment code", width: "144", height: "144" }),
    el("div", {}, el("div", { class: "faint", text: "seed" }), el("div", { class: "seed", text: setup.secret.match(/.{1,4}/g).join(" ") }))),
  tty([["code", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: "7" }]], async ([code]) => {
    const data = await call("/auth/totp/enroll", { json: { code } });
    stageKeys(data.recovery_codes, data.stage);
  }));
}

function stageKeys(codes, stage) {
  hello("recovery keys. shown once. y when stored.");
  const text = codes.join("\n");
  const yank = el("button", { class: "yank", type: "button", text: "[yank]", onclick: async () => {
    try { await navigator.clipboard.writeText(text); yank.textContent = "[yanked]"; } catch { yank.textContent = "[refused]"; }
  } });
  show(el("ol", { class: "keys" }, codes.map((item) => el("li", { text: item }))), yank,
    tty([["stored? y or n", {}]], async ([answer]) => {
      if (!/^y(es)?$/i.test(answer.trim())) throw Object.assign(new Error("Then keep them."), { status: 400 });
      await advance(stage);
    }, { explain: true }));
}

// One prompt takes either: six digits go to the authenticator check, anything else is a recovery key.
function stageCode() {
  hello("prove it.");
  show(tty([["code", { autocomplete: "one-time-code" }]], async ([code]) => {
    const recovery = /[^\d\s]/.test(code);
    const data = await call(recovery ? "/auth/recovery" : "/auth/totp/verify", { json: { code } });
    await advance(data.stage);
  }));
}

async function showAuth(stage, reason = "") {
  $("#console").hidden = true;
  $("#auth").hidden = false;
  document.title = "blacksite";
  document.body.classList.remove("in-console");
  FX.show(true);
  await advance(stage);
  if (reason) nope(reason);
}

async function granted() {
  S.stage = "full";
  await enterConsole();
}

function expired() {
  closeStream();
  S.me = null;
  showAuth("password", "again.");
}

// Console --------------------------------------------------------------------------------

const logBox = () => $("#log");

function line(kind, message, { cls = "", t = null } = {}) {
  const m = el("div", { class: `m${cls ? ` ${cls}` : ""}` });
  if (message instanceof Node) m.append(message); else m.textContent = message ?? "";
  const node = el("div", { class: `ln${kind === "cmd" ? " cmd" : ""}${kind === "err" ? " err" : ""}` },
    el("span", { class: "t", text: t ?? clock() }),
    el("span", { class: `k k-${kind}`, text: kind === "cmd" ? "" : kind.toUpperCase() }),
    m);
  append(node, kind === "cmd");
  return m;
}

function block(node) { append(node); return node; }

// Like a terminal: output keeps the view pinned to the bottom only if it was already there,
// so scrolling back to read is never yanked away. A command you type always jumps down.
function append(node, force = false) {
  const box = logBox();
  const pinned = force || box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  box.append(node);
  if (pinned) box.scrollTop = box.scrollHeight;
}

function follow() {
  const box = logBox();
  if (box.scrollHeight - box.scrollTop - box.clientHeight < 160) box.scrollTop = box.scrollHeight;
}

function ref(text, command) {
  return el("button", { class: "ref", type: "button", text, onclick: () => run(command) });
}

// Citations like app/app.log:3, kern.log:3, 6, or nginx/error.log:3-5 become clickable `cat`s.
function linkRefs(text) {
  const files = (S.current?.artifacts || []).map((a) => a.file).sort((a, b) => b.length - a.length);
  if (!files.length || !text) return [text || ""];
  const escaped = files.map((f) => f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const pattern = new RegExp(`(${escaped.join("|")}):(\\d+)(?:[-–](\\d+))?`, "g");
  const out = [];
  let at = 0;
  for (const match of text.matchAll(pattern)) {
    out.push(text.slice(at, match.index));
    const spec = `${match[1]}:${match[2]}${match[3] ? `-${match[3]}` : ""}`;
    out.push(ref(match[0], `cat ${spec}`));
    at = match.index + match[0].length;
  }
  out.push(text.slice(at));
  return out;
}

async function enterConsole() {
  S.me = await call("/api/me");
  S.csrf = S.me.csrf;
  $("#auth").hidden = true;
  $("#console").hidden = false;
  document.body.classList.add("in-console");
  document.title = "blacksite://term";
  $("#ps-user").textContent = S.me.user.username;
  document.body.classList.remove("saver");
  S.saver = false;
  lastInput = Date.now();
  $("#st-user").textContent = `${S.me.user.username}:${S.me.user.role}`;
  setTimeout(() => { if (!S.saver && !$("#console").hidden) FX.show(false); }, 950);
  if (!logBox().childElementCount) {
    line("sys", `blacksite://term attached · ${location.host} · session ${S.me.session.id.slice(0, 8)} · idle limit ${Math.round(S.me.session.idle_minutes)}m`);
    line("sys", "every command below runs against the same ledger as the default GUI. `help` for the verbs.");
  }
  await Promise.all([refreshStatus(), loadCases()]);
  members().catch(() => {});
  call("/api/models").then((data) => { S.models = data; }).catch(() => {});
  const wanted = decodeURIComponent(location.hash.replace(/^#\/?/, ""));
  if (wanted && S.cases.some((c) => c.id === wanted)) await openCase(wanted);
  else if (!S.current && S.cases.length) line("info", el("span", {}, `${S.cases.length} case(s) on file. `, ref("ls", "ls"), " to list, ", ref("open 1", "open 1"), " to load."));
  else if (!S.cases.length) line("info", el("span", {}, "No cases on file. ", ref("new", "new"), " or drop evidence files anywhere."));
  focusPrompt();
}

async function refreshStatus() {
  try { S.status = await call("/api/status"); } catch { S.status = null; }
  const seg = $("#st-model");
  const s = S.status;
  if (!s) { seg.textContent = "model:??"; seg.classList.add("down"); return; }
  const state = s.loading || s.switching ? "LOADING" : s.loaded ? "UP" : s.reachable ? "IDLE" : "DOWN";
  seg.textContent = `${s.model || "none"}@${(s.backend || s.provider || "?").toLowerCase()}:${state}`;
  seg.classList.toggle("down", state === "DOWN");
}
setInterval(() => { if (S.me && !document.hidden) refreshStatus(); }, 15000);

async function loadCases() {
  const data = await call("/api/incidents");
  S.cases = data.incidents;
  S.sel = Math.min(S.sel, Math.max(0, S.cases.length - 1));
  renderCases();
}

function caseState(c) { return c.running ? "running" : c.queued ? "queued" : c.status; }

function renderCases() {
  $("#case-count").textContent = `[${S.cases.length}]`;
  $("#case-list").replaceChildren(...S.cases.map((c, index) => {
    const state = caseState(c);
    return el("li", { class: `${index === S.sel ? "sel" : ""}${S.current && S.current.id === c.id ? " loaded" : ""}` },
      el("button", { type: "button", title: c.id, onclick: () => { S.sel = index; renderCases(); run(`open ${index + 1}`); } },
        el("span", { class: "title", text: c.title }),
        el("span", { class: "meta" },
          el("span", { class: `st-${state}`, text: state.toUpperCase() }),
          el("span", { text: c.id }),
          c.shared ? el("span", { text: "shared" }) : null,
          c.usb ? el("span", { text: "usb" }) : null)));
  }));
}

async function openCase(id, { quiet = false } = {}) {
  closeStream();
  const data = await call(`/api/incidents/${idOf(id)}`);
  S.current = data;
  S.sel = Math.max(0, S.cases.findIndex((c) => c.id === id));
  history.replaceState(null, "", `#/${idOf(id)}`);
  $("#ps-path").textContent = `~/cases/${id}`;
  $("#ops-title").textContent = `OPS // ${id}`;
  document.title = `${id} · blacksite://term`;
  renderCases();
  renderEvidence();
  if (!quiet) printDossier(data);
  if (data.running) attach(id, { resumed: true });
  setBusy(Boolean(data.running));
}

function printDossier(data) {
  const lines = data.artifacts.reduce((sum, a) => sum + a.lines, 0);
  const errors = data.artifacts.reduce((sum, a) => sum + a.errors, 0);
  const flagged = data.artifacts.reduce((sum, a) => sum + a.flagged, 0);
  const redacted = data.artifacts.reduce((sum, a) => sum + a.redactions, 0);
  line("ok", `case ${data.id} loaded · access=${data.access} · owner=${data.owner ? data.owner.name : "unassigned"}`);
  line("info", data.title, { cls: "inl" });
  if (data.description) line("info", data.description, { cls: "dim" });
  line("info", `${data.artifacts.length} files · ${num(lines)} lines · ${num(errors)} errors · ${redacted} secrets redacted · ${flagged} injection-flagged${data.range[0] ? ` · ${data.range[0]} → ${data.range[1]}` : ""}`);
  if (flagged) line("warn", `${flagged} line(s) flagged as possible prompt injection; the agent treats them as data.`);
  data.turns.forEach((turn, index) => replayTurn(turn, index));
  const last = [...data.turns].reverse().find((turn) => turn.events.some((e) => e.type === "guide"));
  if (!data.turns.length) line("info", el("span", {}, "No runs yet. ", ref("run", "run"), " to put the agent on it, or ", ref("ask <question>", "help ask"), "."));
  else if (last && !data.outcome && data.access !== "view") line("info", el("span", {}, "Close the loop when you've acted: ", ref("outcome resolved", "help outcome"), "."));
  if (data.outcome) line("ok", `outcome recorded: ${data.outcome.outcome}${data.outcome.notes ? ` — ${data.outcome.notes}` : ""}`);
}

function replayTurn(turn, index) {
  line("cmd", turn.message ? `ask ${turn.message}` : "run", { t: `#${index + 1}` });
  const calls = turn.events.filter((e) => e.type === "tool_call").length;
  const done = turn.events.find((e) => e.type === "done");
  line("sys", `replay · ${calls} tool calls${done ? ` · ${done.seconds.toFixed(1)}s · ${done.requests} requests` : ""}`, { t: `#${index + 1}` });
  for (const event of turn.events) {
    if (event.type === "guide") renderGuide(event);
    else if (event.type === "question") renderQuestion(event);
    else if (event.type === "error") line("err", event.message);
  }
}

// Evidence pane -----------------------------------------------------------------------------

const swatch = (i) => `var(--f${(i % 6) + 1})`;  // term.css; follows the colour scheme
const SVG = "http://www.w3.org/2000/svg";

function svg(tag, attrs = {}) {
  const node = document.createElementNS(SVG, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

// Warnings and errors per time bucket, stacked by file in the artifact colours, with a readout
// on hover. SVG rather than block characters, which drift out of line between fonts.
function timeChart(data) {
  const hist = data.histogram || { rows: [] };
  const parse = (text) => Date.parse(String(text || "").replace(" ", "T"));
  const t0 = parse(hist.start || data.range[0]);
  const span = parse(data.range[1]) - t0;
  let step = hist.bucket_seconds || 60;
  let n = Math.max(1, ...hist.rows.map((r) => r.bucket + 1), Number.isFinite(span) ? Math.ceil(span / 1000 / step) : 1);
  const group = Math.max(1, Math.ceil(n / 90));  // keep bars at least a few pixels wide
  n = Math.ceil(n / group);
  step *= group;
  const files = data.artifacts.map((a) => a.file);
  const stacks = Array.from({ length: n }, () => new Map());
  for (const row of hist.rows) {
    const bucket = Math.floor(row.bucket / group);
    if (bucket < n) stacks[bucket].set(row.file, (stacks[bucket].get(row.file) || 0) + row.count);
  }
  const totals = stacks.map((m) => [...m.values()].reduce((a, b) => a + b, 0));
  const peak = Math.max(1, ...totals);
  const at = (i) => (Number.isFinite(t0) ? hhmm(new Date(t0 + i * step * 1000)) : `#${i}`);
  const H = 64;
  const chart = svg("svg", { class: "chart", viewBox: `0 0 ${n} ${H}`, preserveAspectRatio: "none", "shape-rendering": "crispEdges",
    role: "img", "aria-label": `Warnings and errors over time, peak ${peak} per ${step} seconds` });
  chart.append(svg("line", { x1: 0, x2: n, y1: H / 2, y2: H / 2 }));
  const readout = el("div", { class: "readout" });
  stacks.forEach((m, i) => {
    let y = H;
    files.forEach((file, f) => {
      const count = m.get(file);
      if (!count) return;
      const h = Math.max(1, (count / peak) * (H - 2));
      y -= h;
      chart.append(svg("rect", { x: i + 0.14, y, width: 0.72, height: h, style: `fill:${swatch(f)}` }));
    });
    const hit = svg("rect", { class: "hit", x: i, y: 0, width: 1, height: H });
    hit.addEventListener("pointerenter", () => {
      const parts = files.filter((file) => m.get(file)).map((file) => `${file} ${m.get(file)}`);
      readout.textContent = `${at(i)}–${at(i + 1)}  ${totals[i]}${parts.length ? `  (${parts.join(", ")})` : ""}`;
    });
    chart.append(hit);
  });
  chart.addEventListener("pointerleave", () => { readout.textContent = ""; });
  return el("section", {},
    el("h5", {}, el("span", { text: `warn+err / ${step}s` }), el("span", { text: `peak ${peak}` })),
    chart,
    el("div", { class: "axis" }, el("span", { text: at(0) }), el("span", { text: at(n) })),
    readout);
}

function renderEvidence() {
  const data = S.current;
  const box = $("#ev");
  if (!data) { box.replaceChildren(el("div", { class: "faint", text: "no case loaded." })); $("#ev-state").textContent = ""; return; }
  $("#ev-state").textContent = `${data.artifacts.length} files`;
  const files = data.artifacts.map((a, i) => el("div", { class: "file" },
    el("span", { class: "sw", style: `background:${swatch(i)}` }),
    el("button", { class: "ref nm", type: "button", title: `cat ${a.file}`, text: a.file, onclick: () => run(`cat ${a.file}:1`) }),
    el("span", { class: "ct" }, `${num(a.lines)}L `, a.errors ? el("b", { text: `${a.errors}E` }) : "0E",
      a.redactions ? ` ${a.redactions}R` : "", a.flagged ? el("span", { class: "flag", text: ` ${a.flagged}⚠` }) : "")));
  const sigs = (data.patterns || []).slice(0, 10).map((p) => el("div", { class: "sig" },
    el("div", {}, el("span", { class: "cnt", text: `×${p.count} ` }), el("span", { class: `k-${p.level === "error" ? "err" : "warn"}`, text: `[${p.level}${p.guessed ? "?" : ""}] ` }),
      el("span", { class: "tpl", text: p.template })),
    el("div", { class: "at" }, ref(p.sample, `cat ${p.sample}`), ` · ${(p.first || "").slice(11, 16)}–${(p.last || "").slice(11, 16)}`)));
  box.replaceChildren(
    el("section", {}, el("h5", { text: "case" }), el("dl", { class: "kv" },
      el("dt", { text: "id" }), el("dd", { text: data.id }),
      el("dt", { text: "access" }), el("dd", { text: data.access }),
      el("dt", { text: "owner" }), el("dd", { text: data.owner ? data.owner.name : "—" }),
      el("dt", { text: "window" }), el("dd", { text: data.range[0] ? `${data.range[0].slice(5, 16)} → ${data.range[1].slice(11, 16)}` : "—" }),
      el("dt", { text: "runs" }), el("dd", { text: String(data.turns.length) }),
      el("dt", { text: "outcome" }), el("dd", { text: data.outcome ? data.outcome.outcome : "open" }))),
    el("section", {}, el("h5", { text: "artifacts" }), ...files),
    timeChart(data),
    sigs.length ? el("section", {}, el("h5", { text: "recurring signatures" }), ...sigs) : null);
}

// Investigation stream --------------------------------------------------------------------

function setBusy(on) {
  $("#prompt").classList.toggle("busy", on);
  $("#ops-state").textContent = on ? "● LIVE" : "";
  FX.busy(on);
}

function closeStream() { if (S.stream) { S.stream.close(); S.stream = null; } S.live = null; setBusy(false); }

const secs = (t) => (typeof t === "number" ? `+${t.toFixed(1)}s` : "");

function argText(args) {
  const parts = Object.entries(args || {}).filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => `${k}=${typeof v === "string" ? JSON.stringify(v) : v}`);
  return parts.join(" ");
}

function attach(id, { resumed = false } = {}) {
  closeStream();
  const live = { calls: new Map(), think: null, draft: null, draftText: "" };
  S.live = live;
  setBusy(true);
  line("sys", resumed ? "re-attached to a run in progress" : "run started");
  const source = new EventSource(`/api/incidents/${idOf(id)}/stream?from=0`);
  S.stream = source;
  source.onmessage = (message) => onEvent(live, JSON.parse(message.data));
  source.addEventListener("end", async () => {
    closeStream();
    await Promise.all([loadCases(), (async () => {
      S.current = await call(`/api/incidents/${idOf(id)}`);
      renderEvidence();
    })()]);
  });
  source.onerror = () => { if (source.readyState === EventSource.CLOSED) { closeStream(); line("err", "stream dropped. `open` the case again to re-attach."); } };
}

function onEvent(live, event) {
  const t = secs(event.t);
  switch (event.type) {
    case "start":
      line("info", `model=${event.model} think=${event.thinking} rag=${event.features.rag} cases=${event.features.cases} playbook=${event.features.playbook} lang=${event.language}`, { t });
      break;
    case "thinking":
      if (!live.think) live.think = line("think", "", { t, cls: "think" });
      live.think.textContent += event.delta;
      follow();
      break;
    case "text":
      live.think = null;
      if (!live.draft) live.draft = line("draft", "", { t, cls: "draft" });
      live.draftText += event.delta;
      live.draft.textContent = live.draftText.length > 600 ? `…${live.draftText.slice(-600)}` : live.draftText;
      follow();
      break;
    case "tool_call": {
      live.think = null;
      const m = line("call", el("span", {}, el("b", { text: event.name }), ` ${argText(event.args)} `, el("span", { class: "spin" })), { t });
      live.calls.set(event.id, m);
      break;
    }
    case "tool_result": {
      const pending = live.calls.get(event.id);
      if (pending) pending.querySelector(".spin")?.remove();
      const content = String(event.content || "");
      const rows = content.split("\n").length;
      const body = el("pre", { class: "ret-body", hidden: true, text: content });
      const toggle = el("button", { class: "fold", type: "button", text: `[+${rows} lines]`, onclick: () => {
        body.hidden = !body.hidden; toggle.textContent = body.hidden ? `[+${rows} lines]` : "[−]";
      } });
      line(event.error ? "err" : "ret", el("span", {}, `${event.name} ${event.error ? "✗" : "✓"} ${event.ms ?? "?"}ms `, toggle), { t });
      block(body);
      break;
    }
    case "retry":
      line("warn", `retry: ${String(event.reason || "").slice(0, 500)}`, { t });
      break;
    case "guide":
      if (live.draft) { live.draft.textContent = `draft folded (${num(live.draftText.length)} chars) → brief below`; live.draft = null; }
      line("guide", "brief ready", { t });
      renderGuide(event, true);
      break;
    case "question":
      if (live.draft) { live.draft = null; }
      line("q", "agent needs more evidence", { t });
      renderQuestion(event);
      break;
    case "done":
      line("done", `${event.seconds.toFixed(1)}s · ${event.requests} requests · ${event.tool_calls} tool calls · ${num(event.input_tokens)} in / ${num(event.output_tokens)} out tokens`, { t });
      break;
    case "error":
      line("err", event.message, { t });
      break;
  }
}

function copyButton(text) {
  const button = el("button", { type: "button", text: "yank", onclick: async () => {
    try { await navigator.clipboard.writeText(text); button.textContent = "yanked"; } catch { button.textContent = "denied"; }
    setTimeout(() => { button.textContent = "yank"; }, 1400);
  } });
  return button;
}

function renderGuide(event, fresh = false) {
  const g = event.guide;
  const sec = (label, ...content) => el("section", {}, el("h4", { text: label }), ...content);
  const list = (items, ordered = false) => el(ordered ? "ol" : "ul", {}, items.map((item) => el("li", {}, ...linkRefs(item))));
  const steps = (g.steps || []).map((step, i) => el("div", { class: `step${step.risk === "high" ? " risk-high-step" : ""}` },
    el("div", {}, el("span", { class: "step-title", text: `${i + 1}. ${step.title}` }), el("span", { class: `risk risk-${step.risk}`, text: step.risk.toUpperCase() })),
    step.why ? el("div", { class: "dim" }, ...linkRefs(step.why)) : null,
    ...(step.commands || []).map((command) => el("div", { class: "sh" }, el("code", { text: command }), copyButton(command))),
    step.expected ? el("div", { class: "faint", text: `expect: ${step.expected}` }) : null,
    step.rollback ? el("div", { class: "rollback", text: step.rollback }) : null));
  const brief = el("article", { class: "brief" },
    el("div", { class: "brief-head" }, el("span", { class: "lbl", text: `brief · ${S.current ? S.current.id : ""}` }),
      el("span", { class: `conf conf-${g.confidence}`, text: `confidence: ${g.confidence}` })),
    el("div", { class: "brief-body" },
      el("h3", { text: g.title }),
      el("p", {}, ...linkRefs(g.summary)),
      (event.checks || []).length ? el("div", { class: "checks" }, event.checks.map((c) => el("span", { class: `chk-${c.level}`, text: c.text }))) : null,
      sec("root cause", el("p", {}, ...linkRefs(g.root_cause))),
      (g.evidence || []).length ? sec("evidence", el("ul", {}, g.evidence.map((e) => el("li", {}, ...linkRefs(e.ref), " — ", ...linkRefs(e.shows))))) : null,
      steps.length ? sec("procedure", ...steps) : null,
      (g.verify || []).length ? sec("verify", list(g.verify)) : null,
      (g.unknowns || []).length ? sec("unknowns", list(g.unknowns)) : null,
      (g.security_notes || []).length ? sec("security", list(g.security_notes)) : null));
  block(brief);
}

function renderQuestion(event) {
  const r = event.request || {};
  line("q", r.reason || "the agent is asking for more output.");
  for (const q of r.questions || []) line("q", `? ${q}`);
  for (const command of r.commands || []) block(el("div", { class: "sh", style: "margin-left:16ch" }, el("code", { text: command }), copyButton(command)));
  line("info", el("span", {}, "Run those on the box, then ", ref("reply", "reply"), " and paste the output (end with EOF or Ctrl-D)."));
}

// grep ------------------------------------------------------------------------------------
// Server-side RE2 search; the browser only re-finds the match to highlight it. RE2 syntax the
// browser's RegExp can't parse just goes unhighlighted.

function highlighter(pattern, { literal, sensitive }) {
  try {
    const source = literal ? pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") : pattern;
    return new RegExp(source, sensitive ? "g" : "gi");
  } catch { return null; }
}

function marked(text, re) {
  if (!re) return [text];
  const out = [];
  let at = 0;
  for (const match of text.matchAll(re)) {
    if (!match[0]) continue;
    out.push(text.slice(at, match.index), el("mark", { text: match[0] }));
    at = match.index + match[0].length;
  }
  out.push(text.slice(at));
  return out;
}

// Finder ----------------------------------------------------------------------------------
// fzf-style: characters must appear in order; runs and word starts score higher. The best
// match sits next to the prompt.

function fuzzy(query, text) {
  if (!query) return { score: 0, hits: [] };
  const q = query.toLowerCase(), t = text.toLowerCase();
  let score = 0, from = 0, last = -2;
  const hits = [];
  for (const ch of q) {
    const at = t.indexOf(ch, from);
    if (at < 0) return null;
    score += at === last + 1 ? 5 : 1;
    if (at === 0 || /[\s/._:-]/.test(t[at - 1])) score += 3;
    hits.push(at);
    last = at;
    from = at + 1;
  }
  return { score: score - t.length * 0.01, hits };
}

function openFinder(title, items, pick) {
  closeFinder(false);
  const input = el("input", { spellcheck: "false", autocapitalize: "none", "aria-label": title });
  const list = el("div", { class: "finder-list", role: "listbox" });
  const count = el("span", { class: "n" });
  const box = el("div", { class: "finder" }, list,
    el("div", { class: "finder-bar" }, el("span", { class: "ps", text: `${title}>` }), input, count));
  let shown = [], index = 0;
  const choose = () => { const hit = shown[index]; closeFinder(); if (hit) pick(hit.item); };
  const render = () => {
    shown = input.value
      ? items.map((item) => ({ item, m: fuzzy(input.value, item.label) })).filter((x) => x.m).sort((a, b) => b.m.score - a.m.score)
      : items.map((item) => ({ item, m: { hits: [] } }));
    shown = shown.slice(0, 300);
    index = Math.min(index, Math.max(0, shown.length - 1));
    count.textContent = `${shown.length}/${items.length}`;
    list.replaceChildren(...shown.map(({ item, m }, i) => {
      const hits = new Set(m.hits);
      return el("div", { class: `finder-item${i === index ? " on" : ""}`, role: "option", "aria-selected": String(i === index),
        onmousedown: (event) => { event.preventDefault(); index = i; choose(); } },
        el("span", {}, ...[...item.label].map((ch, j) => (hits.has(j) ? el("b", { text: ch }) : ch))),
        el("span", { class: "d", text: item.detail || "" }));
    }));
    list.querySelector(".on")?.scrollIntoView({ block: "nearest" });
  };
  input.addEventListener("input", () => { index = 0; render(); });
  input.addEventListener("keydown", (event) => {
    const key = event.key, ctrl = event.ctrlKey;
    if (key === "ArrowUp" || (ctrl && (key === "p" || key === "k"))) { event.preventDefault(); index = Math.min(shown.length - 1, index + 1); render(); }
    else if (key === "ArrowDown" || (ctrl && (key === "n" || key === "j"))) { event.preventDefault(); index = Math.max(0, index - 1); render(); }
    else if (key === "Enter" || key === "Tab") { event.preventDefault(); choose(); }
    else if (key === "Escape" || (ctrl && (key === "c" || key === "g"))) { event.preventDefault(); closeFinder(); }
  });
  input.addEventListener("blur", () => setTimeout(() => { if (S.finder === box) closeFinder(); }, 120));
  S.finder = box;
  document.body.append(box);
  render();
  input.focus();
}

function closeFinder(refocus = true) {
  if (!S.finder) return;
  S.finder.remove();
  S.finder = null;
  if (refocus) focusPrompt();
}

function historyFinder() {
  const seen = [...new Set([...S.history].reverse())];
  if (!seen.length) { line("info", "no history yet."); return; }
  openFinder("history", seen.map((text) => ({ label: text })), (item) => { cmd().value = item.label; focusPrompt(); });
}

function findAnything() {
  const items = [
    ...S.cases.map((c) => ({ label: c.id, detail: c.title, go: `open ${c.id}` })),
    ...(S.current?.artifacts || []).map((a) => ({ label: a.file, detail: `${a.lines} lines · ${a.errors} errors`, go: `cat ${a.file}` })),
    ...Object.entries(COMMANDS).filter(([, c]) => !c.alias).map(([name, c]) => ({ label: name, detail: c.desc, insert: `${name} ` })),
  ];
  openFinder("find", items, (item) => {
    if (item.go) run(item.go);
    else { cmd().value = item.insert; focusPrompt(); }
  });
}

// Pager -----------------------------------------------------------------------------------
// less over the scrollback: j/k, d/u, space/b, g/G, / to search, n/N between matches.

function enterPager() {
  if (S.paging) return;
  S.paging = true;
  $("#console").classList.add("paging");
  $("#hint").textContent = "j/k · d/u · g/G · / search · n/N · q quit";
  cmd().blur();
}

function exitPager() {
  if (!S.paging) return;
  S.paging = false;
  S.searching = false;
  $("#console").classList.remove("paging");
  $("#hint").textContent = "tab completes · ↑↓ history · help";
  clearFound();
  setPS("");
  focusPrompt();
}

function clearFound() {
  for (const mark of logBox().querySelectorAll("mark.find")) mark.replaceWith(mark.textContent);
  logBox().normalize();
  S.found = [];
}

function findInLog(query) {
  clearFound();
  if (!query) return;
  const q = query.toLowerCase();
  const walker = document.createTreeWalker(logBox(), NodeFilter.SHOW_TEXT, {
    acceptNode: (node) => (node.parentElement.closest("[hidden]") ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT),
  });
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const node of nodes) {
    const text = node.nodeValue, lower = text.toLowerCase();
    let at = lower.indexOf(q);
    if (at < 0) continue;
    const parts = [];
    let from = 0;
    while (at >= 0) {
      parts.push(text.slice(from, at), el("mark", { class: "find", text: text.slice(at, at + q.length) }));
      from = at + q.length;
      at = lower.indexOf(q, from);
    }
    parts.push(text.slice(from));
    node.replaceWith(...parts);
  }
  S.found = [...logBox().querySelectorAll("mark.find")];
  const top = logBox().getBoundingClientRect().top;
  S.foundAt = Math.max(0, S.found.findIndex((mark) => mark.getBoundingClientRect().top > top + 4));
  showFound();
}

function showFound(step = 0) {
  if (!S.found.length) { $("#hint").textContent = "pattern not found · q quit"; return; }
  S.found[S.foundAt]?.classList.remove("cur");
  S.foundAt = (S.foundAt + step + S.found.length) % S.found.length;
  const mark = S.found[S.foundAt];
  mark.classList.add("cur");
  mark.scrollIntoView({ block: "center" });
  $("#hint").textContent = `match ${S.foundAt + 1}/${S.found.length} · n/N · q quit`;
}

function pagerKey(event) {
  const box = logBox();
  const page = box.clientHeight - 40;
  const moves = {
    j: 22, ArrowDown: 22, k: -22, ArrowUp: -22, d: page / 2, u: -page / 2,
    " ": page, f: page, PageDown: page, b: -page, PageUp: -page,
  };
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  if (event.key in moves) box.scrollBy(0, moves[event.key]);
  else if (event.key === "g" || event.key === "Home") box.scrollTop = 0;
  else if (event.key === "G" || event.key === "End") box.scrollTop = box.scrollHeight;
  else if (event.key === "n") showFound(1);
  else if (event.key === "N") showFound(-1);
  else if (event.key === "/") { S.searching = true; setPS("/"); cmd().value = ""; cmd().focus(); }
  else if (event.key === "q" || event.key === "Escape" || event.key === "i" || event.key === "Enter") exitPager();
  else return;
  event.preventDefault();
  event.stopPropagation();
}

// Screensaver and lock --------------------------------------------------------------------
// While you work the console is plain. After a few idle minutes the rain takes the screen;
// any key or click brings it back. `lock` ends the session under the rain.

let idleMinutes = 3;
try { const saved = localStorage.getItem("blacksite.term.idle"); if (saved) idleMinutes = saved === "off" ? 0 : Number(saved) || 3; } catch { /* storage unavailable */ }
let lastInput = Date.now();
const pointerAt = { x: -1, y: -1 };

function sleep() {
  if (S.saver) return;
  S.saver = true;
  closeFinder(false);
  FX.show(true);
  document.body.classList.add("saver");
}

function wake() {
  if (!S.saver) return;
  S.saver = false;
  document.body.classList.remove("saver");
  lastInput = Date.now();
  if (S.locked) { S.locked = false; showAuth("password"); return; }
  setTimeout(() => { if (!S.saver && !$("#console").hidden) FX.show(false); }, 950);
  focusPrompt();
}

setInterval(() => {
  if (S.me && !S.saver && idleMinutes && !$("#console").hidden && Date.now() - lastInput > idleMinutes * 60000) sleep();
}, 5000);

// Colour schemes -------------------------------------------------------------------------

const SCHEMES = { matrix: "green phosphor (default)", tokyonight: "Tokyo Night", gruvbox: "gruvbox dark", nord: "Nord" };

function applyScheme(name) {
  if (name === "matrix") delete document.documentElement.dataset.scheme;
  else document.documentElement.dataset.scheme = name;
  FX.recolor();
}

function storedScheme() {
  try { const saved = localStorage.getItem("blacksite.term.colors"); return saved in SCHEMES ? saved : "matrix"; } catch { return "matrix"; }
}

// Tables and lookups for the admin and settings commands -----------------------------------

function table(headers, rows) {
  return block(el("table", { class: "table" }, el("tr", {}, headers.map((h) => el("th", { text: h }))),
    rows.map((row) => el("tr", {}, row.map((cell) => (cell instanceof Node ? el("td", {}, cell)
      : el("td", { class: typeof cell === "number" ? "n" : "", text: cell ?? "—" })))))));
}

function kv(pairs) {
  return block(el("dl", { class: "help" }, pairs.flatMap(([key, value]) =>
    [el("dt", { text: key }), el("dd", {}, value instanceof Node ? value : String(value ?? "—"))])));
}

const when = (value) => {
  if (value === null || value === undefined || value === "") return "—";
  const d = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${hhmm(d)}`;
};
const bytes = (n) => (!n ? "—" : n >= 1e9 ? `${(n / 1e9).toFixed(1)}G` : n >= 1e6 ? `${(n / 1e6).toFixed(0)}M` : `${Math.ceil(n / 1e3)}K`);
const isAdmin = () => S.me?.user.role === "admin";
const totpAvailable = () => S.me?.auth?.totp_enabled !== false;

async function members() {
  if (!S.members) S.members = (await call("/api/members")).members;
  return S.members;
}

async function memberNamed(name) {
  const found = (await members()).find((m) => m.username === name || String(m.id) === name);
  if (!found) throw new Error(`no such user: ${name}`);
  return found;
}

async function userNamed(name) {
  const users = (await call("/api/admin/users")).users;
  const found = users.find((u) => u.username === name || String(u.id) === name);
  if (!found) throw new Error(`no such user: ${name}`);
  return found;
}

const SWITCHES = { thinking: ["none", "low", "medium"], rag: ["off", "tool", "inject"], cases: ["off", "tool", "inject"],
  playbook: ["off", "on"], language: ["en", "ko"] };

function modelIds() {
  return (S.models?.backends || []).flatMap((b) => b.models.map((m) => [`${b.id}/${m.id}`, `${m.label}${m.in_use ? " (in use)" : ""}`]));
}

function download(blob, name) {
  const url = URL.createObjectURL(blob);
  el("a", { href: url, download: name }).click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// Commands -------------------------------------------------------------------------------

function need(access = "view") {
  if (!S.current) throw new Error("no case loaded. `open <n>` first.");
  const rank = { view: 1, investigate: 2, manage: 3 };
  if (rank[S.current.access] < rank[access]) throw new Error(`EPERM: ${S.current.access}-only access to ${S.current.id}.`);
}

function resolveCase(arg) {
  if (!arg) return S.cases[S.sel]?.id;
  if (/^\d+$/.test(arg)) return S.cases[Number(arg) - 1]?.id;
  const exact = S.cases.find((c) => c.id === arg);
  if (exact) return exact.id;
  const partial = S.cases.filter((c) => c.id.startsWith(arg));
  return partial.length === 1 ? partial[0].id : null;
}

async function startRun(message = "", pasted = "") {
  need("investigate");
  if (S.live) throw new Error("EBUSY: a run is already streaming on this case.");
  await call(`/api/incidents/${idOf(S.current.id)}/turn`, { json: { message, pasted } });
  attach(S.current.id);
  loadCases();
}

const COMMANDS = {
  help: {
    args: "[verb]", desc: "this list",
    run([verb]) {
      if (verb && COMMANDS[verb]) { line("info", `${verb} ${COMMANDS[verb].args || ""} — ${COMMANDS[verb].desc}${COMMANDS[verb].more ? `\n${COMMANDS[verb].more}` : ""}`); return; }
      for (const [group, names] of Object.entries(GROUPS)) {
        const shown = names.filter((name) => COMMANDS[name] && (group !== "admin" || isAdmin()) && (name !== "totp" || totpAvailable()));
        if (!shown.length) continue;
        line("sys", group);
        block(el("dl", { class: "help" }, shown.flatMap((name) =>
          [el("dt", { text: `${name} ${COMMANDS[name].args || ""}` }), el("dd", { text: COMMANDS[name].desc })])));
      }
      line("info", "keys: tab complete · ↑↓ history · ctrl-r search history · ctrl-t find anything · esc on an empty prompt scrolls (less keys) · pgup too · ctrl-n/p select case · ctrl-o load it · ctrl-c cancel · ctrl-l clear · drag files in to open a case");
    },
  },
  "?": { alias: "help", run: (a) => COMMANDS.help.run(a) },
  ls: {
    desc: "list cases",
    run() {
      if (!S.cases.length) { line("info", "no cases."); return; }
      block(el("table", { class: "table" }, el("tr", {}, ["#", "id", "state", "owner", "title"].map((h) => el("th", { text: h }))),
        S.cases.map((c, i) => el("tr", {}, el("td", { class: "n", text: String(i + 1) }), el("td", {}, ref(c.id, `open ${c.id}`)),
          el("td", { class: `st-${caseState(c)}`, text: caseState(c) }), el("td", { text: c.owner || "—" }), el("td", { class: "wrap", text: c.title })))));
    },
  },
  open: {
    args: "<n|id>", desc: "load a case into the console",
    async run([arg]) {
      const id = resolveCase(arg);
      if (!id) throw new Error(`ENOENT: no such case: ${arg ?? "(none selected)"}`);
      await openCase(id);
    },
    complete: () => S.cases.map((c) => [c.id, c.title]),
  },
  cd: { alias: "open", run: (a) => COMMANDS.open.run(a), complete: () => COMMANDS.open.complete() },
  run: {
    args: "[note]", desc: "dispatch the agent on the loaded case",
    more: "The note is passed along as what you already know. Same as the default GUI's Investigate.",
    run: (args) => startRun(args.join(" ")),
  },
  x: { alias: "run", run: (a) => COMMANDS.run.run(a) },
  ask: {
    args: "<question>", desc: "follow-up question on the loaded case",
    run(args) { if (!args.length) throw new Error("ask what?"); return startRun(args.join(" ")); },
  },
  reply: {
    desc: "paste command output the agent asked for (heredoc; EOF or ctrl-d sends)",
    run() {
      need("investigate");
      S.heredoc = [];
      setPS("heredoc>");
      line("sys", "heredoc open. paste or type output. `EOF` on its own line (or ctrl-d) sends, ctrl-c aborts.");
    },
  },
  cat: {
    args: "<file>[:line[-end]]", desc: "print evidence lines with context",
    async run([spec]) {
      need();
      if (!spec) throw new Error("cat what? e.g. cat kern.log:3");
      const match = spec.match(/^(.+?)(?::(\d+)(?:[-–](\d+))?)?$/);
      const file = match[1];
      if (!S.current.artifacts.some((a) => a.file === file)) throw new Error(`ENOENT: ${file}`);
      const start = Number(match[2] || 1), end = Number(match[3] || start);
      const data = await call(`/api/incidents/${idOf(S.current.id)}/lines?file=${encodeURIComponent(file)}&line=${start}&end=${end}&context=${match[2] ? 8 : 30}`);
      block(el("div", { class: "cat" },
        el("div", { class: "cat-head" }, el("span", { text: `${file}:${data.focus[0]}${data.focus[1] !== data.focus[0] ? `-${data.focus[1]}` : ""}` }), el("span", { text: `${data.total} lines` })),
        data.lines.map((row) => el("div", { class: `cat-row lv-${row.level || "none"}${row.flagged ? " flagged" : ""}${row.n >= data.focus[0] && row.n <= data.focus[1] && match[2] ? " focus" : ""}` },
          el("span", { class: "no", text: String(row.n) }), el("span", { class: "tx", text: row.text })))));
    },
    complete: () => (S.current?.artifacts || []).map((a) => [a.file, `${a.lines} lines, ${a.errors} errors`]),
  },
  files: {
    desc: "artifacts in the loaded case",
    run() {
      need();
      block(el("table", { class: "table" }, el("tr", {}, ["file", "lines", "errors", "redacted", "flagged", "first", "last"].map((h) => el("th", { text: h }))),
        S.current.artifacts.map((a) => el("tr", {}, el("td", {}, ref(a.file, `cat ${a.file}`)), el("td", { class: "n", text: num(a.lines) }), el("td", { class: "n", text: String(a.errors) }),
          el("td", { class: "n", text: String(a.redactions) }), el("td", { class: "n", text: String(a.flagged) }), el("td", { text: a.first || "—" }), el("td", { text: a.last || "—" })))));
    },
  },
  sig: {
    args: "[n]", desc: "top recurring log signatures",
    run([n]) {
      need();
      const rows = (S.current.patterns || []).slice(0, Number(n) || 12);
      block(el("table", { class: "table" }, el("tr", {}, ["count", "level", "where", "signature"].map((h) => el("th", { text: h }))),
        rows.map((p) => el("tr", {}, el("td", { class: "n", text: `×${p.count}` }), el("td", { text: p.level }), el("td", {}, ref(p.sample, `cat ${p.sample}`)), el("td", { class: "wrap", text: p.template })))));
    },
  },
  brief: {
    desc: "reprint the latest incident brief",
    run() {
      need();
      const event = [...S.current.turns].reverse().flatMap((turn) => [...turn.events].reverse()).find((e) => e.type === "guide");
      if (!event) throw new Error("no brief yet. `run` first.");
      renderGuide(event, true);
    },
  },
  dl: {
    desc: "download the brief as Markdown",
    run() {
      need();
      el("a", { href: `/api/incidents/${idOf(S.current.id)}/guide.md`, download: `${S.current.id}-guide.md` }).click();
      line("ok", `${S.current.id}-guide.md → downloads`);
    },
  },
  outcome: {
    args: "<resolved|partial|failed> [notes]", desc: "record what actually happened; feeds learning",
    async run([what, ...notes]) {
      need("investigate");
      const map = { resolved: "resolved", partial: "partial", failed: "not_resolved", not_resolved: "not_resolved" };
      if (!map[what]) throw new Error("outcome resolved|partial|failed [notes]");
      const data = await call(`/api/incidents/${idOf(S.current.id)}/outcome`, { json: { outcome: map[what], notes: notes.join(" "), root_cause: "" } });
      line("ok", `outcome=${map[what]} · case ${data.case} · ${data.added.length + data.merged.length} lesson(s) proposed · ${data.approved ? "auto-approved" : "awaiting admin review"}`);
      await openCase(S.current.id, { quiet: true });
    },
    complete: () => [["resolved", "fixed it"], ["partial", "helped, not fixed"], ["failed", "wrong or no help"]],
  },
  new: {
    args: "[title]", desc: "open a new case: title, then pick evidence files",
    async run(args) {
      const title = args.join(" ").trim();
      if (S.pendingFiles) { if (!title) throw new Error("title?"); return createCase(title, S.pendingFiles); }
      if (!title) { const named = await ask("title:"); if (named) COMMANDS.new.run([named]); return; }
      S.newTitle = title;
      $("#upload").click();
      line("sys", "select evidence files… (or drag them in)");
    },
  },
  status: {
    desc: "model runtime",
    async run() {
      await refreshStatus();
      const s = S.status;
      if (!s) throw new Error("status unavailable");
      block(el("dl", { class: "help" }, Object.entries({ version: s.version, backend: s.backend, model: s.model, endpoint: s.base_url,
        reachable: s.reachable, loaded: s.loaded, thinking: s.thinking, rag: s.features.rag, cases: s.features.cases, playbook: s.features.playbook, detail: s.detail })
        .flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: String(v ?? "—") })])));
    },
  },
  whoami: {
    desc: "current user and session",
    run() {
      const u = S.me.user;
      line("info", `${u.username} (${u.display_name}) · role=${u.role} · totp=${totpAvailable() ? u.totp_enabled ? "on" : "OFF" : "off for everyone"} · session=${S.me.session.id.slice(0, 12)}… · expires ${new Date(S.me.session.expires_at * 1000).toLocaleString()}`);
    },
  },
  fx: {
    args: "<on|off> | idle <minutes|off>", desc: "background rain, and when the screensaver starts",
    run([mode, value]) {
      if (mode === "idle") {
        const minutes = value === "off" ? 0 : Number(value);
        if (value !== "off" && !(minutes > 0)) throw new Error("fx idle <minutes|off>");
        idleMinutes = minutes;
        try { localStorage.setItem("blacksite.term.idle", value === "off" ? "off" : String(minutes)); } catch { /* storage unavailable */ }
        line("ok", minutes ? `screensaver after ${minutes}m idle` : "screensaver off");
        return;
      }
      if (mode !== "on" && mode !== "off") throw new Error("fx on|off, or fx idle <minutes|off>");
      FX.setWanted(mode === "on");
      line("ok", `fx ${mode}${mode === "on" && !FX.on ? " (your system asks for reduced motion; honouring it)" : ""}`);
    },
    complete: () => [["on", ""], ["off", ""], ["idle", "minutes before the screensaver"]],
  },
  model: {
    args: "[use <provider/model> | stop]", desc: "list local models; switch, or stop the managed server",
    async run([sub, target]) {
      if (sub === "use") {
        if (!target) throw new Error("model use <provider/model>   (tab completes)");
        if (!S.models) S.models = await call("/api/models");
        let [provider, name] = target.includes("/") ? [target.slice(0, target.indexOf("/")), target.slice(target.indexOf("/") + 1)] : [null, target];
        if (!provider) provider = S.models.backends.find((b) => b.models.some((m) => m.id === name))?.id;
        if (!provider) throw new Error(`no such model: ${target}`);
        const m = line("sys", el("span", {}, `switching to ${provider}/${name} `, el("span", { class: "spin" })));
        try { S.models = await call("/api/models", { json: { provider, model: name } }); }
        finally { m.querySelector(".spin")?.remove(); }
        line("ok", `model: ${S.models.current.provider}/${S.models.current.name}`);
        await refreshStatus();
        return;
      }
      if (sub === "stop") {
        S.models = await call("/api/models", { json: { action: "stop" } });
        line("ok", "managed model server stopped.");
        await refreshStatus();
        return;
      }
      if (sub) throw new Error("model [use <provider/model> | stop]");
      const data = S.models = await call("/api/models");
      line("info", `current: ${data.current.provider}/${data.current.name} · ${data.current.base_url}${data.managed.running ? ` · managed server: ${data.managed.provider}/${data.managed.model}` : ""}`);
      const rows = [];
      for (const b of data.backends) {
        const state = !b.installed ? "not installed" : b.running ? "running" : "stopped";
        rows.push([el("b", { text: b.name }), state, b.base_url, "", "", b.detail || ""]);
        for (const m of b.models) {
          rows.push([`${m.in_use ? "* " : "  "}${b.id}/${m.id}`, m.usable ? "usable" : "unusable", m.source || "", bytes(m.size),
            m.context ? `${Math.round(m.context / 1024)}k ctx` : "", m.note || (m.thinking ? "thinking" : "")]);
        }
      }
      table(["model", "state", "source", "size", "context", "note"], rows);
      line("info", "switch with: model use <provider/model>");
    },
    complete: (args) => (args[0] === "use" ? modelIds() : [["use", "switch model"], ["stop", "stop the managed server"]]),
  },
  set: {
    args: "[switch value]", desc: "agent switches: thinking, rag, cases, playbook, language",
    async run([key, value]) {
      if (!key) {
        const data = await call("/api/settings");
        kv(Object.entries(data.switches).map(([k, v]) => [k, `${v}${SWITCHES[k] ? `   (${SWITCHES[k].join("|")})` : ""}`]));
        line("info", `features: ${Object.entries(data.features).map(([k, v]) => `${k} ${v}`).join(" · ")}`);
        return;
      }
      if (!(key in SWITCHES)) throw new Error(`unknown switch: ${key}. one of ${Object.keys(SWITCHES).join(", ")}`);
      if (!SWITCHES[key].includes(value)) throw new Error(`set ${key} ${SWITCHES[key].join("|")}`);
      const data = await call("/api/settings", { json: { [key]: value } });
      line("ok", `${key}=${data.switches[key]}`);
      await refreshStatus();
    },
    complete: (args) => (args.length ? (SWITCHES[args[0]] || []).map((v) => [v, ""]) : Object.entries(SWITCHES).map(([k, v]) => [k, v.join("|")])),
  },
  share: {
    args: "[user]", desc: "who can see the case; share it with someone",
    async run([name]) {
      need(name ? "manage" : "view");
      if (!name) {
        const shares = S.current.shares || [];
        line("info", `owner: ${S.current.owner ? S.current.owner.name : "unassigned"} · shared with: ${shares.length ? shares.map((u) => u.name).join(", ") : "nobody"}`);
        return;
      }
      const user = await memberNamed(name);
      await call(`/api/incidents/${idOf(S.current.id)}/share`, { json: { user_id: user.id, action: "share" } });
      line("ok", `shared ${S.current.id} with ${user.username}`);
      await openCase(S.current.id, { quiet: true });
    },
    complete: () => (S.members || []).map((m) => [m.username, m.display_name]),
  },
  unshare: {
    args: "<user>", desc: "take someone's access to the case away",
    async run([name]) {
      need("manage");
      if (!name) throw new Error("unshare <user>");
      const user = await memberNamed(name);
      await call(`/api/incidents/${idOf(S.current.id)}/share`, { json: { user_id: user.id, action: "unshare" } });
      line("ok", `unshared ${S.current.id} from ${user.username}`);
      await openCase(S.current.id, { quiet: true });
    },
    complete: () => (S.current?.shares || []).map((u) => [(S.members || []).find((m) => m.id === u.id)?.username || String(u.id), u.name]),
  },
  owner: {
    args: "<user|none>", desc: "assign the case to someone (admin)",
    async run([name]) {
      need();
      if (!name) throw new Error("owner <user|none>");
      const ownerId = name === "none" ? null : (await memberNamed(name)).id;
      await call(`/api/admin/incidents/${idOf(S.current.id)}`, { json: { owner_id: ownerId } });
      line("ok", `owner of ${S.current.id}: ${name}`);
      await openCase(S.current.id, { quiet: true });
    },
    complete: () => [["none", "unassigned"], ...(S.members || []).map((m) => [m.username, m.display_name])],
  },
  reset: {
    desc: "start the case over: forget its runs, keep the evidence",
    async run() {
      need("manage");
      if (!(await confirm(`forget every run on ${S.current.id}?`))) { line("sys", "kept."); return; }
      await call(`/api/incidents/${idOf(S.current.id)}/reset`, { method: "POST" });
      line("ok", "runs cleared.");
      await openCase(S.current.id);
    },
  },
  wipe: {
    desc: "delete the case and its evidence for good (admin)",
    async run() {
      need("manage");
      const id = S.current.id;
      const typed = await ask(`type ${id} to wipe it:`);
      if (typed !== id) { line("sys", "not wiped."); return; }
      await call(`/api/incidents/${idOf(id)}/wipe`, { method: "POST" });
      line("ok", `${id} wiped.`);
      closeStream();
      S.current = null;
      history.replaceState(null, "", "#");
      setPS("");
      $("#ops-title").textContent = "OPS";
      renderEvidence();
      await loadCases();
    },
  },
  export: {
    args: "[en|ko]", desc: "write the solution back to the case's USB drive",
    async run([language]) {
      need("manage");
      const data = await call(`/api/incidents/${idOf(S.current.id)}/export`, { json: { language: language || S.me.user.language || "en" } });
      line("ok", `exported to ${data.path} (${data.files.length} files)${data.wiped ? "; the case was wiped from this machine" : ""}`);
      if (data.wiped) await loadCases();
    },
  },
  prov: {
    args: "[run#]", desc: "signed provenance of a run's brief: signature, evidence hashes",
    async run([n]) {
      need();
      const signed = (S.current.provenance || []).map((p, i) => (p ? i + 1 : 0)).filter(Boolean);
      const turn = n ? Number(n) : signed[signed.length - 1];
      if (!turn) throw new Error("no brief on this case yet.");
      const data = await call(`/api/incidents/${idOf(S.current.id)}/provenance?turn=${turn}`);
      const { manifest, check } = data;
      const verdict = (ok, good, bad) => el("span", { class: ok === null ? "k-warn" : ok ? "k-ok" : "k-err", text: ok === null ? "not checked" : ok ? good : bad });
      kv([
        ["signature", verdict(check.signature, `valid · key ${check.key_fingerprint}`, "INVALID")],
        ["brief", verdict(check.guide, "matches what was signed", "CHANGED since signing")],
        ["evidence", verdict(check.evidence === "unknown" ? null : check.evidence === "unchanged", "unchanged", "CHANGED")],
        ["ran by", data.actor_name || manifest.actor],
        ["when", `${when(manifest.started_at)} → ${when(manifest.finished_at)}`],
        ["model", `${manifest.model.provider}/${manifest.model.name}`],
        ["switches", Object.entries(manifest.settings).map(([k, v]) => `${k}=${v}`).join(" ")],
        ["citations", `${manifest.checks.citations_ok}/${manifest.checks.citations_total} verified`],
        ["ledger", `anchored at #${manifest.ledger_anchor.seq}`],
        ["guide sha256", manifest.guide_sha256],
        ["evidence root", manifest.evidence_root],
      ]);
      table(["file", "bytes", "sha256", "status"], check.files.map((f) => [f.file, bytes(f.bytes), f.sha256.slice(0, 16), f.status]));
      line("info", `verify offline: blacksite verify ${S.current.id}/provenance/turn-${turn}.json`);
    },
    complete: () => (S.current?.provenance || []).map((p, i) => (p ? [String(i + 1), p.signed ? "signed" : "unsigned"] : null)).filter(Boolean),
  },
  dash: {
    args: "[7|30|90] [mine|shared|all]", desc: "team numbers: open, awaiting, resolved, time to brief",
    async run(args) {
      const range = args.find((a) => /^\d+$/.test(a)) || "30";
      const scope = args.find((a) => /^(mine|shared|all)$/.test(a)) || (isAdmin() ? "all" : "mine");
      const d = await call(`/api/dashboard?range=${range}&scope=${scope}`);
      const pct = (v) => (v === null || v === undefined ? "—" : `${Math.round(v * 100)}%`);
      const mins = (v) => (v === null || v === undefined ? "—" : v < 90 ? `${Math.round(v)}s` : `${(v / 60).toFixed(1)}m`);
      kv([
        ["window", `${d.range} days · ${d.scope}`],
        ["open", `${d.kpis.open.value} (${d.kpis.open.created ?? 0} new)`],
        ["awaiting outcome", d.kpis.awaiting.value],
        ["resolved rate", pct(d.kpis.resolved_rate.value)],
        ["median time to brief", mins(d.kpis.time_to_guide.value)],
        ["outcomes", `${d.outcomes.resolved} resolved · ${d.outcomes.partial} partial · ${d.outcomes.not_resolved} not resolved`],
        ["runs", `${d.runtime.runs.length} · median ${mins(d.runtime.median_seconds)} · citations ${pct(d.runtime.citation_rate)} · ${num(d.runtime.tokens_in)} in / ${num(d.runtime.tokens_out)} out tokens`],
        ["learning", `${d.learning.pending} pending · ${d.learning.lessons} lessons · ${d.learning.cases} past cases`],
        ["now", `${d.running} running · ${d.attention} need attention · ${d.incidents} cases`],
      ]);
    },
    complete: () => [["7", "days"], ["30", "days"], ["90", "days"], ["mine", ""], ["shared", ""], ["all", "admin"]],
  },
  activity: {
    args: "[n]", desc: "what people and the agent did, newest first",
    async run([n]) {
      const d = await call(`/api/activity?limit=${Math.min(200, Number(n) || 30)}`);
      table(["#", "when", "who", "did", "on"], d.items.map((item) => [item.seq, when(item.at), item.actor?.name || item.actor?.kind || "—",
        item.action, item.target_name || item.incident || ""]));
      if (d.verification) line(d.verification.ok ? "ok" : "err", `ledger: ${d.verification.reason}`);
    },
  },
  learn: {
    args: "[approve|reject <id…|all>]", desc: "review what the agent proposes to learn from outcomes",
    async run([action, ...ids]) {
      let data = await call("/api/learning");
      const pending = [...data.cases, ...data.bullets].filter((item) => item.status === "pending");
      if (action === "approve" || action === "reject") {
        const chosen = ids[0] === "all" ? pending.map((item) => item.id) : ids;
        if (!chosen.length) throw new Error(`learn ${action} <id…|all>`);
        data = await call("/api/learning", { json: { ids: chosen, action } });
        line("ok", `${action === "approve" ? "approved" : "rejected"} ${chosen.length}.`);
        return;
      }
      if (action) throw new Error("learn [approve|reject <id…|all>]");
      if (!pending.length) line("info", "nothing waiting for review.");
      for (const c of data.cases.filter((x) => x.status === "pending")) {
        line("q", `${c.id} · case · ${c.outcome} · ${c.title}`);
        line("info", `symptoms: ${c.symptoms}\nroot cause: ${c.root_cause}\n${c.outcome === "resolved" ? "fix" : "tried"}: ${c.resolution}${c.lessons.length ? `\nlessons: ${c.lessons.join(" / ")}` : ""}`, { cls: "dim" });
      }
      for (const b of data.bullets.filter((x) => x.status === "pending")) line("q", `${b.id} · lesson (${b.section}) · ${b.text}`);
      const active = data.bullets.filter((b) => b.status === "active");
      const approved = data.cases.filter((c) => c.status === "approved");
      line("info", `${active.length} active lessons · ${approved.length} approved past cases${pending.length ? " · approve or reject with: learn approve <id…|all>" : ""}`);
    },
    complete: (args) => (args.length ? [["all", "every pending item"]] : [["approve", ""], ["reject", ""]]),
  },
  users: {
    args: "[add <name> <member|admin> [display…] | role <name> <role> | suspend|activate|resetpw|resettotp <name>]",
    desc: "accounts (admin)",
    async run([sub, name, ...rest]) {
      if (!sub) {
        const users = (await call("/api/admin/users")).users;
        table(["id", "user", "name", "role", "status", "totp", "last login", "sessions", "cases"], users.map((u) => [u.id, u.username, u.display_name, u.role,
          `${u.status}${u.locked_until ? " (locked)" : ""}${u.must_change ? " (must change)" : ""}`, totpAvailable() ? u.totp_enabled ? "on" : "off" : "off for everyone", when(u.last_login_at), u.sessions, u.incidents]));
        return;
      }
      if (sub === "add") {
        const [role, ...display] = rest;
        if (!name || !["member", "admin"].includes(role)) throw new Error("users add <name> <member|admin> [display name]");
        const data = await call("/api/admin/users", { json: { username: name, role, display_name: display.join(" ") || name } });
        S.members = null;
        line("ok", `created ${data.user.username} (${data.user.role}).`);
        line("warn", `temporary passphrase, shown once: ${data.temporary_password}`);
        return;
      }
      const actions = { role: "role", suspend: "suspend", activate: "activate", resetpw: "reset_password", resettotp: "reset_totp" };
      if (!actions[sub] || !name) throw new Error(this.args);
      const user = await userNamed(name);
      const body = { action: actions[sub] };
      if (sub === "role") {
        if (!["member", "admin"].includes(rest[0])) throw new Error("users role <name> <member|admin>");
        body.role = rest[0];
      }
      if (["suspend", "resetpw", "resettotp"].includes(sub) && !(await confirm(`${sub} ${user.username}?`))) { line("sys", "left alone."); return; }
      const data = await call(`/api/admin/users/${user.id}`, { json: body });
      line("ok", `${sub} ${user.username}: done.`);
      if (data.temporary_password) line("warn", `temporary passphrase, shown once: ${data.temporary_password}`);
    },
    complete: (args) => (args.length === 0
      ? [["add", ""], ["role", ""], ["suspend", ""], ["activate", ""], ["resetpw", ""], ["resettotp", ""]]
      : args.length === 1 && args[0] !== "add" ? (S.members || []).map((m) => [m.username, m.display_name])
        : args[0] === "role" || args[0] === "add" ? [["member", ""], ["admin", ""]] : []),
  },
  sessions: {
    args: "[revoke <id>]", desc: "signed-in sessions (admin)",
    async run([sub, id]) {
      if (sub === "revoke") {
        const list = (await call("/api/admin/sessions")).sessions;
        const found = list.filter((x) => x.id.startsWith(id || "\0"));
        if (found.length !== 1) throw new Error(found.length ? "ambiguous id; use more characters." : `no session ${id}`);
        await call(`/api/admin/sessions/${found[0].id}/revoke`, { method: "POST" });
        line("ok", `revoked ${found[0].id.slice(0, 12)} (${found[0].user.username}).`);
        return;
      }
      const d = await call("/api/admin/sessions");
      table(["id", "user", "stage", "started", "last seen", "expires", ""], d.sessions.map((x) => [x.id.slice(0, 12), x.user.username, x.stage,
        when(x.created_at), when(x.last_seen_at), when(x.expires_at), x.current ? "this one" : x.ended_at ? `ended: ${x.end_reason}` : ""]));
      line("info", `idle limit ${Math.round(d.idle_minutes)}m · revoke with: sessions revoke <id>`);
    },
  },
  audit: {
    args: "[n | verify | anchor | export]", desc: "the signed ledger (admin)",
    async run([sub]) {
      if (sub === "verify") {
        const r = await call("/api/admin/audit/verify", { method: "POST" });
        line(r.ok ? "ok" : "err", r.reason);
        return;
      }
      if (sub === "anchor") {
        const r = await call("/api/admin/audit/anchor", { method: "POST" });
        line("ok", `anchored #${r.anchor.seq} · ${r.anchor.hash.slice(0, 16)} · key ${r.anchor.fingerprint || r.anchor.key_id}`);
        return;
      }
      if (sub === "export") {
        const blob = await call("/api/admin/audit/export", { method: "POST", raw: true });
        download(blob, `blacksite-ledger-${new Date().toISOString().slice(0, 10)}.ndjson`);
        line("ok", "ledger exported → downloads");
        return;
      }
      const d = await call(`/api/admin/audit?limit=${Math.min(500, Number(sub) || 40)}`);
      table(["#", "when", "who", "action", "target", "hash"], d.records.map((r) => [r.seq, when(r.at), r.actor_name || r.actor, r.action, r.target || "", r.hash.slice(0, 10)]));
      line("info", `head #${d.head}`);
    },
    complete: () => [["verify", "check the hash chain"], ["anchor", "sign the current head"], ["export", "download ndjson"]],
  },
  health: {
    desc: "security posture of this install (admin)",
    async run() {
      const h = await call("/api/admin/health");
      kv([
        ["listening", `${h.host}${h.loopback ? " (loopback only)" : " (NOT loopback)"}`],
        ["data dirs private", h.private ? "yes" : "NO"],
        ["signing key", h.keys ? h.signing_key : "missing"],
        ["accounts", `${h.admins} admins · ${h.members} members · ${h.locked} locked · ${h.suspended} suspended`],
        totpAvailable() ? ["admins without totp", h.admins_without_totp] : ["two-step sign-in", "temporarily off for everyone"],
        ["failed sign-ins, 24h", h.failed_24h],
        ["active sessions", `${h.active_sessions} · ${h.session_hours}h max · ${h.idle_minutes}m idle`],
        ["ledger", `${h.ledger.records} records${h.ledger.broken ? " · BROKEN" : ""}`],
        ["last verification", h.last_verification ? `${h.last_verification.ok ? "ok" : "FAILED"} · ${h.last_verification.reason}` : "never"],
        ["anchor", h.anchor ? `#${h.anchor.seq} · ${when(h.anchor.at)}` : "none"],
      ]);
    },
  },
  usb: {
    desc: "USB mode: drives, queue, recent events (admin)",
    async run() {
      const u = await call("/api/usb");
      line("info", `usb mode ${u.enabled ? "on" : "off"} · marker "${u.marker}"`);
      if (u.drives.length) table(["drive", "path", "state"], u.drives.map((d) => [d.label || d.drive || "?", d.path || d.mount || "", d.state || d.status || ""]));
      if (u.queue.length) line("info", `queued: ${u.queue.map((q) => q.incident || q.id || JSON.stringify(q)).join(", ")}`);
      for (const e of u.events.slice(-10)) line("info", `${e.kind} ${e.drive || ""} ${e.message || e.incident || ""}`);
    },
  },
  passwd: {
    desc: "change your passphrase",
    async run() {
      const current = await ask("current passphrase:", { secret: true });
      if (current === null) return;
      const fresh = await ask("new passphrase:", { secret: true });
      if (fresh === null) return;
      const again = await ask("again:", { secret: true });
      if (again === null) return;
      if (fresh !== again) throw new Error("they differ. nothing changed.");
      await call("/auth/password", { json: { current, new: fresh } });
      line("ok", "passphrase changed. other sessions were signed out.");
    },
  },
  totp: {
    desc: "bind a new authenticator (replaces the old one)",
    async run() {
      if (!totpAvailable()) { line("info", "two-step sign-in is temporarily off for everyone. existing authenticator setups are saved."); return; }
      if (!(await confirm("replace your authenticator?"))) { line("sys", "kept."); return; }
      const setup = await call("/auth/totp/setup");
      block(el("div", { class: "qr-row", style: "margin-left:16ch" },
        el("img", { src: setup.qr, alt: "authenticator enrolment code", width: "144", height: "144" }),
        el("div", {}, el("div", { class: "faint", text: "seed" }), el("div", { class: "seed", text: setup.secret.match(/.{1,4}/g).join(" ") }))));
      const code = await ask("code:");
      if (code === null) return;
      const data = await call("/auth/totp/enroll", { json: { code } });
      line("ok", "authenticator bound. new recovery keys, shown once:");
      block(el("ol", { class: "keys", style: "margin-left:16ch" }, data.recovery_codes.map((k) => el("li", { text: k }))));
      S.me = await call("/api/me");
    },
  },
  grep: {
    args: "[-F] [-l level] [-m n] <pattern> [file]", desc: "search the evidence (RE2, smart case)",
    more: "-F fixed string · -l warning|error|critical minimum level · -m max lines (default 100)\nlowercase pattern ignores case; any uppercase makes it case-sensitive. click a line to cat it.",
    async run(args) {
      need();
      const opts = { literal: false, level: "", limit: 100 };
      const rest = [];
      for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === "-F") opts.literal = true;
        else if (a === "-l") opts.level = args[++i] || "";
        else if (a === "-m") opts.limit = Number(args[++i]) || 100;
        else if (a === "--") { rest.push(...args.slice(i + 1)); break; }
        else rest.push(a);
      }
      const [pattern, file] = rest;
      if (!pattern) throw new Error("usage: grep [-F] [-l level] [-m n] <pattern> [file]");
      if (file && !S.current.artifacts.some((a) => a.file === file)) throw new Error(`ENOENT: ${file}`);
      const sensitive = /[A-Z]/.test(pattern);
      const params = new URLSearchParams({ pattern, limit: String(opts.limit) });
      if (file) params.set("file", file);
      if (opts.level) params.set("level", opts.level);
      if (opts.literal) params.set("literal", "1");
      if (sensitive) params.set("case", "1");
      const data = await call(`/api/incidents/${idOf(S.current.id)}/search?${params}`);
      if (!data.lines.length) { line("info", "no matches."); return; }
      const re = highlighter(pattern, { literal: opts.literal, sensitive });
      const files = S.current.artifacts.map((a) => a.file);
      const out = el("div", { class: "grep" });
      let current = null;
      for (const row of data.lines) {
        if (row.file !== current) {
          current = row.file;
          out.append(el("div", { class: "grep-file", style: `color:${swatch(files.indexOf(current))}`, text: current }));
        }
        out.append(el("div", { class: `grep-row lv-${row.level || "none"}`, title: `cat ${row.file}:${row.n}`, onclick: () => run(`cat ${row.file}:${row.n}`) },
          el("span", { class: "no", text: String(row.n) }), el("span", { class: "tx" }, ...marked(row.text, re))));
      }
      block(out);
      line("info", data.total > data.lines.length
        ? `${data.total} matches, showing ${data.lines.length}. raise -m, or narrow with a file or -l.`
        : `${data.total} match${data.total === 1 ? "" : "es"}.`);
    },
    complete: () => (S.current?.artifacts || []).map((a) => [a.file, `${a.lines} lines`]),
  },
  less: { desc: "scroll mode over the log (also: esc on an empty prompt)", run() { enterPager(); } },
  hist: { desc: "fuzzy-search command history (ctrl-r)", run() { historyFinder(); } },
  find: { desc: "fuzzy-find a case, file, or command (ctrl-t)", run() { findAnything(); } },
  replay: {
    args: "[run#] [speed]", desc: "play a past run back, call by call",
    more: "speed is a multiplier (default 8); pauses are capped at 1.5s. ctrl-c stops.",
    async run([n, speed]) {
      need();
      const turns = S.current.turns;
      if (!turns.length) throw new Error("no runs to replay.");
      const index = n ? Number(n) - 1 : turns.length - 1;
      const turn = turns[index];
      if (!turn) throw new Error(`no run #${n}; ${turns.length} on file.`);
      if (S.live || S.replay) throw new Error("EBUSY: something is already streaming.");
      const rate = Math.max(1, Number(speed) || 8);
      const token = { stop: false };
      S.replay = token;
      $("#ops-state").textContent = `▶ replay #${index + 1} ${rate}x`;
      line("sys", `replay run #${index + 1}${turn.message ? ` (“${turn.message}”)` : ""} at ${rate}x · ctrl-c stops`);
      const live = { calls: new Map(), think: null, draft: null, draftText: "" };
      let previous = 0;
      (async () => {
      try {
        for (const event of turn.events) {
          const t = typeof event.t === "number" ? event.t : previous;
          const delay = Math.min(1500, Math.max(0, ((t - previous) * 1000) / rate));
          previous = t;
          if (delay) await new Promise((r) => setTimeout(r, delay));
          if (token.stop) break;
          onEvent(live, event);
        }
      } finally {
        S.replay = null;
        $("#ops-state").textContent = "";
      }
      line("sys", token.stop ? "replay stopped." : "replay done.");
      })();
    },
    complete: () => (S.current?.turns || []).map((t, i) => [String(i + 1), t.message || "run"]),
  },
  colors: {
    args: "[name]", desc: "colour scheme; the rain follows",
    run([name]) {
      const current = storedScheme();
      if (!name) {
        block(el("dl", { class: "help" }, Object.entries(SCHEMES).flatMap(([key, label]) =>
          [el("dt", { text: `${key === current ? "*" : " "} ${key}` }), el("dd", { text: label })])));
        return;
      }
      if (!(name in SCHEMES)) throw new Error(`unknown scheme: ${name}. try: ${Object.keys(SCHEMES).join(", ")}`);
      applyScheme(name);
      try { localStorage.setItem("blacksite.term.colors", name); } catch { /* storage unavailable */ }
      line("ok", `colors: ${name}`);
    },
    complete: () => Object.entries(SCHEMES),
  },
  cmatrix: { desc: "start the screensaver now", run() { sleep(); } },
  lock: {
    desc: "end the session and blank the screen",
    async run() {
      closeStream();
      try { await call("/auth/logout", { json: {} }); } catch { /* already gone */ }
      S.me = null; S.csrf = ""; S.locked = true;
      logBox().replaceChildren();
      sleep();
    },
  },
  clear: { desc: "clear the scrollback", run() { logBox().replaceChildren(); } },
  gui: { desc: "open the default GUI in a new tab", run() { window.open(`/${S.current ? `#/incidents/${idOf(S.current.id)}` : ""}`, "_blank", "noopener"); } },
  logout: {
    desc: "end the session",
    async run() {
      closeStream();
      try { await call("/auth/logout", { json: {} }); } catch { /* already gone */ }
      S.me = null; S.csrf = ""; S.current = null;
      logBox().replaceChildren();
      showAuth("password");
    },
  },
  exit: { alias: "logout", run: () => COMMANDS.logout.run() },
};

const GROUPS = {
  cases: ["ls", "open", "new", "share", "unshare", "owner", "reset", "wipe", "export", "outcome", "brief", "dl", "prov"],
  evidence: ["files", "cat", "grep", "sig"],
  agent: ["run", "ask", "reply", "replay", "model", "set", "status", "learn"],
  team: ["dash", "activity"],
  admin: ["users", "sessions", "audit", "health", "usb"],
  you: ["whoami", "passwd", "totp", "lock", "logout"],
  console: ["help", "hist", "find", "less", "clear", "colors", "fx", "cmatrix", "gui"],
};

async function createCase(title, files) {
  S.pendingFiles = null;
  const form = new FormData();
  form.append("title", title);
  form.append("description", "");
  for (const file of files) form.append("files", file, file.name);
  const m = line("sys", el("span", {}, `indexing ${files.length} file(s) for “${title}” `, el("span", { class: "spin" })));
  try {
    const data = await call("/api/incidents", { form });
    m.querySelector(".spin")?.remove();
    await loadCases();
    await openCase(data.id);
  } catch (error) { m.querySelector(".spin")?.remove(); throw error; }
}

// Prompt -----------------------------------------------------------------------------------

const cmd = () => $("#cmd");
function setPS(mode) {
  const ps = $(".ps1");
  ps.classList.toggle("asking", Boolean(mode));
  $("#ps-ask").textContent = mode || "";
  $("#ps-path").textContent = S.current ? `~/cases/${S.current.id}` : "~/cases";
}

// A question on the prompt line. Secret answers are masked, never echoed, never in history.
function ask(label, { secret = false } = {}) {
  return new Promise((resolve) => {
    S.ask = { label, secret, done: resolve };
    setPS(label);
    const input = cmd();
    input.type = secret ? "password" : "text";
    input.value = "";
    focusPrompt();
  });
}

function endAsk(value) {
  const pending = S.ask;
  if (!pending) return;
  S.ask = null;
  cmd().type = "text";
  setPS("");
  pending.done(value);
}

async function confirm(question) {
  const answer = await ask(`${question} [y/N]`);
  return /^y(es)?$/i.test(String(answer || "").trim());
}

async function confirmIdentity() {
  line("sys", "this action needs a fresh confirmation.");
  const password = await ask("password:", { secret: true });
  if (password === null) return false;
  let code = "";
  if (totpAvailable() && S.me?.user.totp_enabled) {
    code = await ask("code:");
    if (code === null) return false;
  }
  try { await call("/auth/confirm", { json: { password, code } }, true); line("ok", "confirmed."); return true; }
  catch (error) { line("err", error.message); return false; }
}
function focusPrompt() { const input = cmd(); if (input && !$("#console").hidden) input.focus(); }

function tokenize(text) {
  const out = [];
  for (const match of text.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)) out.push(match[1] ?? match[2] ?? match[3]);
  return out;
}

// Commands run one after another, like a shell: each echo sits right above its own output.
let queue = Promise.resolve();
function run(text) {
  const job = queue.then(() => execute(text));
  queue = job.catch(() => {});
  return job;
}

async function execute(text) {
  text = text.trim();
  if (!text) return;
  line("cmd", text);
  S.history.push(text);
  S.back = -1;
  const [verb, ...args] = tokenize(text);
  const command = COMMANDS[verb];
  if (!command) { line("err", `blacksite: command not found: ${verb}`); return; }
  try { await command.run(args); } catch (error) { line("err", error.message); }
}

// Tab completion: verbs first, then the verb's own candidates.
let completion = null;
function candidates(value) {
  const parts = value.split(/\s+/);
  if (parts.length <= 1) return { base: "", word: parts[0], list: Object.entries(COMMANDS).filter(([name, c]) => !c.alias && (name !== "totp" || totpAvailable())).map(([n, c]) => [n, c.desc]) };
  const command = COMMANDS[parts[0]];
  const word = parts[parts.length - 1];
  return { base: `${parts.slice(0, -1).join(" ")} `, word, list: command && command.complete ? command.complete(parts.slice(1, -1)) : [] };
}

function complete(backward = false) {
  const input = cmd();
  if (!completion) {
    const { base, word, list } = candidates(input.value);
    const hits = list.filter(([name]) => name.startsWith(word));
    if (!hits.length) return;
    if (hits.length === 1) { input.value = `${base}${hits[0][0]} `; return; }
    let prefix = hits[0][0];
    for (const [name] of hits) while (!name.startsWith(prefix)) prefix = prefix.slice(0, -1);
    completion = { base, hits, index: -1 };
    input.value = `${base}${prefix}`;
    showCompletion();
    return;
  }
  completion.index = (completion.index + (backward ? -1 : 1) + completion.hits.length) % completion.hits.length;
  input.value = `${completion.base}${completion.hits[completion.index][0]}`;
  showCompletion();
}

function showCompletion() {
  const box = $("#complete");
  if (!completion) { box.hidden = true; return; }
  box.replaceChildren(...completion.hits.map(([name, desc], i) => el("div", { class: i === completion.index ? "on" : "" },
    el("span", { text: name }), el("span", { text: desc || "" }))));
  box.hidden = false;
  box.querySelector(".on")?.scrollIntoView({ block: "nearest" });
}
function endCompletion() { completion = null; showCompletion(); }

async function submitPrompt(event) {
  event.preventDefault();
  const input = cmd();
  const value = input.value;
  input.value = "";
  endCompletion();
  if (S.searching) { S.searching = false; setPS(""); input.blur(); findInLog(value.trim()); return; }
  if (S.heredoc) {
    if (value.trim() === "EOF") return sendHeredoc();
    S.heredoc.push(value);
    line("draft", value, { t: "<<" });
    return;
  }
  if (S.ask) { line("cmd", `${S.ask.label} ${S.ask.secret ? "(hidden)" : value}`); endAsk(value); return; }
  await run(value);
}

async function sendHeredoc() {
  const text = S.heredoc.join("\n");
  S.heredoc = null;
  setPS("");
  line("sys", `sending ${text.split("\n").length} line(s) of output`);
  try { await startRun("Here is the output you asked for.", text); } catch (error) { line("err", error.message); }
}

function onPromptKey(event) {
  const input = cmd();
  if (S.searching) {
    if (event.key === "Escape") { event.preventDefault(); S.searching = false; input.value = ""; setPS(""); input.blur(); }
    return;
  }
  if (event.ctrlKey && event.key === "r") { event.preventDefault(); historyFinder(); return; }
  if (event.ctrlKey && event.key === "t") { event.preventDefault(); findAnything(); return; }
  if (event.key === "PageUp") { event.preventDefault(); enterPager(); logBox().scrollBy(0, -(logBox().clientHeight - 40)); return; }
  if (event.key === "Escape" && !input.value && !completion && !S.heredoc && !S.ask) { event.preventDefault(); enterPager(); return; }
  if (event.ctrlKey && event.key === "c" && S.replay && input.selectionStart === input.selectionEnd) { event.preventDefault(); S.replay.stop = true; return; }
  if (event.key === "Tab") { event.preventDefault(); if (!S.heredoc && !S.ask) complete(event.shiftKey); return; }
  if (completion && event.key !== "Shift") { if (event.key === "Escape") { event.preventDefault(); endCompletion(); return; } endCompletion(); }
  if (event.ctrlKey && event.key === "d" && S.heredoc) { event.preventDefault(); sendHeredoc(); return; }
  if (event.ctrlKey && event.key === "c" && (S.heredoc || S.ask || S.pendingFiles) && input.selectionStart === input.selectionEnd) {
    event.preventDefault(); S.heredoc = null; S.pendingFiles = null; line("sys", "^C"); endAsk(null); setPS(""); input.value = ""; return;
  }
  if (event.ctrlKey && event.key === "l") { event.preventDefault(); logBox().replaceChildren(); return; }
  if (event.ctrlKey && (event.key === "n" || event.key === "p")) {
    event.preventDefault();
    if (!S.cases.length) return;
    S.sel = (S.sel + (event.key === "n" ? 1 : -1) + S.cases.length) % S.cases.length;
    renderCases();
    $("#case-list .sel")?.scrollIntoView({ block: "nearest" });
    return;
  }
  if (event.ctrlKey && event.key === "o") { event.preventDefault(); run(`open ${S.sel + 1}`); return; }
  if (event.key === "ArrowUp" || event.key === "ArrowDown") {
    if (S.heredoc || !S.history.length) return;
    event.preventDefault();
    if (S.back === -1) { if (event.key === "ArrowDown") return; S.draft = input.value; S.back = S.history.length; }
    S.back += event.key === "ArrowUp" ? -1 : 1;
    if (S.back < 0) S.back = 0;
    if (S.back >= S.history.length) { S.back = -1; input.value = S.draft; return; }
    input.value = S.history[S.back];
    return;
  }
  if (event.key === "Escape") { input.value = ""; }
}

// Multi-line paste into the prompt becomes a heredoc (in reply mode) or is refused.
function onPromptPaste(event) {
  const text = event.clipboardData?.getData("text") || "";
  if (!text.includes("\n")) return;
  event.preventDefault();
  if (!S.heredoc) { line("warn", "multi-line paste. open a heredoc with `reply` first."); return; }
  const rows = text.replace(/\n$/, "").split("\n");
  S.heredoc.push(...rows);
  line("draft", `[${rows.length} lines pasted]`, { t: "<<" });
}

function wireConsole() {
  $("#prompt").addEventListener("submit", submitPrompt);
  cmd().addEventListener("keydown", onPromptKey);
  cmd().addEventListener("paste", onPromptPaste);
  // The key or click that wakes the screensaver is swallowed, as screensavers do.
  document.addEventListener("keydown", (event) => {
    lastInput = Date.now();
    if (S.saver) { event.preventDefault(); event.stopPropagation(); wake(); return; }
    if (S.paging && !S.searching) pagerKey(event);
  }, true);
  document.addEventListener("pointerdown", (event) => {
    lastInput = Date.now();
    if (S.saver) { event.preventDefault(); event.stopPropagation(); wake(); }
  }, true);
  addEventListener("pointermove", (event) => {
    const moved = Math.abs(event.clientX - pointerAt.x) + Math.abs(event.clientY - pointerAt.y) > 12;
    pointerAt.x = event.clientX; pointerAt.y = event.clientY;
    if (!moved) return;
    lastInput = Date.now();
    if (S.saver) wake();
  }, { passive: true });
  addEventListener("wheel", () => { lastInput = Date.now(); }, { passive: true });
  // Typing anywhere lands in the prompt.
  document.addEventListener("keydown", (event) => {
    if ($("#console").hidden || S.paging || S.finder || event.metaKey || event.ctrlKey || event.altKey) return;
    const target = event.target;
    if (target.closest("input, textarea, select, button, a, [contenteditable]")) {
      if (target.tagName === "BUTTON" && event.key.length === 1 && !/\s/.test(event.key)) { cmd().focus(); }
      return;
    }
    if (event.key.length === 1 || event.key === "Enter") cmd().focus();
  });
  for (const button of document.querySelectorAll(".wins button")) {
    button.addEventListener("click", () => {
      const win = button.dataset.win;
      const frame = $("#console");
      frame.classList.toggle("show-ev", win === "ev");
      frame.classList.toggle("show-cases", win === "cases");
      for (const other of document.querySelectorAll(".wins button")) other.classList.toggle("on", other === button);
      $(`#pane-${win}`).classList.add("lit");
      setTimeout(() => $(`#pane-${win}`).classList.remove("lit"), 600);
      focusPrompt();
    });
  }
  $(".wins button[data-win=ops]").classList.add("on");
  $("#upload").addEventListener("change", async () => {
    const files = [...$("#upload").files];
    $("#upload").value = "";
    if (!files.length) { line("sys", "no files selected."); return; }
    try { await createCase(S.newTitle || files[0].name, files); } catch (error) { line("err", error.message); }
    S.newTitle = null;
  });
  // Drag evidence anywhere to open a case.
  let depth = 0;
  addEventListener("dragenter", (event) => { if (!S.me || !event.dataTransfer?.types.includes("Files")) return; depth++; $("#drop").hidden = false; });
  addEventListener("dragleave", () => { depth = Math.max(0, depth - 1); if (!depth) $("#drop").hidden = true; });
  addEventListener("dragover", (event) => { if (S.me) event.preventDefault(); });
  addEventListener("drop", (event) => {
    if (!S.me) return;
    event.preventDefault();
    depth = 0; $("#drop").hidden = true;
    const files = [...(event.dataTransfer?.files || [])];
    if (!files.length) return;
    S.pendingFiles = files;
    line("sys", `${files.length} file(s) staged: ${files.map((f) => f.name).join(", ")}`);
    ask("title:").then(async (value) => {
      S.pendingFiles = null;
      if (value === null) return;
      try { await createCase(value || files[0].name, files); } catch (error) { line("err", error.message); }
    });
  });
}

// Boot -------------------------------------------------------------------------------------

async function boot() {
  applyScheme(storedScheme());
  FX.initCursor();
  wireConsole();
  let me = null;
  try { me = await call("/api/me"); } catch { me = null; }
  if (me && me.stage === "full") { S.csrf = me.csrf; await enterConsole(); FX.show(false); return; }
  await showAuth(me ? me.stage : "password");
}

boot().catch((error) => { console.error(error); nope("no."); });
