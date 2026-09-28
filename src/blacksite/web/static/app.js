// Blacksite demo UI. Plain DOM, no dependencies: it must run with no internet.
// Log text is attacker-controlled, so text is only ever inserted with textContent.
"use strict";

const S = {
  status: null, switches: {}, incidents: [], current: null, files: [], colors: {},
  live: null, stream: null, tab: "overview", viewer: null, learning: null, upload: [],
  usb: { enabled: false, marker: "blacksite", drives: [], last: null },
  me: null, view: null,
};

const isAdmin = () => S.me?.user.role === "admin";
const totpAvailable = () => S.me?.auth?.totp_enabled !== false;

// Language and theme -------------------------------------------------------------------

let I18N = { en: {}, ko: {} };
let LANG = "en";
const THEMES = ["system", "light", "dark"];
const IS_MAC = /Mac|iPhone|iPad/.test(navigator.userAgentData?.platform || navigator.platform || navigator.userAgent);

function stored(key, fallback) {
  try { return localStorage.getItem(key) || fallback; } catch { return fallback; }
}

function store(key, value) {
  try { localStorage.setItem(key, value); } catch { /* storage unavailable; the choice lasts this visit */ }
}

// t("head.errors", { count: 3 }) looks up the current language, then English, then the key.
// When count is 1, a "key.one" string wins if the language has one ("1 error", not "1 errors").
function t(key, vars = {}) {
  const single = Number(String(vars.count ?? "").replace(/,/g, "")) === 1;
  const lookup = (lang) => (single && I18N[lang]?.[`${key}.one`]) || I18N[lang]?.[key];
  const text = lookup(LANG) ?? lookup("en") ?? key;
  return text.replace(/\{(\w+)\}/g, (whole, name) => (name in vars ? String(vars[name]) : whole));
}

function applyStaticText() {
  document.documentElement.lang = LANG;
  for (const node of document.querySelectorAll("[data-i18n]")) node.textContent = t(node.dataset.i18n);
  for (const node of document.querySelectorAll("[data-i18n-placeholder]")) node.placeholder = t(node.dataset.i18nPlaceholder);
  for (const node of document.querySelectorAll("[data-i18n-title]")) node.title = t(node.dataset.i18nTitle);
  for (const node of document.querySelectorAll("[data-i18n-aria]")) node.setAttribute("aria-label", t(node.dataset.i18nAria));
  for (const button of document.querySelectorAll("#lang-toggle button")) {
    const on = button.dataset.lang === LANG;
    button.classList.toggle("on", on);
    button.setAttribute("aria-pressed", String(on));
  }
  renderThemeToggle();
}

async function setLanguage(lang, { announce = true } = {}) {
  LANG = lang in I18N ? lang : "en";
  store("blacksite.lang", LANG);
  applyStaticText();
  loadStatus();
  renderUsbPill();
  renderSwitches();
  renderIncidentList();
  renderUserButton();
  if (S.current) { renderIncident(); renderEvidence(); }
  if (!$("#learning").hidden) renderLearning();
  if (S.view && S.view !== "incidents") route();
  // The guide language follows the page language; it applies to everyone, so admins set it.
  if (isAdmin() && S.switches.language && S.switches.language !== LANG) {
    try {
      const data = await api("/api/settings", { json: { language: LANG } });
      S.switches = data.switches;
      if (announce) toast(t("toast.languageRun"));
    } catch (error) { toast(error.message); }
  }
}

function currentTheme() {
  const theme = stored("blacksite.theme", "system");
  return THEMES.includes(theme) ? theme : "system";
}

function setTheme(theme) {
  store("blacksite.theme", theme);
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  renderThemeToggle();
}

function renderThemeToggle() {
  const current = currentTheme();
  const icons = { system: "◐", light: "☀", dark: "☾" };
  $("#theme-toggle").replaceChildren(...THEMES.map((theme) => el("button", {
    type: "button", class: theme === current ? "on" : "", "aria-pressed": String(theme === current),
    title: t(`theme.${theme}`), onclick: () => setTheme(theme),
  }, el("span", { "aria-hidden": "true", text: icons[theme] }), el("span", { class: "hide-narrow", text: ` ${t(`theme.${theme}`)}` }))));
}

// Helpers ------------------------------------------------------------------------------

const $ = (selector, root = document) => root.querySelector(selector);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "style") node.setAttribute("style", value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

let leaving = false;

function goToLogin() {
  if (leaving) return;
  leaving = true;
  location.replace(`/login?next=${encodeURIComponent("/" + location.hash)}`);
}

async function api(path, options = {}, retried = false) {
  const init = { ...options, headers: { ...(options.headers || {}) }, credentials: "same-origin" };
  if (init.json !== undefined) {
    init.method = init.method || "POST";
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.json);
    delete init.json;
  }
  if ((init.method || "GET").toUpperCase() !== "GET" && S.me) init.headers["X-CSRF-Token"] = S.me.csrf;
  const response = await fetch(path, init);
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && data.login) {
    goToLogin();
    throw new Error(data.error || t("auth.signInAgain"));
  }
  if (response.status === 403 && data.confirm && !retried) {
    if (await confirmIdentity()) return api(path, options, true);
    throw new Error(t("reauth.cancelled"));
  }
  if (!response.ok) throw new Error(data.error || response.statusText);
  return data;
}

// Asks for the password (and a code) before a sensitive admin action; true once confirmed.
function confirmIdentity() {
  return new Promise((resolve) => {
    const password = el("input", { type: "password", autocomplete: "current-password", required: true });
    const code = totpAvailable() && S.me.user.totp_enabled
      ? el("input", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: "7", required: true }) : null;
    const error = el("p", { class: "form-error", role: "alert", hidden: true });
    const cancel = el("button", { class: "btn", type: "button", text: t("dialog.cancel"), onclick: () => close(false) });
    const submit = el("button", { class: "btn primary", type: "submit", text: t("reauth.confirm") });
    const form = el("form", { class: "modal dialog", role: "dialog", "aria-modal": "true", "aria-labelledby": "reauth-title",
      onsubmit: async (event) => {
        event.preventDefault();
        submit.disabled = true;
        try {
          await api("/auth/confirm", { json: { password: password.value, code: code ? code.value : "" } });
          close(true);
        } catch (failure) {
          error.hidden = false;
          error.textContent = failure.message;
          submit.disabled = false;
        }
      } },
      el("h2", { id: "reauth-title", text: t("reauth.title") }),
      el("p", { class: "flush muted", text: t(code ? "reauth.bodyCode" : "reauth.body") }),
      el("label", { class: "field" }, el("span", { text: t("login.password") }), password),
      code ? el("label", { class: "field" }, el("span", { text: t("login.code") }), code) : null,
      error,
      el("div", { class: "modal-actions" }, cancel, submit));
    const overlay = el("div", { class: "overlay" }, form);
    function keys(event) { if (event.key === "Escape") close(false); }
    function close(answer) { overlay.remove(); document.removeEventListener("keydown", keys, true); resolve(answer); }
    document.body.append(overlay);
    document.addEventListener("keydown", keys, true);
    password.focus();
  });
}

function toast(text) {
  const node = el("div", { class: "toast", role: "status", text });
  document.body.append(node);
  setTimeout(() => node.remove(), 2600);
}

// An in-page confirmation. Embedded browsers (like an app's preview pane) often block
// window.confirm, which then returns false without showing anything.
function confirmDialog({ title, body, action, danger = false }) {
  return new Promise((resolve) => {
    const previous = document.activeElement;
    const cancel = el("button", { class: "btn", type: "button", text: t("dialog.cancel"), onclick: () => close(false) });
    const accept = el("button", { class: `btn primary${danger ? " danger-fill" : ""}`, type: "button", text: action, onclick: () => close(true) });
    const overlay = el("div", { class: "overlay", onclick: (event) => { if (event.target === overlay) close(false); } },
      el("div", { class: "modal dialog", role: "alertdialog", "aria-modal": "true", "aria-labelledby": "dialog-title", "aria-describedby": "dialog-body" },
        el("h2", { id: "dialog-title", text: title }),
        el("p", { id: "dialog-body", class: "flush muted", text: body }),
        el("div", { class: "modal-actions" }, cancel, accept)));
    function keys(event) {
      if (event.key === "Escape") { event.preventDefault(); close(false); }
      if (event.key === "Tab") {  // keep focus inside the dialog
        event.preventDefault();
        (document.activeElement === cancel ? accept : cancel).focus();
      }
    }
    function close(answer) {
      overlay.remove();
      document.removeEventListener("keydown", keys, true);
      if (previous && previous.isConnected) previous.focus();
      resolve(answer);
    }
    document.body.append(overlay);
    document.addEventListener("keydown", keys, true);
    cancel.focus();  // the safe choice is the default
  });
}

async function copy(text, label) {
  try { await navigator.clipboard.writeText(text); toast(label || t("copy.done")); }
  catch { toast(t("copy.failed")); }
}

function duration(seconds) {
  seconds = Math.max(0, Math.round(seconds));
  const m = Math.floor(seconds / 60), s = seconds % 60;
  return m ? t("time.minutes", { m, s: String(s).padStart(2, "0") }) : t("time.seconds", { s });
}

function clock(seconds) {
  seconds = Math.max(0, Math.floor(seconds));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function number(n) { return (n || 0).toLocaleString(LANG === "ko" ? "ko-KR" : "en-US"); }

function bytes(n) {
  const units = ["B", "KB", "MB", "GB"];
  let value = n || 0, unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value.toLocaleString(LANG === "ko" ? "ko-KR" : "en-US", { maximumFractionDigits: unit ? 1 : 0 })} ${units[unit]}`;
}

function hhmm(iso) { return iso ? iso.slice(11, 16) : ""; }

function words(text) {
  const trimmed = text.trim();
  return trimmed ? trimmed.split(/\s+/).length : 0;
}

// A check from the server carries a code and parameters, so it reads in either language.
function checkText(check) {
  if (!check.code || !(`check.${check.code}` in I18N.en)) return check.text;
  const params = { ...check.params };
  if (params.from) params.from = t(`risk.${params.from}`);
  if (params.to) params.to = t(`risk.${params.to}`);
  if (params.reason) params.reason = t(`reason.${params.reason}`);
  return t(`check.${check.code}`, params);
}

// Evidence references ("nginx/error.log:3", "kern.log:5-6,8") become buttons that open the
// line viewer. Built from the incident's own file names, so ordinary text is left alone.
function refPattern() {
  if (!S.files.length) return null;
  const names = [...S.files].sort((a, b) => b.length - a.length)
    .map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  return new RegExp(`(${names.join("|")}):(\\d+)(?:\\s*[-–]\\s*(\\d+))?((?:\\s*,\\s*\\d+(?:\\s*[-–]\\s*\\d+)?)*)`, "g");
}

function linkify(text) {
  const fragment = document.createDocumentFragment();
  const pattern = refPattern();
  if (!pattern || !text) { fragment.append(emphasis(text || "")); return fragment; }
  let last = 0;
  for (const match of text.matchAll(pattern)) {
    fragment.append(emphasis(text.slice(last, match.index)));
    const [whole, file, start, end] = match;
    fragment.append(refButton(whole, file, Number(start), Number(end || start)));
    last = match.index + whole.length;
  }
  fragment.append(emphasis(text.slice(last)));
  return fragment;
}

// A small Markdown renderer for the model's answer while it streams. Text nodes only.
function renderMarkdown(text) {
  const fragment = document.createDocumentFragment();
  let list = null, code = null, paragraph = [];
  const flush = () => {
    if (paragraph.length) { fragment.append(el("p", {}, linkify(paragraph.join(" ")))); paragraph = []; }
  };
  for (const line of text.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) {
      if (code) { fragment.append(el("div", { class: "cmd" }, el("pre", { text: code.join("\n") }))); code = null; }
      else { flush(); list = null; code = []; }
      continue;
    }
    if (code) { code.push(line); continue; }
    const heading = line.match(/^(#{1,3})\s+(.*)$/);
    const bullet = line.match(/^\s*(?:[-*+]|\d+[.)])\s+(.*)$/);
    if (heading) {
      flush(); list = null;
      fragment.append(el(["h3", "h4", "h5"][heading[1].length - 1], {}, linkify(heading[2])));
    } else if (bullet) {
      flush();
      if (!list) { list = el("ul"); fragment.append(list); }
      list.append(el("li", {}, linkify(bullet[1])));
    } else if (!line.trim()) {
      flush(); list = null;
    } else {
      list = null; paragraph.push(line.trim());
    }
  }
  flush();
  if (code) fragment.append(el("div", { class: "cmd" }, el("pre", { text: code.join("\n") })));
  return fragment;
}

// Models often write **bold** and `code`; show them as such, still as plain text nodes.
function emphasis(text) {
  const fragment = document.createDocumentFragment();
  let last = 0;
  for (const match of text.matchAll(/\*\*([^*\n]+)\*\*|`([^`\n]+)`/g)) {
    fragment.append(text.slice(last, match.index));
    fragment.append(match[1] !== undefined ? el("strong", { text: match[1] }) : el("code", { text: match[2] }));
    last = match.index + match[0].length;
  }
  fragment.append(text.slice(last));
  return fragment;
}

function refButton(label, file, start, end = start) {
  return el("button", {
    class: "ref", type: "button", title: t("ref.title", { file, line: start }), text: label,
    onclick: () => openLines(file, start, end),
  });
}

// Boot ---------------------------------------------------------------------------------

async function boot() {
  try { I18N = await (await fetch(window.BLACKSITE_I18N || "/static/i18n.json")).json(); } catch { /* English keys */ }
  const preferred = stored("blacksite.lang", (navigator.language || "en").toLowerCase().startsWith("ko") ? "ko" : "en");
  LANG = preferred in I18N ? preferred : "en";
  S.me = await api("/api/me");
  if (S.me.stage !== "full") { goToLogin(); return; }
  applyRole();
  wireStatics();
  applyStaticText();
  await Promise.all([loadStatus(), loadSettings(), loadIncidents(), ...(isAdmin() ? [loadLearningCount(), pollUsb()] : [])]);
  if (isAdmin() && S.switches.language && S.switches.language !== LANG) await setLanguage(LANG, { announce: false });
  setInterval(loadStatus, 10000);
  if (isAdmin()) setInterval(pollUsb, 2500);
  setInterval(tickLive, 1000);
  setInterval(renderUserButton, 30000);
  addEventListener("hashchange", route);
  try {
    const low = sessionStorage.getItem("blacksite.lowCodes");
    if (low !== null) {
      sessionStorage.removeItem("blacksite.lowCodes");
      if (totpAvailable()) toast(t("account.lowCodes", { count: low }));
    }
  } catch { /* storage unavailable */ }
  await route();
}

// Views and roles ------------------------------------------------------------------------

function applyRole() {
  document.body.dataset.role = S.me.user.role;
  for (const node of document.querySelectorAll("[data-role='admin']")) node.hidden = !isAdmin();
  renderUserButton();
}

function showView(name) {
  S.view = name;
  for (const view of ["dashboard", "incidents", "admin", "account"]) $(`#view-${view}`).hidden = view !== name;
  for (const link of document.querySelectorAll(".nav a")) {
    if (link.dataset.view === name) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  }
  $("#evidence-toggle").hidden = name !== "incidents";
  document.title = name === "incidents" && S.current ? `${S.current.title} · Blacksite` : `${t(`nav.${name}`)} · Blacksite`;
}

// #/ dashboard, #/incidents/<id>, #/admin/<tab>, #/account. An old #<id> link still opens its incident.
async function route() {
  const hash = decodeURIComponent(location.hash.slice(1));
  if (hash && !hash.startsWith("/")) {
    history.replaceState(null, "", `#/incidents/${encodeURIComponent(hash)}`);
    return route();
  }
  const parts = hash.split("/").filter(Boolean);
  const view = parts[0] || "dashboard";
  if (view === "incidents") {
    showView("incidents");
    const wanted = parts[1];
    if (wanted && (!S.current || S.current.id !== wanted)) {
      try { await selectIncident(wanted); } catch (error) { toast(error.message); renderEmpty(); }
    } else if (!wanted && !S.current) {
      if (S.incidents[0]) await selectIncident(S.incidents[0].id); else renderEmpty();
    }
    return;
  }
  if (view === "admin" && isAdmin()) { showView("admin"); await renderAdmin(parts[1] || "members", parts.slice(2)); return; }
  if (view === "account") { showView("account"); await renderAccount(); return; }
  showView("dashboard");
  await renderDashboard();
}

function initials(name) {
  const words = String(name || "?").trim().split(/\s+/);
  return (words.length > 1 ? words[0][0] + words[1][0] : words[0].slice(0, 2)).toUpperCase();
}

function avatarColor(id) {
  return `var(--f${((Number(id) || 1) - 1) % 6 + 1})`;
}

function sessionLeft() {
  const seconds = S.me ? S.me.session.expires_at - Date.now() / 1000 : 0;
  const hours = Math.floor(seconds / 3600), minutes = Math.max(0, Math.floor((seconds % 3600) / 60));
  return hours ? t("user.leftHours", { h: hours, m: minutes }) : t("user.leftMinutes", { m: minutes });
}

function renderUserButton() {
  if (!S.me) return;
  const user = S.me.user;
  const avatar = $("#user-avatar");
  avatar.textContent = initials(user.display_name);
  avatar.style.background = avatarColor(user.id);
  $("#user-name").textContent = user.display_name;
  $("#user-role").textContent = t(`role.${user.role}`);
  $("#user-role").className = `role-badge ${user.role}`;
  $("#user-session").textContent = t("user.session", { left: sessionLeft() });
}

function toggleUserMenu() {
  const menu = $("#user-menu");
  if (!menu.hidden) { closeUserMenu(); return; }
  const user = S.me.user;
  const item = (key, onclick, cls = "") => el("button", { class: `menu-item ${cls}`, type: "button", role: "menuitem", text: t(key),
    onclick: () => { closeUserMenu(); onclick(); } });
  menu.replaceChildren(
    el("div", { class: "menu-who" },
      el("span", { class: "avatar big", style: `background:${avatarColor(user.id)}`, text: initials(user.display_name) }),
      el("div", {}, el("b", { text: user.display_name }), el("div", { class: "faint small mono", text: user.username }))),
    el("div", { class: "menu-facts" },
      el("div", {}, el("span", { class: "faint", text: t("user.role") }), el("span", { class: `role-badge ${user.role}`, text: t(`role.${user.role}`) })),
      el("div", {}, el("span", { class: "faint", text: t("user.twoStep") }),
        el("span", { class: `badge ${totpAvailable() ? user.totp_enabled ? "ok" : "warn" : ""}`,
          text: t(!totpAvailable() ? "account.disabled" : user.totp_enabled ? "account.on" : "account.off") })),
      el("div", {}, el("span", { class: "faint", text: t("user.sessionLabel") }), el("span", { text: sessionLeft() }))),
    item("user.account", () => { location.hash = "#/account"; }),
    item("user.signOut", signOut, "danger"));
  const button = $("#user-button");
  const box = button.getBoundingClientRect();
  menu.style.top = `${box.bottom + 6}px`;
  menu.style.right = `${Math.max(8, innerWidth - box.right)}px`;
  menu.style.left = "auto";
  menu.hidden = false;
  button.setAttribute("aria-expanded", "true");
  menu.querySelector(".menu-item").focus();
}

function closeUserMenu() {
  $("#user-menu").hidden = true;
  $("#user-button").setAttribute("aria-expanded", "false");
}

async function signOut() {
  try { await api("/auth/logout", { method: "POST" }); } catch { /* already signed out */ }
  leaving = true;
  location.replace("/login");
}

function wireStatics() {
  $("#user-button").addEventListener("click", toggleUserMenu);
  document.addEventListener("pointerdown", (event) => {
    if (!$("#user-menu").hidden && !event.target.closest("#user-menu, #user-button")) closeUserMenu();
  });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape" && !$("#user-menu").hidden) closeUserMenu(); });
  $("#new-incident").addEventListener("click", openNewIncident);
  $("#new-cancel").addEventListener("click", () => { $("#new-modal").hidden = true; });
  $("#new-form").addEventListener("submit", submitNewIncident);
  $("#learning-open").addEventListener("click", openLearning);
  $("#learning-close").addEventListener("click", () => { $("#learning").hidden = true; });
  $("#evidence-toggle").addEventListener("click", () => setEvidenceOpen($("#evidence").classList.contains("closed")));
  $("#evidence-close").addEventListener("click", () => setEvidenceOpen(false));
  // A saved choice wins; otherwise the panel starts open on wide screens and closed on narrow ones.
  const saved = stored("blacksite.evidence", "");
  setEvidenceOpen(saved ? saved === "open" : !matchMedia("(max-width: 1100px)").matches, { remember: false });
  $("#model-pill").addEventListener("click", toggleModelMenu);
  document.addEventListener("keydown", (event) => { if (event.key === "Escape" && !$("#model-menu").hidden) closeModelMenu(true); });
  document.addEventListener("pointerdown", (event) => {
    if (!$("#model-menu").hidden && !event.target.closest("#model-menu, #model-pill")) closeModelMenu();
  });
  addEventListener("resize", () => { if (!$("#model-menu").hidden) placeModelMenu(); });
  for (const button of document.querySelectorAll("#lang-toggle button")) {
    button.addEventListener("click", () => setLanguage(button.dataset.lang));
  }
  $("#paste-toggle").addEventListener("click", () => {
    const paste = $("#paste");
    paste.hidden = !paste.hidden;
    if (!paste.hidden) paste.focus();
  });
  $("#send").addEventListener("click", () => sendTurn());
  const message = $("#message");
  message.addEventListener("input", () => { message.style.height = "auto"; message.style.height = `${message.scrollHeight}px`; });
  message.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) sendTurn();
  });
  for (const button of document.querySelectorAll(".tabs button")) {
    button.addEventListener("click", () => { S.tab = button.dataset.tab; renderEvidence(); });
  }
  const drop = $("#drop"), input = $("#file-input");
  drop.addEventListener("click", (event) => { if (event.target !== input) input.click(); });
  drop.addEventListener("dragover", (event) => { event.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (event) => {
    event.preventDefault(); drop.classList.remove("over");
    S.upload = [...S.upload, ...event.dataTransfer.files];
    renderUploadList();
  });
  input.addEventListener("change", () => { S.upload = [...S.upload, ...input.files]; input.value = ""; renderUploadList(); });
}

// Status and switches ------------------------------------------------------------------

async function loadStatus() {
  try { S.status = await api("/api/status"); } catch { S.status = null; }
  const pill = $("#model-pill");
  const dot = pill.querySelector(".dot");
  const label = pill.querySelector(".pill-label");
  if (!S.status) { dot.className = "dot bad"; label.textContent = t("status.unreachable"); return; }
  const { model, backend, reachable, loaded, loading, detail } = S.status;
  dot.className = `dot ${loaded ? "ok" : loading ? "warn" : "bad"}`;
  const problem = loading ? "status.loading" : !reachable ? "status.notRunning" : "status.notReady";
  const state = loaded ? "" : ` · ${t(problem)}`;
  label.textContent = `${model} · ${backend}${state}`;
  pill.title = [t("status.title", { url: S.status.base_url }), detail].filter(Boolean).join(" · ");
}

// Model picker: the model server, then a model already on this computer ------------------

const MODELS = { data: null, provider: null, choice: null, busy: false, error: "", watch: null };

function toggleModelMenu() {
  if (!isAdmin()) { toast(t("models.adminOnly")); return; }
  if ($("#model-menu").hidden) openModelMenu(); else closeModelMenu();
}

async function openModelMenu() {
  const menu = $("#model-menu");
  menu.hidden = false;
  $("#model-pill").setAttribute("aria-expanded", "true");
  MODELS.error = "";
  MODELS.choice = null;
  MODELS.provider = S.status?.provider || MODELS.provider;
  renderModelMenu();
  await loadModels();
}

function closeModelMenu(focusPill = false) {
  $("#model-menu").hidden = true;
  $("#model-pill").setAttribute("aria-expanded", "false");
  if (focusPill) $("#model-pill").focus();
}

function placeModelMenu() {
  const menu = $("#model-menu"), rect = $("#model-pill").getBoundingClientRect();
  menu.style.top = `${rect.bottom + 6}px`;
  menu.style.left = `${Math.max(8, Math.min(rect.left, innerWidth - menu.offsetWidth - 8))}px`;
}

async function loadModels() {
  try { MODELS.data = await api("/api/models"); } catch (error) { MODELS.error = error.message; }
  if (MODELS.data && !MODELS.data.backends.some((item) => item.id === MODELS.provider)) {
    MODELS.provider = MODELS.data.current.provider;
  }
  if (!$("#model-menu").hidden) renderModelMenu();
}

function gigabytes(bytes) {
  return bytes ? `${(bytes / 1e9).toFixed(1)} GB` : "";
}

function modelRow(model, backend) {
  const selected = MODELS.choice ? MODELS.choice === model.id : model.in_use;
  const context = backend.id !== "ollama" ? ""
    : model.context ? t("models.context", { k: Math.round(model.context / 1024) }) : t("models.ollamaContext");
  const meta = [gigabytes(model.size), model.source, context].filter(Boolean).join(" · ");
  const reason = model.usable ? "" : t(model.note === "no-template" ? "models.noTemplate" : "models.noTools");
  return el("button", {
    type: "button", role: "radio", class: `model-row${selected ? " on" : ""}`, disabled: !model.usable || MODELS.busy,
    "aria-checked": String(selected), title: model.id,
    onclick: () => { MODELS.choice = model.in_use ? null : model.id; MODELS.error = ""; renderModelMenu(); },
  },
  el("span", { class: "radio", "aria-hidden": "true" }),
  el("span", { class: "model-text" },
    el("span", { class: "model-name" }, model.label, model.in_use ? el("span", { class: "badge ok", text: t("models.inUse") }) : null),
    el("span", { class: "model-meta", text: reason || meta })));
}

function renderModelMenu() {
  const menu = $("#model-menu");
  const data = MODELS.data;
  if (!data) {
    menu.replaceChildren(el("div", { class: "menu-head" }, el("h2", { text: t("models.title") })),
      MODELS.error ? el("div", { class: "note error", text: MODELS.error })
        : el("div", { class: "muted small" }, el("span", { class: "spinner inline" }), t("models.loading")));
    placeModelMenu();
    return;
  }
  const backend = data.backends.find((item) => item.id === MODELS.provider) || data.backends[0];
  const tabs = el("div", { class: "seg", role: "radiogroup", "aria-label": t("models.server") },
    data.backends.map((item) => el("button", {
      type: "button", role: "radio", class: item.id === backend.id ? "on" : "", "aria-checked": String(item.id === backend.id),
      onclick: () => { MODELS.provider = item.id; MODELS.choice = null; MODELS.error = ""; renderModelMenu(); },
    }, el("span", { class: `dot ${item.running ? "ok" : item.installed ? "idle" : "bad"}` }), item.name)));
  const host = backend.base_url.replace(/^https?:\/\//, "").replace(/\/v1\/?$/, "");
  const state = !backend.installed ? el("div", { class: "note error", text: backend.detail || t("models.notInstalled") })
    : el("div", { class: "muted small", text: t(backend.running ? "models.runningAt" : "models.stoppedAt", { host }) });
  const usable = backend.models.filter((model) => model.usable).length;
  const list = backend.models.length
    ? el("div", { class: "model-list", role: "radiogroup", "aria-label": t("models.models") }, backend.models.map((model) => modelRow(model, backend)))
    : el("div", { class: "muted small", text: t("models.none") });
  const hint = backend.id === "ollama" ? t("models.hintOllama") : t("models.hintStart", { k: Math.round(data.context / 1024) });
  const managed = data.managed.running
    ? el("button", { class: "btn small danger", type: "button", disabled: MODELS.busy, onclick: stopModelServer,
      text: t("models.stop", { name: data.managed.model }) })
    : null;
  const choice = backend.models.find((model) => model.id === MODELS.choice);
  const use = el("button", {
    class: "btn primary", type: "button", disabled: !choice || MODELS.busy || !backend.installed, onclick: useModel,
  }, MODELS.busy ? el("span", { class: "spinner inline" }) : null, t(MODELS.busy ? "models.switching" : "models.use"));
  menu.replaceChildren(...[
    el("div", { class: "menu-head" }, el("h2", { text: t("models.title") }),
      el("span", { class: "faint small", text: t("models.count", { count: usable }) })),
    tabs, state,
    el("div", { class: "label", text: t("models.models") }), list,
    el("p", { class: "faint small flush", text: hint }),
    MODELS.error ? el("div", { class: "note error", text: MODELS.error }) : null,
    el("div", { class: "menu-actions" }, managed, el("span", { class: "spacer" }), use),
  ].filter(Boolean));
  placeModelMenu();
}

async function useModel() {
  const provider = MODELS.provider, model = MODELS.choice;
  MODELS.busy = true;
  MODELS.error = "";
  renderModelMenu();
  try {
    MODELS.data = await api("/api/models", { json: { provider, model } });
    MODELS.choice = null;
  } catch (error) {
    MODELS.error = error.message;
  }
  MODELS.busy = false;
  renderModelMenu();
  await loadStatus();
  await loadSettings();
  watchModelStartup();
}

async function stopModelServer() {
  MODELS.busy = true;
  renderModelMenu();
  try { MODELS.data = await api("/api/models", { json: { action: "stop" } }); } catch (error) { MODELS.error = error.message; }
  MODELS.busy = false;
  renderModelMenu();
  loadStatus();
}

// While a model server starts, check every two seconds instead of every ten.
function watchModelStartup() {
  clearInterval(MODELS.watch);
  const started = Date.now();
  MODELS.watch = setInterval(async () => {
    await loadStatus();
    if (!S.status?.loading || Date.now() - started > 15 * 60 * 1000) {
      clearInterval(MODELS.watch);
      if (!$("#model-menu").hidden) loadModels();
    }
  }, 2000);
}

async function loadSettings() {
  const data = await api("/api/settings");
  S.switches = data.switches;
  renderSwitches();
}

const SWITCHES = [
  { key: "rag", options: ["off", "tool", "inject"] },
  { key: "cases", options: ["off", "tool", "inject"] },
  { key: "playbook", options: ["off", "on"] },
  { key: "thinking", options: ["none", "low", "medium"] },
];

function renderSwitches() {
  const root = $("#switches");
  root.replaceChildren(...SWITCHES.map((item) => el("div", { class: "switch" },
    el("div", { class: "name", text: t(`switch.${item.key}.name`) }),
    el("div", { class: "seg", role: "group", "aria-label": t(`switch.${item.key}.name`) },
      item.options.map((option) => el("button", {
        type: "button", class: S.switches[item.key] === option ? "on" : "", "aria-pressed": String(S.switches[item.key] === option),
        text: t(`option.${option}`), onclick: () => setSwitch(item.key, option), disabled: !isAdmin(),
      }))),
    el("div", { class: "hint", text: t(`switch.${item.key}.hint`) }))),
    ...(isAdmin() ? [] : [el("div", { class: "hint", text: t("switch.adminOnly") })]));
  const baseline = S.switches.rag === "off" && S.switches.cases === "off" && S.switches.playbook === "off";
  $("#baseline-tag").hidden = !baseline;
}

async function setSwitch(key, value) {
  try {
    const data = await api("/api/settings", { json: { [key]: value } });
    S.switches = data.switches;
    renderSwitches();
    toast(t("toast.nextRun"));
  } catch (error) { toast(error.message); }
}

// Incidents ----------------------------------------------------------------------------

async function loadIncidents() {
  const data = await api("/api/incidents");
  S.incidents = data.incidents;
  renderIncidentList();
}

function renderIncidentList() {
  const list = $("#incident-list");
  if (!S.incidents.length) { list.replaceChildren(el("div", { class: "faint", text: t("side.none") })); return; }
  list.replaceChildren(...S.incidents.map((item) => el("button", {
    type: "button", class: `incident-item${S.current && S.current.id === item.id ? " active" : ""}`,
    onclick: () => selectIncident(item.id),
  },
    el("span", { class: "t", text: item.title }),
    el("span", { class: "s" },
      item.usb ? el("span", { class: "badge usb", title: item.usb.drive, text: t("usb.badge") }) : null,
      item.shared ? el("span", { class: "badge share", text: t("incident.sharedWithYou") }) : null,
      isAdmin() && !item.mine ? el("span", { class: "badge owner", text: item.owner || t("incident.unassigned") }) : null,
      item.running ? el("span", { class: "spinner", "aria-hidden": "true" }) : null,
      t(item.running ? "incident.status.running" : item.queued ? "incident.status.queued" : `incident.status.${item.status}`)))));
}

async function selectIncident(id, { keepScroll = false } = {}) {
  closeStream();
  const scroll = $("#main").scrollTop;
  const data = await api(`/api/incidents/${encodeURIComponent(id)}`);
  S.current = data;
  S.files = data.artifacts.map((item) => item.file);
  S.colors = Object.fromEntries(S.files.map((file, index) => [file, `var(--f${(index % 6) + 1})`]));
  history.replaceState(null, "", `#/incidents/${encodeURIComponent(id)}`);
  if (S.view === "incidents") document.title = `${data.title} · Blacksite`;
  renderIncidentList();
  renderIncident();
  renderEvidence();
  if (data.running) attachStream(id, { message: "", pasted: "", resumed: true });
  $("#main").scrollTop = keepScroll ? scroll : 0;
}

function renderEmpty() {
  $("#composer").hidden = true;
  $("#page").replaceChildren(el("div", { class: "empty" },
    el("h2", { text: t("empty.title") }),
    el("p", { text: t("empty.body") }),
    el("button", { class: "btn primary", type: "button", text: t("empty.button"), onclick: openNewIncident }),
    S.usb.enabled ? el("p", { class: "faint", text: t("empty.usb", { marker: S.usb.marker }) }) : null));
  $("#evidence-body").replaceChildren();
}

function renderIncident() {
  const data = S.current;
  const page = $("#page");
  const errors = data.artifacts.reduce((sum, item) => sum + item.errors, 0);
  const lines = data.artifacts.reduce((sum, item) => sum + item.lines, 0);
  const flagged = data.artifacts.reduce((sum, item) => sum + item.flagged, 0);
  const redacted = data.artifacts.reduce((sum, item) => sum + item.redactions, 0);
  const head = el("section", { class: "incident-head" },
    el("h1", { text: data.title }),
    data.description ? el("p", { text: data.description }) : null,
    el("div", { class: "meta" },
      el("span", { class: "pill", text: t("head.files", { count: data.artifacts.length, files: data.artifacts.length, lines: number(lines) }) }),
      el("span", { class: "pill", text: t("head.errors", { count: number(errors) }) }),
      data.range[0] ? el("span", { class: "pill", text: `${data.range[0].slice(0, 16)} → ${hhmm(data.range[1])}` }) : null,
      redacted ? el("span", { class: "pill", title: t("head.redactedTitle"), text: t("head.redacted", { count: redacted }) }) : null,
      flagged ? el("span", { class: "badge error", title: t("head.flaggedTitle"), text: t("head.flagged", { count: flagged }) }) : null,
      data.owner ? el("span", { class: "pill", title: t("share.ownerTitle"), text: t("share.owner", { name: data.owner.name || "?" }) })
        : el("span", { class: "pill", text: t("incident.unassigned") }),
      data.access === "manage" ? el("button", { class: "btn ghost small", type: "button", onclick: openShare,
        text: data.shares.length ? t("share.buttonCount", { count: data.shares.length }) : t("share.button") }) : null,
      data.turns.length && !data.usb && data.access === "manage"
        ? el("button", { class: "btn ghost small", type: "button", text: t("head.startOver"), onclick: resetIncident }) : null),
    data.usb ? usbSource(data) : null);
  const turns = el("div", { class: "turns" });
  data.turns.forEach((turn, index) => {
    const view = new TurnView(turns, { message: turn.message, pasted: turn.pasted, live: false, index });
    for (const event of turn.events) view.add(event);
    view.finish();
  });
  page.replaceChildren(head, turns);
  S.turnsRoot = turns;
  if (!data.turns.length && !data.running) {
    turns.append(el("div", { class: "card intro" },
      el("b", { text: t("ready.title") }),
      el("p", { class: "muted", text: t("ready.body") })));
  }
  updateComposer();
}

function updateComposer() {
  const composer = $("#composer");
  composer.hidden = !S.current;
  const running = Boolean(S.live && !S.live.finished);
  const started = S.current && S.current.turns.length > 0;
  $("#send").disabled = running;
  $("#send").textContent = t(running ? "composer.working" : started ? "composer.send" : "composer.investigate");
  $("#composer-hint").textContent = running ? t("composer.workingHint")
    : t("composer.shortcut", { keys: IS_MAC ? "⌘↩" : "Ctrl+Enter" });
}

async function resetIncident() {
  const confirmed = await confirmDialog({ title: t("confirm.resetTitle"), body: t("confirm.reset"),
    action: t("head.startOver"), danger: true });
  if (!confirmed) return;
  try {
    await api(`/api/incidents/${encodeURIComponent(S.current.id)}/reset`, { method: "POST" });
    await selectIncident(S.current.id);
    await loadIncidents();
  } catch (error) { toast(error.message); }
}

// USB mode -----------------------------------------------------------------------------

function usbSource(data) {
  const usb = data.usb;
  return el("div", { class: "usb-source" },
    el("span", { class: "badge usb", text: t("usb.badge") }),
    el("span", { text: t("usb.source", { drive: usb.drive, bundle: usb.bundle, count: usb.files, files: number(usb.files), size: bytes(usb.bytes) }) }),
    usb.skipped.length ? el("span", { class: "badge warn", title: usb.skipped.slice(0, 20).join("\n"), text: t("usb.skipped", { count: usb.skipped.length }) }) : null,
    usb.present ? null : el("span", { class: "badge warn", text: t("usb.notPresent") }),
    el("span", { class: "spacer" }),
    isAdmin() ? el("button", { class: "btn ghost small danger", type: "button", text: t("usb.wipe"), disabled: data.running, onclick: wipeIncident }) : null);
}

function renderUsbPill() {
  const pill = $("#usb-pill");
  const dot = pill.querySelector(".dot");
  const label = pill.querySelector("span:last-child");
  const drive = S.usb.drives[0];
  pill.hidden = !S.usb.enabled;
  dot.className = `dot ${drive ? "ok" : "idle"}`;
  label.textContent = !S.usb.enabled ? t("usb.pill.off") : drive ? t("usb.pill.drive", { drive: drive.label }) : t("usb.pill.waiting");
  pill.title = t("usb.pill.title", { marker: S.usb.marker });
}

async function pollUsb() {
  let data;
  try { data = await api(`/api/usb?after=${S.usb.last ?? 0}`); } catch { return; }
  const first = S.usb.last === null;
  S.usb.enabled = data.enabled;
  S.usb.marker = data.marker;
  const wasPresent = new Set(S.usb.drives.map((drive) => drive.name));
  S.usb.drives = data.drives;
  if (data.events.length) S.usb.last = data.events[data.events.length - 1].id;
  else if (first) S.usb.last = 0;
  renderUsbPill();
  if (first) return;  // events from before this page loaded are not replayed
  let refresh = false;
  for (const event of data.events) {
    if (event.kind === "inserted") toast(t("usb.inserted", { drive: event.drive }));
    else if (event.kind === "removed") { toast(t("usb.removed", { drive: event.drive })); refresh = true; }
    else if (event.kind === "error") toast(t("usb.error", { drive: event.drive || "USB", message: event.message }));
    else if (event.kind === "imported") {
      toast(t("usb.imported", { title: event.title, count: event.files, files: event.files, drive: event.drive }));
      await loadIncidents();
      if (!S.live || S.live.finished) await selectIncident(event.incident);
    } else if (event.kind === "started") {
      await loadIncidents();
      if (S.current && S.current.id === event.incident) { toast(t("usb.started")); await selectIncident(event.incident, { keepScroll: true }); }
    } else refresh = true;
  }
  const present = new Set(S.usb.drives.map((drive) => drive.name));
  if ([...present].some((name) => !wasPresent.has(name))) refresh = true;
  if (refresh) {
    await loadIncidents();
    if (S.current && S.current.usb && (!S.live || S.live.finished)) await selectIncident(S.current.id, { keepScroll: true }).catch(() => renderEmpty());
  }
}

async function exportToDrive(button) {
  const id = S.current.id;
  button.disabled = true;
  button.textContent = t("usb.saving");
  try {
    const result = await api(`/api/incidents/${encodeURIComponent(id)}/export`, { json: { language: LANG } });
    await loadIncidents();
    renderReceipt(result);
  } catch (error) {
    toast(error.message);
    button.disabled = false;
    button.textContent = t("usb.saveWipe", { drive: S.current.usb.drive });
  }
}

async function wipeIncident() {
  const confirmed = await confirmDialog({ title: t("usb.confirmWipeTitle"), body: t("usb.confirmWipe"),
    action: t("usb.wipe"), danger: true });
  if (!confirmed) return;
  try {
    await api(`/api/incidents/${encodeURIComponent(S.current.id)}/wipe`, { method: "POST" });
    toast(t("usb.wiped"));
    S.current = null;
    await loadIncidents();
    if (S.incidents[0]) await selectIncident(S.incidents[0].id); else renderEmpty();
  } catch (error) { toast(error.message); }
}

function renderReceipt(result) {
  closeStream();
  S.current = null;
  S.viewer = null;
  $("#composer").hidden = true;
  $("#evidence-body").replaceChildren();
  history.replaceState(null, "", location.pathname);
  renderIncidentList();
  $("#page").replaceChildren(el("div", { class: "card receipt" },
    el("div", { class: "receipt-mark", "aria-hidden": "true", text: "\u2713" }),
    el("h2", { text: t("usb.done.title") }),
    el("div", { class: "faint small", text: t("usb.done.path") }),
    el("code", { class: "receipt-path", text: result.path }),
    el("p", { text: t("usb.done.files") }),
    el("p", { text: t(result.wiped ? "usb.done.wiped" : "usb.done.kept") }),
    el("p", { class: "strong", text: t("usb.done.remove") }),
    el("div", {}, el("button", { class: "btn", type: "button", text: t("usb.done.back"),
      onclick: async () => { if (S.incidents[0]) await selectIncident(S.incidents[0].id); else renderEmpty(); } }))));
}

// Turns --------------------------------------------------------------------------------

function toolLabel(name, a) {
  const arg = (key, value) => (value ? t(`tool.arg.${key}`, { value }) : null);
  switch (name) {
    case "list_artifacts": return [t("tool.list_artifacts")];
    case "log_patterns": return [t("tool.log_patterns"), arg("level", a.level), a.file];
    case "search_logs": return [t("tool.search_logs"), a.pattern ? `“${a.pattern}”` : a.flagged_only ? t("tool.arg.suspicious") : "", arg("in", a.file)];
    case "read_lines": return [t("tool.read_lines"), `${a.file}:${a.start}–${a.end}`];
    case "timeline": return [t("tool.timeline"), arg("from", a.since), arg("to", a.until), arg("level", a.level)];
    case "search_docs": return [t("tool.search_docs"), `“${a.query}”`];
    case "read_doc": return [t("tool.read_doc"), a.path];
    case "recall_cases": return [t("tool.recall_cases"), a.query && `“${a.query}”`];
    default: return [name];
  }
}

class TurnView {
  constructor(parent, { message, pasted, live, index }) {
    this.live = live;
    this.index = index;
    this.message = message;
    this.events = [];
    this.tools = new Map();
    this.lastEventAt = Date.now();
    this.elapsed = 0;
    this.root = el("div", { class: "turn" });
    if (message || pasted) {
      this.root.append(el("div", { class: "dev-msg" },
        el("div", { class: "who", text: t("turn.developer") }),
        message ? el("div", { text: message }) : null,
        pasted ? el("pre", { text: pasted }) : null));
    }
    this.status = el("span");
    this.timer = el("span", { class: "faint" });
    this.spinner = live ? el("span", { class: "spinner", "aria-hidden": "true" }) : null;
    this.features = el("span", { class: "faint features" });
    this.replayButton = !live && index !== undefined ? el("button", {
      class: "btn ghost small", type: "button", text: t("turn.replay"), title: t("turn.replayTitle"),
      onclick: () => this.replay(),
    }) : null;
    this.log = el("div", { class: "log" });
    this.summary = el("span", { class: "faint summary" });
    this.foldButton = el("button", {
      class: "fold", type: "button", hidden: true, onclick: () => this.setFolded(!this.folded),
    }, el("span", { class: "chevron", "aria-hidden": "true" }));
    this.work = el("div", { class: "card work" },
      el("div", { class: "work-head" }, this.spinner, el("b", {}, this.status), this.timer, this.summary,
        el("span", { class: "spacer" }), this.features, this.replayButton, this.foldButton),
      this.log);
    this.after = el("div", { class: "after" });
    this.root.append(this.work, this.after);
    parent.append(this.root);
    this.status.textContent = t(live ? "turn.investigating" : "turn.investigation");
  }

  add(event) {
    this.events.push(event);
    this.lastEventAt = Date.now();
    if (typeof event.t === "number") this.elapsed = event.t;
    switch (event.type) {
      case "start":
        this.model = event.model;  // the model that ran this turn, whatever is selected now
        const state = (value) => (value === "off" ? t("option.off") : value);
        this.features.textContent = t("turn.features", {
          model: event.model, thinking: t(`option.${event.thinking}`), rag: state(event.features.rag),
          cases: state(event.features.cases), playbook: state(event.features.playbook),
          language: event.language === "ko" ? "한국어" : "English",
        });
        break;
      case "thinking": this.addThinking(event.delta); break;
      case "text": this.addText(event.delta); break;
      case "tool_call": this.addToolCall(event); break;
      case "tool_result": this.addToolResult(event); break;
      case "retry":
        this.closeThinking();
        this.foldDraft();
        this.log.append(el("div", { class: "note retry" },
          el("b", { text: `${t("turn.retry")} ` }), linkify(event.reason.slice(0, 500))));
        break;
      case "guide":
        this.closeThinking();
        this.foldDraft();
        this.status.textContent = t("turn.guideReady");
        this.after.append(renderGuide(event, this.model, this.live ? undefined : this.index), renderOutcome());
        break;
      case "question":
        this.closeThinking();
        this.foldDraft();
        this.status.textContent = t("turn.needsInfo");
        this.after.append(renderQuestion(event));
        break;
      case "done":
        this.log.append(el("div", { class: "stats" },
          el("span", { text: t("turn.stat.time", { time: duration(event.seconds) }) }),
          el("span", { text: t("turn.stat.requests", { count: event.requests }) }),
          el("span", { text: t("turn.stat.tools", { count: event.tool_calls }) }),
          el("span", { text: t("turn.stat.tokens", { read: number(event.input_tokens), written: number(event.output_tokens) }) })));
        break;
      case "error":
        this.status.textContent = t("turn.stopped");
        this.log.append(el("div", { class: "note error", text: event.message }));
        break;
    }
  }

  addThinking(delta) {
    if (!this.thinkingBlock) {
      const text = el("div", { class: "text" });
      const summary = el("summary", { text: t("turn.thinking") });
      const block = el("details", { class: "thinking", open: this.live }, summary, text);
      this.log.append(block);
      this.thinkingBlock = { block, text, summary };
    }
    this.thinkingBlock.text.append(delta);
    this.thinkingBlock.text.scrollTop = this.thinkingBlock.text.scrollHeight;
  }

  closeThinking() {
    if (!this.thinkingBlock) return;
    this.thinkingBlock.summary.textContent = t("turn.reasoning", { count: words(this.thinkingBlock.text.textContent) });
    this.thinkingBlock.block.open = false;
    this.thinkingBlock = null;
  }

  addText(delta) {
    this.closeThinking();
    if (!this.textBlock) {
      this.textBlock = el("div", { class: "model-text md" });
      this.textRaw = "";
      this.log.append(this.textBlock);
      if (this.live) this.status.textContent = t("turn.writing");
    }
    this.textRaw += delta;
    if (!this.renderPending) {
      this.renderPending = true;
      requestAnimationFrame(() => {
        this.renderPending = false;
        if (this.textBlock) this.textBlock.replaceChildren(renderMarkdown(this.textRaw));
      });
    }
  }

  foldDraft() {
    // The checked card replaces the live draft; keep the draft one click away.
    if (this.textBlock && this.textRaw) this.textBlock.replaceChildren(renderMarkdown(this.textRaw));
    for (const block of this.log.querySelectorAll(":scope > .model-text")) {
      const fold = el("details", { class: "draft" }, el("summary", { text: t("turn.draft", { count: words(block.textContent) }) }));
      block.replaceWith(fold);
      fold.append(block);
    }
    this.textBlock = null;
  }

  addToolCall(event) {
    this.closeThinking();
    this.textBlock = null;
    const [verb, ...rest] = toolLabel(event.name, event.args || {});
    const res = el("span", { class: "res" }, el("span", { class: "spinner inline", "aria-hidden": "true" }));
    const pre = el("pre", { text: "" });
    const node = el("details", { class: "tool" },
      el("summary", {}, el("span", { class: "icon", text: "›" }),
        el("span", { class: "what" }, `${verb} `, ...rest.filter(Boolean).map((part) => [el("em", { text: part }), " "])),
        res),
      pre);
    this.tools.set(event.id, { node, res, pre });
    this.log.append(node);
  }

  addToolResult(event) {
    const entry = this.tools.get(event.id);
    if (!entry) return;
    const first = (event.content || "").split("\n").find((line) => line.trim()) || "(empty)";
    entry.res.replaceChildren(`${first.slice(0, 70)}${first.length > 70 ? "…" : ""} · ${event.ms} ms`);
    entry.pre.replaceChildren(linkify(event.content || ""));
    if (event.error) entry.node.classList.add("error");
  }

  // A finished investigation folds to its header line; the chevron unfolds the steps.
  setFolded(folded) {
    this.folded = folded;
    this.work.classList.toggle("folded", folded);
    this.foldButton.hidden = false;
    this.foldButton.setAttribute("aria-expanded", String(!folded));
    this.foldButton.setAttribute("aria-label", t(folded ? "turn.showSteps" : "turn.hideSteps"));
    this.foldButton.title = t(folded ? "turn.showSteps" : "turn.hideSteps");
  }

  finish() {
    this.closeThinking();
    this.finished = true;
    if (this.spinner) this.spinner.remove();
    this.spinner = null;
    for (const entry of this.tools.values()) {
      if (entry.res.querySelector(".spinner")) entry.res.textContent = t("turn.noResult");
    }
    const done = this.events.find((event) => event.type === "done");
    this.timer.textContent = done ? `· ${duration(done.seconds)}` : "";
    if (this.status.textContent === t("turn.investigating")) this.status.textContent = t("turn.stopped");
    const calls = this.events.filter((event) => event.type === "tool_call").length;
    this.summary.textContent = calls ? `· ${t("turn.stat.tools", { count: calls })}` : "";
    // Keep a failed turn open: its error is in the steps.
    this.setFolded(!this.events.some((event) => event.type === "error"));
  }

  tick() {
    if (!this.live || this.finished) return;
    const now = Date.now();
    const total = this.elapsed + (now - this.lastEventAt) / 1000;
    const quiet = (now - this.lastEventAt) / 1000;
    const waiting = quiet > 6 ? ` · ${t("turn.quiet", { time: clock(quiet) })}` : "";
    this.timer.textContent = `· ${clock(total)}${waiting}`;
  }

  async replay() {
    const holder = el("div");
    this.root.replaceWith(holder);
    const view = new TurnView(holder, { message: this.message, pasted: "", live: true });
    view.status.textContent = t("turn.replaying");
    let previous = 0;
    for (const event of this.events) {
      const gap = Math.min(Math.max((event.t || previous) - previous, 0) / 8, 1.5);
      previous = event.t || previous;
      if (gap > 0.02) await new Promise((resolve) => setTimeout(resolve, gap * 1000));
      if ((event.type === "thinking" || event.type === "text") && event.delta.length > 400) {
        for (let i = 0; i < event.delta.length; i += 160) {
          view.add({ ...event, delta: event.delta.slice(i, i + 160) });
          await new Promise((resolve) => setTimeout(resolve, 30));
        }
      } else view.add(event);
      if (typeof event.t === "number") view.timer.textContent = `· ${t("turn.recorded", { time: clock(event.t) })}`;
    }
    view.finish();
    view.status.textContent = t("turn.replayed");
  }
}

function tickLive() { if (S.live) S.live.tick(); }

async function sendTurn(message = null, pasted = null) {
  if (!S.current || (S.live && !S.live.finished)) return;
  message = message ?? $("#message").value.trim();
  pasted = pasted ?? ($("#paste").hidden ? "" : $("#paste").value);
  try {
    await api(`/api/incidents/${encodeURIComponent(S.current.id)}/turn`, { json: { message, pasted } });
  } catch (error) { toast(error.message); return; }
  $("#message").value = ""; $("#paste").value = ""; $("#paste").hidden = true;
  const intro = S.turnsRoot.querySelector(":scope > .intro");
  if (intro) intro.remove();
  attachStream(S.current.id, { message, pasted });
  loadIncidents();
}

function attachStream(id, { message, pasted, resumed = false }) {
  closeStream();
  const view = new TurnView(S.turnsRoot, { message, pasted, live: true });
  if (resumed && S.current && S.current.turns.length) view.status.textContent = t("turn.resumed");
  S.live = view;
  updateComposer();
  const source = new EventSource(`/api/incidents/${encodeURIComponent(id)}/stream?from=0`);
  S.stream = source;
  source.onmessage = (event) => {
    view.add(JSON.parse(event.data));
    const main = $("#main");
    if (main.scrollHeight - main.scrollTop - main.clientHeight < 240) main.scrollTop = main.scrollHeight;
  };
  source.addEventListener("end", async () => {
    closeStream();
    view.finish();
    S.live = null;
    await selectIncident(id, { keepScroll: true });
    await loadIncidents();
  });
  source.onerror = () => { if (source.readyState === EventSource.CLOSED) { view.finish(); S.live = null; updateComposer(); } };
}

function closeStream() { if (S.stream) { S.stream.close(); S.stream = null; } }

// Guide --------------------------------------------------------------------------------

function renderGuide(event, model, index) {
  const guide = event.guide;
  const section = (key, ...content) => el("div", { class: "guide-section" }, el("h3", { text: t(key) }), ...content);
  const sections = [
    section("guide.rootCause", el("div", { class: "root-cause" }, linkify(guide.root_cause))),
    section("guide.evidence", el("ul", { class: "evidence-list" }, guide.evidence.map((item) => el("li", {},
      el("span", {}, linkify(item.ref)), el("span", {}, linkify(item.shows)))))),
    section("guide.steps", el("div", { class: "steps" }, guide.steps.map((step, index) => el("div", { class: "step" },
      el("div", { class: `num ${step.risk === "high" ? "high" : ""}`, text: String(index + 1) }),
      el("div", { class: "step-body" },
        el("div", { class: "title" }, step.title, el("span", { class: `badge ${step.risk}`, text: t(`risk.${step.risk}`) })),
        el("div", { class: "why" }, linkify(step.why)),
        step.commands.length ? commandBlock(step.commands) : null,
        el("dl", { class: "kv" },
          el("dt", { text: t("guide.expect") }), el("dd", {}, linkify(step.expected)),
          step.rollback ? el("dt", { text: t("guide.undo") }) : null,
          step.rollback ? el("dd", {}, linkify(step.rollback)) : null)))))),
  ];
  if (guide.verify.length) {
    sections.push(section("guide.verify", el("ul", { class: "verify" }, guide.verify.map((item) => el("li", {},
      el("label", {}, el("input", { type: "checkbox" }), el("span", {}, linkify(item))))))));
  }
  if (guide.unknowns.length) {
    sections.push(section("guide.unknowns", el("ul", { class: "plain-list" }, guide.unknowns.map((item) => el("li", {}, linkify(item))))));
  }
  if (guide.security_notes.length) {
    const security = section("guide.security", el("ul", { class: "plain-list" }, guide.security_notes.map((item) => el("li", {}, linkify(item)))));
    security.classList.add("security");
    sections.push(security);
  }
  const id = S.current.id;
  return el("article", { class: "card guide" },
    el("header", { class: "guide-head" },
      el("div", { class: "guide-kicker" },
        el("span", { class: `badge ${guide.confidence}-conf`, text: t(`guide.confidence.${guide.confidence}`) }),
        el("span", { text: t("guide.writtenBy", { model: model || S.status?.model || "local model" }) }),
        provenanceBadge(index)),
      el("h2", { text: guide.title }),
      el("p", { class: "summary" }, linkify(guide.summary))),
    event.checks.length ? el("div", { class: "checks", "aria-label": t("guide.checksLabel") },
      event.checks.map((check) => el("span", { class: `check ${check.level}`, text: checkText(check) }))) : null,
    ...sections,
    el("div", { class: "guide-actions" },
      S.current.usb && S.current.access === "manage" ? saveButton() : null,
      el("button", { class: "btn", type: "button", text: t("guide.copyMarkdown"), onclick: () => copy(event.markdown, t("copy.guide")) }),
      el("a", { class: "btn", href: `/api/incidents/${encodeURIComponent(id)}/guide.md`, text: t("guide.download") }),
      el("span", { class: "spacer" }),
      el("span", { class: "faint small", text: t("guide.checkedBy") })));
}

function saveButton() {
  const usb = S.current.usb;
  if (!usb.present) return el("button", { class: "btn primary", type: "button", disabled: true, text: t("usb.insertToSave", { drive: usb.drive }) });
  const button = el("button", { class: "btn primary", type: "button", text: t("usb.saveWipe", { drive: usb.drive }) });
  button.addEventListener("click", () => exportToDrive(button));
  return button;
}

function commandBlock(commands) {
  const text = commands.join("\n");
  return el("div", { class: "cmd" }, el("pre", { text }),
    el("button", { class: "copy", type: "button", text: t("copy.button"), onclick: () => copy(text, t("copy.commands")) }));
}

function renderQuestion(event) {
  const request = event.request;
  const output = el("textarea", { placeholder: t("question.placeholder") });
  const send = el("button", { class: "btn primary", type: "button", text: t("question.send"),
    onclick: () => sendTurn(t("question.message"), output.value) });
  return el("article", { class: "card question" },
    el("h3", { text: t("question.title") }),
    el("div", {}, linkify(request.reason)),
    request.questions.length ? el("ul", { class: "plain-list" }, request.questions.map((q) => el("li", {}, linkify(q)))) : null,
    request.commands.length ? el("div", {}, el("div", { class: "faint small", text: t("question.run") }), commandBlock(request.commands)) : null,
    event.checks.length ? el("div", { class: "check-row" },
      event.checks.map((check) => el("span", { class: `check ${check.level}`, text: checkText(check) }))) : null,
    output, el("div", {}, send));
}

function renderOutcome() {
  const recorded = S.current && S.current.outcome;
  if (recorded) {
    return el("div", { class: "card outcome" },
      el("div", {}, el("b", { text: t("outcome.recorded") }), t(`outcome.${recorded.outcome}`),
        recorded.notes ? el("span", { class: "muted", text: ` — ${recorded.notes}` }) : null),
      el("div", {}, el("button", { class: "btn small", type: "button", text: t("outcome.seeLearned"), onclick: openLearning })));
  }
  let choice = "resolved";
  const buttons = ["resolved", "partial", "not_resolved"].map((value) => el("button", {
    class: `btn choice${value === choice ? " on" : ""}`, type: "button", text: t(`outcome.${value}`),
    onclick: (event) => { choice = value; for (const b of buttons) b.classList.remove("on"); event.currentTarget.classList.add("on"); },
  }));
  const notes = el("input", { type: "text", placeholder: t("outcome.notes") });
  const cause = el("input", { type: "text", placeholder: t("outcome.cause") });
  const result = el("div", { class: "muted" });
  const submit = el("button", { class: "btn primary", type: "button", text: t("outcome.submit"), onclick: async () => {
    submit.disabled = true;
    result.replaceChildren(el("span", { class: "spinner inline" }), t("outcome.working"));
    try {
      const data = await api(`/api/incidents/${encodeURIComponent(S.current.id)}/outcome`,
        { json: { outcome: choice, notes: notes.value, root_cause: cause.value } });
      result.replaceChildren(el("b", { text: t("outcome.proposed", { case: data.case, count: data.added.length + data.merged.length }) }),
        data.approved ? t("outcome.approvedAuto") : t("outcome.awaiting"),
        el("button", { class: "btn small", type: "button", text: t("outcome.review"), onclick: openLearning }));
      loadLearningCount();
    } catch (error) {
      result.textContent = error.message;
      submit.disabled = false;
    }
  } });
  return el("div", { class: "card outcome" },
    el("div", {}, el("b", { text: t("outcome.ask") }), el("span", { class: "muted", text: t("outcome.explain") })),
    el("div", { class: "row" }, buttons),
    el("div", { class: "row" }, notes), el("div", { class: "row" }, cause),
    el("div", { class: "row" }, submit), result);
}

// Evidence panel -----------------------------------------------------------------------

function renderEvidence() {
  for (const button of document.querySelectorAll(".tabs button")) button.classList.toggle("on", button.dataset.tab === S.tab);
  const body = $("#evidence-body");
  if (!S.current) { body.replaceChildren(); return; }
  if (S.tab === "lines") { renderViewer(); return; }
  if (S.tab === "search") { renderSearch(); return; }
  const data = S.current;
  const levelClass = (level) => (level === "error" || level === "critical" ? "error" : level === "warning" ? "warn" : "ok");
  body.replaceChildren(
    el("section", {}, el("div", { class: "label", text: t("ev.files") }),
      el("div", { class: "files" }, data.artifacts.map((item) => el("div", {
        class: "file", role: "button", tabindex: "0", onclick: () => openLines(item.file, 1),
        onkeydown: (event) => { if (event.key === "Enter") openLines(item.file, 1); },
      },
        el("span", { class: "swatch", style: `background:${S.colors[item.file]}` }),
        el("span", { class: "name", title: item.file, text: item.file }),
        el("span", { class: "n", text: item.kind === "binary" ? t("ev.binary") : t("ev.linesErrors", { lines: number(item.lines), errors: number(item.errors) }) }),
        item.redactions || item.flagged ? el("span", { class: "flags" },
          item.redactions ? el("span", { class: "badge ok", text: t("ev.redacted", { count: item.redactions }) }) : null,
          item.flagged ? el("span", { class: "badge error", text: t("ev.suspicious", { count: item.flagged }) }) : null) : null)))),
    el("section", { class: "chart" }, el("div", { class: "label", text: t("ev.chart") }), histogram(data)),
    el("section", {}, el("div", { class: "label", text: t("ev.patterns") }),
      el("div", { class: "patterns" }, data.patterns.map((pattern) => {
        const sampleFile = pattern.sample.split(":").slice(0, -1).join(":");
        return el("div", { class: "pattern" },
          el("span", { class: "count", text: `×${number(pattern.count)}` }),
          el("div", {},
            el("div", { class: "tpl", text: pattern.template.length > 220 ? `${pattern.template.slice(0, 220)}…` : pattern.template }),
            el("div", { class: "sub" },
              pattern.level ? el("span", { class: `badge ${levelClass(pattern.level)}`, text: pattern.level + (pattern.guessed ? "?" : "") }) : null,
              refButton(pattern.sample, sampleFile, Number(pattern.sample.split(":").pop())),
              el("span", { text: pattern.first ? `${hhmm(pattern.first)}–${hhmm(pattern.last)}` : "" }))));
      }))));
}

function histogram(data) {
  const rows = data.histogram.rows;
  if (!rows.length) return el("div", { class: "faint", text: t("ev.noDated") });
  const svgNS = "http://www.w3.org/2000/svg";
  const make = (tag, attrs) => { const node = document.createElementNS(svgNS, tag); for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v); return node; };
  const size = data.histogram.bucket_seconds;
  const start = new Date(data.histogram.start.replace(" ", "T") + "Z");
  const end = new Date(data.range[1].replace(" ", "T") + "Z");
  const buckets = Math.max(1, Math.floor((end - start) / 1000 / size) + 1);
  const totals = new Array(buckets).fill(0);
  const byBucket = new Map();
  for (const row of rows) {
    totals[row.bucket] = (totals[row.bucket] || 0) + row.count;
    if (!byBucket.has(row.bucket)) byBucket.set(row.bucket, []);
    byBucket.get(row.bucket).push(row);
  }
  const max = Math.max(...totals, 1);
  const W = 360, H = 120, top = 12, bottom = 18, width = W / buckets;
  const svg = make("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": t("ev.chartAria") });
  svg.append(make("line", { x1: 0, x2: W, y1: H - bottom + 0.5, y2: H - bottom + 0.5, stroke: "var(--rule)" }));
  for (const [bucket, parts] of byBucket) {
    let y = H - bottom;
    const when = new Date(start.getTime() + bucket * size * 1000).toISOString().slice(11, 19);
    for (const part of parts.sort((a, b) => S.files.indexOf(a.file) - S.files.indexOf(b.file))) {
      const h = (part.count / max) * (H - top - bottom);
      y -= h;
      const rect = make("rect", { x: bucket * width + 0.5, y, width: Math.max(width - 1, 1), height: Math.max(h, 0.8), style: `fill:${S.colors[part.file]}` });
      const title = make("title", {});
      title.textContent = `${when}: ${part.file} ×${part.count}`;
      rect.append(title);
      svg.append(rect);
    }
  }
  const label = (x, anchor, text, y = H - 4) => { const node = make("text", { x, y, "text-anchor": anchor, class: "axis" }); node.textContent = text; return node; };
  svg.append(label(0, "start", start.toISOString().slice(11, 16)), label(W, "end", end.toISOString().slice(11, 16)),
    label(0, "start", t("ev.chartMax", { count: max, size }), 9));
  return el("div", {}, svg);
}

function setEvidenceOpen(open, { remember = true } = {}) {
  $("#evidence").classList.toggle("closed", !open);
  $(".body").classList.toggle("evidence-closed", !open);
  $("#evidence-toggle").setAttribute("aria-pressed", String(open));
  if (remember) store("blacksite.evidence", open ? "open" : "closed");
}

async function openLines(file, start, end = start) {
  if (!S.current) return;
  S.tab = "lines";
  setEvidenceOpen(true, { remember: false });
  try {
    S.viewer = await api(`/api/incidents/${encodeURIComponent(S.current.id)}/lines?file=${encodeURIComponent(file)}&line=${start}&end=${end}&context=14`);
  } catch (error) { toast(error.message); return; }
  renderEvidence();
}

function renderViewer() {
  const body = $("#evidence-body");
  const view = S.viewer;
  if (!view) { body.replaceChildren(el("div", { class: "faint", text: t("viewer.empty") })); return; }
  const [from, to] = view.focus;
  const first = view.lines.length ? view.lines[0].n : from;
  const last = view.lines.length ? view.lines[view.lines.length - 1].n : to;
  const list = el("div", { class: "lines" }, view.lines.map((line) => el("div", {
    class: `line${line.n >= from && line.n <= to ? " focus" : ""}${line.flagged ? " flagged" : ""}${line.level === "error" || line.level === "critical" ? " error" : ""}`,
    title: [line.ts, line.level && `${line.level}${line.guessed ? "?" : ""}`, line.flagged && t("viewer.flagged")].filter(Boolean).join(" · "),
  }, el("span", { class: "n", text: String(line.n) }), el("span", { class: "t", text: (line.flagged ? "⚠ " : "") + line.text }))));
  body.replaceChildren(
    el("div", { class: "viewer-head" },
      el("span", { class: "swatch", style: `background:${S.colors[view.file]}` }),
      el("span", { class: "name", text: view.file }),
      el("span", { class: "faint", text: t("viewer.range", { first, last, total: number(view.total) }) }),
      el("span", { class: "spacer" }),
      el("button", { class: "btn small", type: "button", text: "↑", title: t("viewer.earlier"), "aria-label": t("viewer.earlier"), disabled: first <= 1, onclick: () => openLines(view.file, Math.max(1, first - 14)) }),
      el("button", { class: "btn small", type: "button", text: "↓", title: t("viewer.later"), "aria-label": t("viewer.later"), disabled: last >= view.total, onclick: () => openLines(view.file, Math.min(view.total, last + 15)) })),
    list,
    el("div", { class: "faint small", text: t("viewer.note") }));
  const focus = list.querySelector(".focus");
  if (focus) focus.scrollIntoView({ block: "center" });
}

// Search -------------------------------------------------------------------------------
// The same search the agent's search_logs tool runs, for the person at the keyboard. Plain
// text by default; "Pattern" switches to RE2 regular expressions. A match opens in Lines.

function searchState() {
  if (!S.search || S.search.incident !== S.current.id) {
    S.search = { incident: S.current.id, query: "", file: "", level: "", regex: false, exact: false, result: null, error: "" };
  }
  return S.search;
}

async function runSearch() {
  const q = searchState();
  if (!q.query.trim()) { q.result = null; q.error = ""; renderSearch(); return; }
  const params = new URLSearchParams({ pattern: q.query, limit: "200" });
  if (q.file) params.set("file", q.file);
  if (q.level) params.set("level", q.level);
  if (!q.regex) params.set("literal", "1");
  if (q.exact) params.set("case", "1");
  try {
    q.result = await api(`/api/incidents/${encodeURIComponent(S.current.id)}/search?${params}`);
    q.error = "";
  } catch (error) { q.result = null; q.error = error.message; }
  renderSearch({ keepFocus: true });
}

// Highlights what matched. Regex syntax the browser can't read (RE2 differs a little) just
// shows the line without highlights.
function highlighted(text, q) {
  let pattern;
  try {
    pattern = new RegExp(q.regex ? q.query : q.query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), q.exact ? "g" : "gi");
  } catch { return [text]; }
  const out = [];
  let at = 0;
  for (const match of text.matchAll(pattern)) {
    if (!match[0]) continue;
    out.push(text.slice(at, match.index), el("mark", { text: match[0] }));
    at = match.index + match[0].length;
  }
  out.push(text.slice(at));
  return out;
}

function renderSearch({ keepFocus = false } = {}) {
  const body = $("#evidence-body");
  const q = searchState();
  const input = el("input", { type: "search", class: "search-input", value: q.query, placeholder: t("search.placeholder"),
    "aria-label": t("search.label"), spellcheck: "false", autocapitalize: "none" });
  input.addEventListener("input", () => { q.query = input.value; });
  const choose = (key) => (event) => { q[key] = event.target.value; runSearch(); };
  const toggle = (key) => (event) => { q[key] = event.target.checked; runSearch(); };
  const form = el("form", { class: "search-form", onsubmit: (event) => { event.preventDefault(); runSearch(); } },
    el("div", { class: "search-row" }, input, el("button", { class: "btn primary", type: "submit", text: t("search.go") })),
    el("div", { class: "search-row" },
      el("select", { "aria-label": t("search.file"), onchange: choose("file") },
        el("option", { value: "", text: t("search.allFiles") }),
        S.current.artifacts.map((item) => el("option", { value: item.file, text: item.file, selected: item.file === q.file }))),
      el("select", { "aria-label": t("search.level"), onchange: choose("level") },
        ["", "warning", "error"].map((value) => el("option", { value, text: t(value ? `search.level.${value}` : "search.anyLevel"), selected: value === q.level }))),
      el("label", { class: "check-line" }, el("input", { type: "checkbox", checked: q.regex, onchange: toggle("regex") }), el("span", { text: t("search.regex") })),
      el("label", { class: "check-line" }, el("input", { type: "checkbox", checked: q.exact, onchange: toggle("exact") }), el("span", { text: t("search.case") }))));
  let results;
  if (q.error) results = el("div", { class: "note error", text: q.error });
  else if (!q.result) results = el("p", { class: "faint small", text: t("search.intro") });
  else if (!q.result.lines.length) results = el("p", { class: "faint", text: t("search.none") });
  else {
    const shown = q.result.lines.length, total = q.result.total;
    results = el("div", { class: "search-results" },
      el("div", { class: "faint small" }, t("search.count", { count: number(total) }),
        total > shown ? ` ${t("search.more", { shown: number(shown) })}` : "", ` ${t("search.hint")}`),
      el("div", { class: "lines" }, q.result.lines.map((line) => el("button", {
        type: "button", class: `line hit${line.flagged ? " flagged" : ""}${line.level === "error" || line.level === "critical" ? " error" : ""}`,
        title: `${line.file}:${line.n}${line.ts ? ` · ${line.ts}` : ""}`, onclick: () => openLines(line.file, line.n),
      },
        el("span", { class: "n" }, el("span", { class: "swatch", style: `background:${S.colors[line.file]}` }), String(line.n)),
        el("span", { class: "t" }, el("span", { class: "hit-file", text: `${line.file} ` }), ...highlighted((line.flagged ? "⚠ " : "") + line.text, q))))));
  }
  body.replaceChildren(form, results);
  if (keepFocus || !q.result) input.focus();
}

// New incident -------------------------------------------------------------------------

function openNewIncident() {
  S.upload = [];
  $("#new-form").reset();
  renderUploadList();
  $("#new-modal").hidden = false;
  $("#new-form").elements.title.focus();
}

function renderUploadList() {
  $("#file-names").replaceChildren(...S.upload.map((file) => el("li", { text: `${file.name} (${number(Math.ceil(file.size / 1024))} KB)` })));
}

async function submitNewIncident(event) {
  event.preventDefault();
  const form = new FormData($("#new-form"));
  for (const file of S.upload) form.append("files", file, file.name);
  const submit = $("#new-submit");
  submit.disabled = true; submit.textContent = t("new.indexing");
  try {
    const data = await api("/api/incidents", { method: "POST", body: form });
    $("#new-modal").hidden = true;
    await loadIncidents();
    await selectIncident(data.id);
  } catch (error) { toast(error.message); }
  finally { submit.disabled = false; submit.textContent = t("new.create"); }
}

// Learning -----------------------------------------------------------------------------

async function loadLearningCount() {
  try {
    S.learning = await api("/api/learning");
    const pending = S.learning.cases.filter((c) => c.status === "pending").length + S.learning.bullets.filter((b) => b.status === "pending").length;
    const badge = $("#pending-count");
    badge.hidden = !pending;
    badge.textContent = String(pending);
  } catch { /* the badge is optional */ }
}

async function openLearning() {
  $("#learning").hidden = false;
  await loadLearningCount();
  renderLearning();
}

async function decide(ids, action) {
  try {
    S.learning = await api("/api/learning", { json: { ids, action } });
    renderLearning();
    loadLearningCount();
    toast(t(action === "approve" ? "learn.approved" : "learn.rejected"));
  } catch (error) { toast(error.message); }
}

function renderLearning() {
  const data = S.learning || { cases: [], bullets: [] };
  const pendingCases = data.cases.filter((c) => c.status === "pending");
  const pendingBullets = data.bullets.filter((b) => b.status === "pending");
  const approvedCases = data.cases.filter((c) => c.status === "approved");
  const active = data.bullets.filter((b) => b.status === "active");
  const actions = (id) => [el("button", { class: "btn small primary", type: "button", text: t("learn.approve"), onclick: () => decide([id], "approve") }),
    el("button", { class: "btn small", type: "button", text: t("learn.reject"), onclick: () => decide([id], "reject") })];
  const outcomeClass = (outcome) => (outcome === "resolved" ? "ok" : outcome === "partial" ? "warn" : "error");
  const caseCard = (c, pending) => el("div", { class: "learn-item" },
    el("div", { class: "top" }, el("span", { class: "id", text: c.id }),
      el("span", { class: `badge ${outcomeClass(c.outcome)}`, text: t(`outcome.${c.outcome}`) }),
      el("span", { class: "spacer" }), pending ? actions(c.id) : null),
    el("b", { text: c.title }),
    el("div", { class: "muted", text: t("learn.symptoms", { value: c.symptoms }) }),
    el("div", { text: t("learn.rootCause", { value: c.root_cause }) }),
    el("div", { text: t(c.outcome === "resolved" ? "learn.fix" : "learn.tried", { value: c.resolution }) }),
    c.lessons.length ? el("ul", { class: "plain-list" }, c.lessons.map((lesson) => el("li", { text: lesson }))) : null);
  const bulletCard = (b, pending) => el("div", { class: "learn-item" },
    el("div", { class: "top" }, el("span", { class: "id", text: b.id }), el("span", { class: "badge ok", text: t(`section.${b.section}`) }),
      pending ? null : el("span", { class: "faint small", text: `+${b.helpful} / −${b.harmful}` }),
      el("span", { class: "spacer" }), pending ? actions(b.id) : null),
    el("div", { text: b.text }));
  const group = (items) => el("div", { class: "stack" }, items);
  $("#learning-body").replaceChildren(
    el("p", { class: "muted flush", text: t("learn.intro") }),
    el("section", {}, el("div", { class: "label", text: t("learn.waiting", { count: pendingCases.length + pendingBullets.length }) }),
      pendingCases.length + pendingBullets.length ? group([...pendingCases.map((c) => caseCard(c, true)), ...pendingBullets.map((b) => bulletCard(b, true))])
        : el("div", { class: "faint", text: t("learn.nothing") })),
    el("section", {}, el("div", { class: "label", text: t("learn.playbook", { count: active.length }) }),
      active.length ? group(active.map((b) => bulletCard(b, false))) : el("div", { class: "faint", text: t("learn.noLessons") })),
    el("section", {}, el("div", { class: "label", text: t("learn.past", { count: approvedCases.length }) }),
      approvedCases.length ? group(approvedCases.map((c) => caseCard(c, false))) : el("div", { class: "faint", text: t("learn.noCases") })));
}

// Provenance ---------------------------------------------------------------------------

function icon(name) {
  const paths = {
    shield: "M8 1.5 2.5 3.5v4c0 3.5 2.4 6 5.5 7 3.1-1 5.5-3.5 5.5-7v-4z",
    check: "m5.5 8 1.8 1.8L10.8 6",
    alert: "M8 5v4M8 11.2v.1",
  };
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("class", "icon");
  svg.setAttribute("aria-hidden", "true");
  for (const part of name.split(" ")) {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", paths[part]);
    svg.append(path);
  }
  return svg;
}

function provenanceBadge(index) {
  const info = index === undefined ? null : S.current?.provenance?.[index];
  if (!info) return null;
  if (info.unsigned) return el("span", { class: "badge prov", title: t("prov.unsignedTitle"), text: t("prov.unsigned") });
  const state = !info.signed ? "error" : info.evidence === "unchanged" ? "ok" : "warn";
  const text = !info.signed ? t("prov.invalid") : info.evidence === "unchanged"
    ? t("prov.signed", { count: info.files }) : t("prov.changed");
  return el("button", { class: `badge prov ${state}`, type: "button", title: t("prov.open"), onclick: () => openProvenance(index + 1) },
    icon(state === "ok" ? "shield check" : "shield alert"), text);
}

function short(hash, size = 12) { return hash ? `${hash.slice(0, size)}…` : ""; }

async function openProvenance(turn) {
  let data;
  try { data = await api(`/api/incidents/${encodeURIComponent(S.current.id)}/provenance?turn=${turn}`); }
  catch (error) { toast(error.message); return; }
  const { manifest, check } = data;
  const verdict = (ok, good, bad) => el("div", { class: `verdict ${ok === null ? "unknown" : ok ? "ok" : "bad"}` },
    icon(ok === false ? "shield alert" : "shield check"), el("span", { text: ok === null ? t("prov.notChecked") : ok ? good : bad }));
  const kv = (pairs) => el("dl", { class: "kv" }, pairs.flatMap(([key, value]) => [el("dt", { text: t(key) }), el("dd", {}, value)]));
  const code = (text) => el("code", { class: "hash", title: text, text });
  const verifyCommand = `blacksite verify ${S.current.id}/provenance/turn-${turn}.json`;
  const close = () => overlay.remove();
  const overlay = el("div", { class: "overlay", onclick: (event) => { if (event.target === overlay) close(); } },
    el("div", { class: "modal prov-modal", role: "dialog", "aria-modal": "true", "aria-labelledby": "prov-title" },
      el("div", { class: "prov-head" }, el("h2", { id: "prov-title", text: t("prov.title") }), el("span", { class: "spacer" }),
        el("button", { class: "btn ghost small", type: "button", text: t("learn.close"), onclick: close })),
      el("div", { class: "verdicts" },
        verdict(check.signature, t("prov.sigOk", { key: check.key_fingerprint }), t("prov.sigBad")),
        verdict(check.guide, t("prov.guideOk"), t("prov.guideBad")),
        verdict(check.evidence === "unknown" ? null : check.evidence === "unchanged", t("prov.evidenceOk"), t("prov.evidenceBad"))),
      kv([
        ["prov.ranBy", `${data.actor_name || manifest.actor}`],
        ["prov.when", [manifest.started_at, manifest.finished_at].map((value) => new Date(value).toLocaleString(LANG === "ko" ? "ko-KR" : "en-US",
          { dateStyle: "medium", timeStyle: "medium" })).join(" → ")],
        ["prov.model", `${manifest.model.name} · ${manifest.model.provider}`],
        ["prov.switches", Object.entries(manifest.settings).map(([key, value]) => `${key} ${value}`).join(" · ")],
        ["prov.citations", t("prov.citationCount", { ok: manifest.checks.citations_ok, total: manifest.checks.citations_total })],
        ["prov.ledger", t("prov.ledgerAt", { seq: number(manifest.ledger_anchor.seq) })],
        ["prov.version", `Blacksite ${manifest.blacksite_version}`],
      ]),
      el("div", { class: "label", text: t("prov.files", { count: check.files.length }) }),
      el("div", { class: "prov-files" }, check.files.map((file) => el("div", { class: "prov-file" },
        el("span", { class: "mono name", text: file.file }),
        el("span", { class: "faint small", text: bytes(file.bytes) }),
        code(short(file.sha256)),
        el("span", { class: `badge ${file.status === "unchanged" ? "ok" : "warn"}`, text: t(`prov.status.${file.status}`) })))),
      el("details", { class: "prov-hashes" }, el("summary", { text: t("prov.hashes") }),
        kv([["prov.guideHash", code(manifest.guide_sha256)], ["prov.evidenceRoot", code(manifest.evidence_root)],
            ["prov.promptHash", code(manifest.prompt_sha256)], ["prov.keyId", code(manifest.key_id)]])),
      el("div", { class: "prov-verify" }, el("span", { class: "faint small", text: t("prov.verifyHint") }),
        el("div", { class: "cmd" }, el("pre", { text: verifyCommand }),
          el("button", { class: "copy", type: "button", text: t("copy.button"), onclick: () => copy(verifyCommand) })))));
  document.body.append(overlay);
  overlay.querySelector("button").focus();
}

// Sharing ------------------------------------------------------------------------------

async function openShare() {
  let members;
  try { members = (await api("/api/members")).members; } catch (error) { toast(error.message); return; }
  const incident = S.current;
  const shared = new Set(incident.shares.map((item) => item.id));
  const others = members.filter((member) => member.id !== incident.owner?.id && member.id !== S.me.user.id);
  const list = el("div", { class: "share-list" });
  const render = () => list.replaceChildren(...(others.length ? others.map((member) => el("div", { class: "share-row" },
    el("span", { class: "avatar", style: `background:${avatarColor(member.id)}`, text: initials(member.display_name) }),
    el("span", {}, el("b", { text: member.display_name }), " ", el("span", { class: "faint small mono", text: member.username })),
    el("span", { class: "spacer" }),
    el("button", { class: `btn small ${shared.has(member.id) ? "" : "primary"}`, type: "button",
      text: t(shared.has(member.id) ? "share.remove" : "share.add"),
      onclick: async () => {
        const action = shared.has(member.id) ? "unshare" : "share";
        try {
          await api(`/api/incidents/${encodeURIComponent(incident.id)}/share`, { json: { user_id: member.id, action } });
          if (action === "share") shared.add(member.id); else shared.delete(member.id);
          render();
        } catch (error) { toast(error.message); }
      } })))
    : [el("p", { class: "faint", text: t("share.nobody") })]));
  render();
  const close = async () => { overlay.remove(); await selectIncident(incident.id, { keepScroll: true }); };
  const overlay = el("div", { class: "overlay", onclick: (event) => { if (event.target === overlay) close(); } },
    el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-labelledby": "share-title" },
      el("h2", { id: "share-title", text: t("share.title") }),
      el("p", { class: "flush muted", text: t("share.body") }),
      list,
      el("div", { class: "modal-actions" }, el("button", { class: "btn primary", type: "button", text: t("share.done"), onclick: close }))));
  document.body.append(overlay);
}

// Account ------------------------------------------------------------------------------

async function renderAccount() {
  const root = $("#view-account");
  S.me = await api("/api/me");
  renderUserButton();
  const user = S.me.user;
  const current = el("input", { type: "password", autocomplete: "current-password", required: true });
  const fresh = el("input", { type: "password", autocomplete: "new-password", required: true, minlength: "12" });
  const again = el("input", { type: "password", autocomplete: "new-password", required: true });
  const passwordError = el("p", { class: "form-error", role: "alert", hidden: true });
  const passwordForm = el("form", { class: "stack", onsubmit: async (event) => {
    event.preventDefault();
    passwordError.hidden = true;
    try {
      if (fresh.value !== again.value) throw new Error(t("login.mismatch"));
      const data = await api("/auth/password", { json: { current: current.value, new: fresh.value } });
      S.me.csrf = data.csrf;
      current.value = fresh.value = again.value = "";
      toast(t("account.passwordChanged"));
    } catch (error) { passwordError.hidden = false; passwordError.textContent = error.message; }
  } },
  el("label", { class: "field" }, el("span", { text: t("account.current") }), current),
  el("label", { class: "field" }, el("span", { text: t("login.newPassword") }), fresh),
  el("label", { class: "field" }, el("span", { text: t("login.repeatPassword") }), again),
  el("p", { class: "faint small flush", text: t("login.passwordHint") }),
  passwordError,
  el("div", {}, el("button", { class: "btn primary", type: "submit", text: t("account.changePassword") })));

  const twoStep = el("div", { class: "stack" });
  const renderTwoStep = () => {
    if (!totpAvailable()) {
      twoStep.replaceChildren(el("div", { class: "verdict unknown" }, icon("shield"), el("span", { text: t("account.totpDisabled") })),
        el("p", { class: "faint small flush", text: t("account.totpDisabledHint") }));
      return;
    }
    if (S.me.user.totp_enabled) {
      twoStep.replaceChildren(el("div", { class: "verdict ok" }, icon("shield check"), el("span", { text: t("account.totpOn") })),
        el("p", { class: "faint small flush", text: t("account.totpOnHint") }));
      return;
    }
    twoStep.replaceChildren(el("div", { class: "verdict unknown" }, icon("shield alert"), el("span", { text: t("account.totpOff") })),
      el("p", { class: "faint small flush", text: t("account.totpOffHint") }),
      el("div", {}, el("button", { class: "btn primary", type: "button", text: t("account.setUp"), onclick: startSetup })));
  };
  const startSetup = async () => {
    let setup;
    try { setup = await api("/auth/totp/setup"); } catch (error) { toast(error.message); return; }
    const code = el("input", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: "7", required: true });
    const error = el("p", { class: "form-error", role: "alert", hidden: true });
    twoStep.replaceChildren(el("div", { class: "qr-block" },
      el("img", { class: "qr", src: setup.qr, alt: t("login.qrAlt"), width: "168", height: "168" }),
      el("div", { class: "qr-side" }, el("ol", { class: "login-steps" },
        el("li", { text: t("login.enrollStep1") }), el("li", { text: t("login.enrollStep2") }), el("li", { text: t("login.enrollStep3") })),
      el("details", {}, el("summary", { text: t("login.manual") }), el("code", { class: "secret", text: setup.secret.match(/.{1,4}/g).join(" ") })))),
    el("form", { class: "stack", onsubmit: async (event) => {
      event.preventDefault();
      try {
        const data = await api("/auth/totp/enroll", { json: { code: code.value } });
        S.me.csrf = data.csrf;
        S.me.user.totp_enabled = true;
        twoStep.replaceChildren(el("p", { class: "flush", text: t("login.recoveryLead") }),
          el("ol", { class: "recovery-codes" }, data.recovery_codes.map((item) => el("li", {}, el("code", { text: item })))),
          el("div", { class: "row-actions" },
            el("button", { class: "btn", type: "button", text: t("login.copyCodes"), onclick: () => copy(data.recovery_codes.join("\n")) }),
            el("button", { class: "btn primary", type: "button", text: t("login.continue"), onclick: renderTwoStep })));
      } catch (failure) { error.hidden = false; error.textContent = failure.message; }
    } }, el("label", { class: "field" }, el("span", { text: t("login.code") }), code), error,
    el("div", {}, el("button", { class: "btn primary", type: "submit", text: t("login.enrollSubmit") }))));
    code.focus();
  };
  renderTwoStep();

  const session = S.me.session;
  root.replaceChildren(el("div", { class: "account-page" },
    el("header", { class: "view-head" }, el("div", {},
      el("h1", { text: t("account.title") }), el("div", { class: "faint", text: `${user.display_name} · ${user.username} · ${t(`role.${user.role}`)}` }))),
    el("div", { class: "account-grid" },
      el("section", { class: "card pad" }, el("h2", { text: t("account.password") }), passwordForm),
      el("section", { class: "card pad" }, el("h2", { text: t("account.twoStep") }), twoStep),
      el("section", { class: "card pad" }, el("h2", { text: t("account.session") }),
        el("dl", { class: "kv" },
          el("dt", { text: t("account.sessionId") }), el("dd", {}, el("code", { class: "hash", text: short(session.id, 8) })),
          el("dt", { text: t("account.expires") }), el("dd", { text: new Date(session.expires_at * 1000).toLocaleString(LANG) }),
          el("dt", { text: t("account.idle") }), el("dd", { text: t("account.idleMinutes", { m: session.idle_minutes }) })),
        el("p", { class: "faint small", text: t("account.auditNote") }),
        el("div", {}, el("button", { class: "btn danger", type: "button", text: t("user.signOut"), onclick: signOut }))))));
}

// Run after every script on the page has loaded (dashboard.js and admin.js define views).
document.addEventListener("DOMContentLoaded", () => boot().catch((error) => {
  $("#view-incidents").hidden = false;
  $("#page").replaceChildren(el("div", { class: "empty" }, el("h2", { text: t("error.server") }), el("p", { text: error.message })));
}));
