// Blacksite sign-in: password, then (first time) a new password, then two-step sign-in.
// Plain DOM, no dependencies, no inline scripts. Secrets never go into the URL or storage.
"use strict";

let I18N = { en: {}, ko: {} };
let LANG = "en";
let CSRF = "";
const $ = (selector) => document.querySelector(selector);

function t(key, vars = {}) {
  const text = I18N[LANG]?.[key] ?? I18N.en?.[key] ?? key;
  return text.replace(/\{(\w+)\}/g, (whole, name) => (name in vars ? String(vars[name]) : whole));
}

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

async function call(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json", ...(CSRF ? { "X-CSRF-Token": CSRF } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  const data = await response.json().catch(() => ({}));
  if (data.csrf) CSRF = data.csrf;
  if (!response.ok) {
    const error = new Error(data.error || response.statusText);
    error.login = Boolean(data.login);
    throw error;
  }
  return data;
}

function showError(message) {
  const box = $("#login-error");
  box.hidden = !message;
  box.textContent = message || "";
}

function heading(titleKey, leadKey, vars) {
  $("#login-title").textContent = t(titleKey, vars);
  $("#login-lead").textContent = leadKey ? t(leadKey, vars) : "";
  document.title = `${t(titleKey, vars)} · Blacksite`;
}

function field(labelKey, attrs) {
  const input = el("input", { class: "login-input", ...attrs });
  return { input, node: el("label", { class: "field" }, el("span", { text: t(labelKey) }), input) };
}

function form(fields, buttonKey, onsubmit, extra = null) {
  const button = el("button", { class: "btn primary login-submit", type: "submit", text: t(buttonKey) });
  const node = el("form", {
    class: "login-form", novalidate: true,
    onsubmit: async (event) => {
      event.preventDefault();
      button.disabled = true;
      showError("");
      try { await onsubmit(); }
      catch (error) {
        if (error.login) { CSRF = ""; renderPassword(); }
        showError(error.message);
      } finally { button.disabled = false; }
    },
  }, fields.map((item) => item.node), button, extra);
  return node;
}

function show(...nodes) {
  $("#login-step").replaceChildren(...nodes);
  const first = $("#login-step input");
  if (first) first.focus();
}

// Only a page on this server: a ?next= link that starts with // or a backslash never leads elsewhere.
function safeNext(raw) {
  try {
    const url = new URL(raw || "/", location.origin);
    return url.origin === location.origin ? url.pathname + url.search + url.hash : "/";
  } catch { return "/"; }
}

function done() {
  location.replace(safeNext(new URLSearchParams(location.search).get("next")));
}

async function advance(stage) {
  if (stage === "full") done();
  else if (stage === "password_change") renderPasswordChange();
  else if (stage === "totp_enroll") await renderEnroll();
  else if (stage === "totp") renderCode();
  else renderPassword();
}

function renderPassword() {
  heading("login.title", "login.lead");
  const username = field("login.username", { name: "username", autocomplete: "username", autocapitalize: "none", spellcheck: "false", required: true });
  const password = field("login.password", { name: "password", type: "password", autocomplete: "current-password", required: true });
  show(form([username, password], "login.submit", async () => {
    const data = await call("/auth/login", { username: username.input.value, password: password.input.value });
    password.input.value = "";
    await advance(data.stage);
  }));
}

function renderPasswordChange() {
  heading("login.changeTitle", "login.changeLead");
  const fresh = field("login.newPassword", { type: "password", autocomplete: "new-password", required: true, minlength: "12" });
  const again = field("login.repeatPassword", { type: "password", autocomplete: "new-password", required: true });
  const meter = el("div", { class: "strength", "aria-live": "polite" });
  fresh.input.addEventListener("input", () => {
    const value = fresh.input.value;
    const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(value)).length;
    const score = value.length < 12 ? 0 : Math.min(3, Math.floor(value.length / 8) + (kinds >= 3 ? 1 : 0));
    meter.dataset.score = String(score);
    meter.textContent = value ? t(`login.strength${score}`) : "";
  });
  const hint = { node: el("div", { class: "password-hint" }, meter, el("p", { class: "faint small flush", text: t("login.passwordHint") })) };
  show(form([fresh, again, hint], "login.changeSubmit", async () => {
    if (fresh.input.value !== again.input.value) throw new Error(t("login.mismatch"));
    const data = await call("/auth/password", { new: fresh.input.value });
    await advance(data.stage);
  }));
}

async function renderEnroll() {
  heading("login.enrollTitle", "login.enrollLead");
  const setup = await call("/auth/totp/setup");
  const code = field("login.code", { inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]*", maxlength: "7", required: true });
  const grouped = setup.secret.match(/.{1,4}/g).join(" ");
  const qr = el("div", { class: "qr-block" },
    el("img", { class: "qr", src: setup.qr, alt: t("login.qrAlt"), width: "184", height: "184" }),
    el("div", { class: "qr-side" },
      el("ol", { class: "login-steps" },
        el("li", { text: t("login.enrollStep1") }),
        el("li", { text: t("login.enrollStep2") }),
        el("li", { text: t("login.enrollStep3") })),
      el("details", {}, el("summary", { text: t("login.manual") }),
        el("code", { class: "secret", text: grouped }))));
  show(qr, form([code], "login.enrollSubmit", async () => {
    const data = await call("/auth/totp/enroll", { code: code.input.value });
    renderRecovery(data.recovery_codes, data.stage);
  }));
}

function renderRecovery(codes, stage) {
  heading("login.recoveryTitle", "login.recoveryLead");
  const text = codes.join("\n");
  const saved = el("input", { type: "checkbox", id: "saved" });
  const next = el("button", { class: "btn primary login-submit", type: "button", text: t("login.continue"), disabled: true,
    onclick: () => advance(stage) });
  saved.addEventListener("change", () => { next.disabled = !saved.checked; });
  show(
    el("ol", { class: "recovery-codes" }, codes.map((item) => el("li", {}, el("code", { text: item })))),
    el("div", { class: "row-actions" },
      el("button", { class: "btn", type: "button", text: t("login.copyCodes"),
        onclick: async () => { try { await navigator.clipboard.writeText(text); showError(""); } catch { showError(t("copy.failed")); } } }),
      el("a", { class: "btn", download: "blacksite-recovery-codes.txt",
        href: URL.createObjectURL(new Blob([`${t("login.recoveryFile")}\n\n${text}\n`], { type: "text/plain" })),
        text: t("login.downloadCodes") })),
    el("label", { class: "check-line" }, saved, el("span", { text: t("login.savedCodes") })),
    next);
}

function renderCode(recovery = false) {
  heading(recovery ? "login.recoveryUseTitle" : "login.codeTitle", recovery ? "login.recoveryUseLead" : "login.codeLead");
  const code = recovery
    ? field("login.recoveryCode", { autocomplete: "off", autocapitalize: "none", spellcheck: "false", required: true })
    : field("login.code", { inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]*", maxlength: "7", required: true });
  const toggle = el("button", { class: "btn ghost small", type: "button", text: t(recovery ? "login.useApp" : "login.useRecovery"),
    onclick: () => renderCode(!recovery) });
  show(form([code], "login.verify", async () => {
    const data = await call(recovery ? "/auth/recovery" : "/auth/totp/verify", { code: code.input.value });
    if (recovery && data.remaining !== undefined && data.remaining < 3) sessionStorage.setItem("blacksite.lowCodes", String(data.remaining));
    await advance(data.stage);
  }, el("div", { class: "row-actions" }, toggle,
    el("button", { class: "btn ghost small", type: "button", text: t("login.startOver"),
      onclick: async () => { try { await call("/auth/logout", {}); } catch { /* already signed out */ } CSRF = ""; renderPassword(); } }))));
}

function applyText() {
  document.documentElement.lang = LANG;
  for (const node of document.querySelectorAll("[data-i18n]")) node.textContent = t(node.dataset.i18n);
  for (const node of document.querySelectorAll("[data-i18n-aria]")) node.setAttribute("aria-label", t(node.dataset.i18nAria));
  for (const button of document.querySelectorAll("#lang-toggle button")) {
    button.classList.toggle("on", button.dataset.lang === LANG);
    button.setAttribute("aria-pressed", String(button.dataset.lang === LANG));
  }
}

async function start() {
  try { I18N = await (await fetch(window.BLACKSITE_I18N || "/static/i18n.json")).json(); } catch { /* keys show */ }
  let saved = "";
  try { saved = localStorage.getItem("blacksite.lang") || ""; } catch { /* storage unavailable */ }
  LANG = saved || ((navigator.language || "en").toLowerCase().startsWith("ko") ? "ko" : "en");
  if (!(LANG in I18N)) LANG = "en";
  applyText();
  let stage = null;
  const refresh = async () => {
    try { const me = await call("/api/me"); stage = me.stage; } catch { stage = null; }
    await advance(stage);
  };
  for (const button of document.querySelectorAll("#lang-toggle button")) {
    button.addEventListener("click", async () => {
      LANG = button.dataset.lang;
      try { localStorage.setItem("blacksite.lang", LANG); } catch { /* storage unavailable */ }
      applyText();
      showError("");
      await refresh();
    });
  }
  await refresh();
}

start().catch((error) => showError(error.message));
