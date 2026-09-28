// The admin console: members, sessions (with per-session timelines), the audit log, incident
// access, and security health. Uses app.js and dashboard.js helpers (el, t, api, svg, icon).
"use strict";

const ADMIN = { tab: "members", audit: { filters: {}, records: [], next: null }, health: null, members: [] };
const TABS = ["members", "sessions", "audit", "incidents", "health"];

async function renderAdmin(tab, rest = []) {
  ADMIN.tab = TABS.includes(tab) ? tab : "members";
  const root = $("#view-admin");
  const body = el("div", { class: "admin-body" }, el("div", { class: "faint", text: t("dash.loading") }));
  root.replaceChildren(el("div", { class: "admin-page" },
    el("header", { class: "view-head" },
      el("div", {}, el("h1", { text: t("admin.title") }), el("div", { class: "faint", text: t("admin.subtitle") }))),
    el("nav", { class: "tabs admin-tabs", "aria-label": t("admin.title") }, TABS.map((name) => el("a", {
      href: `#/admin/${name}`, class: name === ADMIN.tab ? "on" : "", "aria-current": name === ADMIN.tab ? "page" : null,
      text: t(`admin.tab.${name}`) }))),
    body));
  try {
    if (ADMIN.tab === "members") await membersTab(body);
    else if (ADMIN.tab === "sessions") await (rest[0] ? timelineTab(body, rest[0]) : sessionsTab(body));
    else if (ADMIN.tab === "audit") await auditTab(body);
    else if (ADMIN.tab === "incidents") await incidentsTab(body);
    else await healthTab(body);
  } catch (error) {
    body.replaceChildren(el("p", { class: "form-error", text: error.message }));
  }
}

function stamp(iso) {
  return iso ? new Date(iso).toLocaleString(LANG === "ko" ? "ko-KR" : "en-US", { dateStyle: "medium", timeStyle: "short" }) : "";
}

function when(iso) {
  if (!iso) return "—";
  const date = typeof iso === "number" ? new Date(iso * 1000) : new Date(iso);
  return el("time", { datetime: date.toISOString(), title: date.toLocaleString(LANG), text: relative(date) });
}

function person(user) {
  return el("span", { class: "person" },
    el("span", { class: "avatar", style: `background:${avatarColor(user.id)}`, text: initials(user.display_name || user.username) }),
    el("span", {}, el("b", { text: user.display_name || "—" }), el("span", { class: "faint small mono", text: user.username || "" })));
}

function secretDialog(title, body, secret) {
  const close = () => overlay.remove();
  const overlay = el("div", { class: "overlay" },
    el("div", { class: "modal dialog", role: "alertdialog", "aria-modal": "true", "aria-labelledby": "secret-title" },
      el("h2", { id: "secret-title", text: title }),
      el("p", { class: "flush muted", text: body }),
      el("div", { class: "cmd secret-box" }, el("pre", { text: secret }),
        el("button", { class: "copy", type: "button", text: t("copy.button"), onclick: () => copy(secret) })),
      el("p", { class: "faint small flush", text: t("admin.shownOnce") }),
      el("div", { class: "modal-actions" }, el("button", { class: "btn primary", type: "button", text: t("share.done"), onclick: close }))));
  document.body.append(overlay);
  overlay.querySelector(".copy").focus();
}

// Members --------------------------------------------------------------------------------

async function membersTab(body) {
  const { users } = await api("/api/admin/users");
  ADMIN.members = users;
  const act = async (user, action, extra = {}) => {
    const labels = {
      suspend: ["admin.confirmSuspend", true], activate: ["admin.confirmActivate", false],
      reset_password: ["admin.confirmResetPassword", true], reset_totp: ["admin.confirmResetTotp", true],
      role: [extra.role === "admin" ? "admin.confirmMakeAdmin" : "admin.confirmMakeMember", false],
    };
    const [key, danger] = labels[action];
    const ok = await confirmDialog({ title: t(`${key}.title`, { name: user.display_name }), body: t(`${key}.body`, { name: user.display_name }),
      action: t(`${key}.action`), danger });
    if (!ok) return;
    try {
      const result = await api(`/api/admin/users/${user.id}`, { json: { action, ...extra } });
      if (result.temporary_password) {
        secretDialog(t("admin.tempTitle", { name: user.display_name }), t("admin.tempBody"), result.temporary_password);
      } else toast(t("admin.done"));
      await renderAdmin("members");
    } catch (error) { toast(error.message); }
  };
  const rows = users.map((user) => {
    const self = user.id === S.me.user.id;
    const locked = user.locked_until && user.locked_until * 1000 > Date.now();
    const status = user.status === "suspended" ? ["error", "admin.suspended"] : locked ? ["warn", "admin.locked"] : ["ok", "admin.active"];
    return el("tr", {},
      el("td", {}, person(user), self ? el("span", { class: "badge", text: t("admin.you") }) : null),
      el("td", {}, el("span", { class: `role-badge ${user.role}`, text: t(`role.${user.role}`) })),
      el("td", {}, el("span", { class: `badge ${status[0]}`, text: t(status[1]) }), user.must_change ? el("span", { class: "badge warn", text: t("admin.mustChange") }) : null),
      el("td", {}, el("span", { class: `badge ${totpAvailable() ? user.totp_enabled ? "ok" : user.role === "admin" ? "error" : "" : ""}`,
        text: t(!totpAvailable() ? "account.disabled" : user.totp_enabled ? "account.on" : "account.off") })),
      el("td", {}, when(user.last_login_at)),
      el("td", { class: "num", text: number(user.sessions) }),
      el("td", { class: "num", text: number(user.incidents) }),
      el("td", { class: "actions" }, self ? el("span", { class: "faint small", text: t("admin.selfHint") }) : [
        el("button", { class: "btn small", type: "button", text: t("admin.resetPassword"), onclick: () => act(user, "reset_password") }),
        totpAvailable() && user.totp_enabled ? el("button", { class: "btn small", type: "button", text: t("admin.resetTotp"), onclick: () => act(user, "reset_totp") }) : null,
        el("button", { class: "btn small", type: "button", text: t(user.role === "admin" ? "admin.makeMember" : "admin.makeAdmin"),
          onclick: () => act(user, "role", { role: user.role === "admin" ? "member" : "admin" }) }),
        user.status === "active"
          ? el("button", { class: "btn small danger", type: "button", text: t("admin.suspend"), onclick: () => act(user, "suspend") })
          : el("button", { class: "btn small", type: "button", text: t("admin.activate"), onclick: () => act(user, "activate") }),
      ]));
  });
  body.replaceChildren(
    el("div", { class: "toolbar" },
      el("p", { class: "faint flush", text: t("admin.membersIntro", { count: users.length }) }),
      el("span", { class: "spacer" }),
      el("button", { class: "btn primary", type: "button", text: t("admin.addMember"), onclick: addMemberDialog })),
    el("div", { class: "table-scroll card" }, el("table", { class: "data-table admin-table" },
      el("thead", {}, el("tr", {}, ["admin.col.member", "admin.col.role", "admin.col.status", "admin.col.twoStep", "admin.col.lastSignIn",
        "admin.col.sessions", "admin.col.incidents", "admin.col.actions"].map((key) => el("th", { text: t(key) })))),
      el("tbody", {}, rows))));
}

function addMemberDialog() {
  const username = el("input", { required: true, autocomplete: "off", autocapitalize: "none", spellcheck: "false", pattern: "[A-Za-z0-9._-]{2,40}" });
  const name = el("input", { autocomplete: "off" });
  const role = el("select", {}, el("option", { value: "member", text: t("role.member") }), el("option", { value: "admin", text: t("role.admin") }));
  const error = el("p", { class: "form-error", role: "alert", hidden: true });
  const close = () => overlay.remove();
  const overlay = el("div", { class: "overlay" }, el("form", { class: "modal dialog", role: "dialog", "aria-modal": "true", "aria-labelledby": "add-title",
    onsubmit: async (event) => {
      event.preventDefault();
      try {
        const result = await api("/api/admin/users", { json: { username: username.value, display_name: name.value, role: role.value } });
        close();
        secretDialog(t("admin.createdTitle", { name: result.user.display_name }),
          t(totpAvailable() && result.user.role === "admin" ? "admin.createdBodyAdmin" : "admin.createdBody", { username: result.user.username }),
          result.temporary_password);
        await renderAdmin("members");
      } catch (failure) { error.hidden = false; error.textContent = failure.message; }
    } },
  el("h2", { id: "add-title", text: t("admin.addMember") }),
  el("p", { class: "flush muted", text: t("admin.addIntro") }),
  el("label", { class: "field" }, el("span", { text: t("login.username") }), username),
  el("label", { class: "field" }, el("span", {}, t("admin.displayName"), " ", el("span", { class: "faint", text: t("new.optional") })), name),
  el("label", { class: "field" }, el("span", { text: t("admin.col.role") }), role),
  el("p", { class: "faint small flush", text: t(totpAvailable() ? "admin.roleHint" : "admin.roleHintPassword") }),
  error,
  el("div", { class: "modal-actions" },
    el("button", { class: "btn", type: "button", text: t("dialog.cancel"), onclick: close }),
    el("button", { class: "btn primary", type: "submit", text: t("admin.create") }))));
  document.body.append(overlay);
  username.focus();
}

// Sessions -------------------------------------------------------------------------------

async function sessionsTab(body) {
  const { sessions } = await api("/api/admin/sessions");
  const revoke = async (session) => {
    const ok = await confirmDialog({ title: t("admin.revokeTitle"), body: t("admin.revokeBody", { name: session.user.display_name }),
      action: t("admin.revoke"), danger: true });
    if (!ok) return;
    try { await api(`/api/admin/sessions/${session.id}/revoke`, { method: "POST" }); toast(t("admin.done")); await renderAdmin("sessions"); }
    catch (error) { toast(error.message); }
  };
  body.replaceChildren(
    el("p", { class: "faint", text: t("admin.sessionsIntro", { count: sessions.length }) }),
    el("div", { class: "table-scroll card" }, el("table", { class: "data-table admin-table" },
      el("thead", {}, el("tr", {}, ["admin.col.member", "admin.col.session", "admin.col.started", "admin.col.lastActive", "admin.col.expires",
        "admin.col.browser", "admin.col.actions"].map((key) => el("th", { text: t(key) })))),
      el("tbody", {}, sessions.map((session) => el("tr", {},
        el("td", {}, person(session.user)),
        el("td", {}, el("code", { class: "hash", text: short(session.id, 8) }), session.current ? el("span", { class: "badge ok", text: t("admin.thisSession") }) : null,
          session.stage !== "full" ? el("span", { class: "badge warn", text: t(`admin.stage.${session.stage}`) }) : null),
        el("td", {}, when(session.created_at)),
        el("td", {}, when(session.last_seen_at)),
        el("td", {}, when(session.expires_at)),
        el("td", {}, el("code", { class: "hash", title: t("admin.browserHint"), text: session.ua_hash.slice(0, 8) })),
        el("td", { class: "actions" },
          el("a", { class: "btn small", href: `#/admin/sessions/${session.id}`, text: t("admin.timeline") }),
          session.current ? null : el("button", { class: "btn small danger", type: "button", text: t("admin.revoke"), onclick: () => revoke(session) }))))))),
    el("p", { class: "faint small", text: t("admin.sessionsHint") }));
}

function recordItem(record) {
  const kind = record.actor.startsWith("user:") ? "user" : record.actor.startsWith("cli:") ? "cli" : "system";
  return { seq: record.seq, at: record.at, action: record.action, detail: record.detail || {}, target_name: record.target_name,
    actor: { kind, id: kind === "user" ? Number(record.actor.slice(5)) : null, name: record.actor_name },
    incident: record.target && !record.target.startsWith("user:") ? { id: record.target, title: null } : null };
}

async function timelineTab(body, sessionId) {
  const [data, health] = await Promise.all([api(`/api/admin/sessions/${sessionId}/timeline`), api("/api/admin/health")]);
  const verified = health.last_verification;
  const session = data.session;
  const records = data.records.slice().reverse();
  body.replaceChildren(
    el("a", { class: "btn ghost small", href: "#/admin/sessions", text: t("admin.backToSessions") }),
    el("section", { class: "card pad timeline-head" },
      person(data.user),
      el("dl", { class: "kv" },
        el("dt", { text: t("admin.col.session") }), el("dd", {}, el("code", { class: "hash", text: session.id })),
        el("dt", { text: t("admin.col.started") }), el("dd", {}, when(session.created_at)),
        el("dt", { text: t("admin.col.lastActive") }), el("dd", {}, when(session.last_seen_at)),
        el("dt", { text: t("admin.ended") }), el("dd", {}, session.ended_at ? [when(session.ended_at), ` · ${t(`admin.end.${session.end_reason}`)}`] : t("admin.stillActive")),
        el("dt", { text: t("admin.col.browser") }), el("dd", {}, el("code", { class: "hash", text: session.ua_hash })))),
    el("ol", { class: "timeline" }, records.map((record) => {
      const checked = verified && verified.ok && record.seq <= verified.records;
      const item = recordItem(record);
      return el("li", {},
        el("span", { class: `tl-dot ${record.action.split(".")[0]}` }),
        el("div", { class: "tl-body" },
          el("div", {}, el("b", { text: item.actor.name }), " ", activitySentence(item),
            item.incident ? el("a", { href: `#/incidents/${encodeURIComponent(item.incident.id)}`, class: "mono small", text: ` ${item.incident.id}` }) : null),
          el("div", { class: "tl-meta" }, when(record.at), el("code", { text: `#${number(record.seq)}` }),
            el("code", { class: "hash", title: record.hash, text: short(record.hash, 10) }),
            el("span", { class: `chain small ${checked ? "ok" : "unknown"}`, title: t(checked ? "admin.linkOk" : "admin.linkPending") },
              icon(checked ? "shield check" : "shield"), t(checked ? "admin.linkOkShort" : "admin.linkPendingShort")))));
    })));
}

// Audit log ------------------------------------------------------------------------------

function verifyBanner(result) {
  if (!result) return el("div", { class: "banner unknown" }, icon("shield"), el("span", { text: t("admin.notVerified") }));
  const checkpoint = result.last_checkpoint;
  return el("div", { class: `banner ${result.ok ? "ok" : "bad"}` }, icon(result.ok ? "shield check" : "shield alert"),
    el("div", {},
      el("b", { text: result.ok ? t("admin.verifiedOk", { count: number(result.records) }) : t("admin.verifiedBad", { seq: number(result.first_bad) }) }),
      el("div", { class: "small", text: [result.reason, checkpoint ? t("admin.checkpoint", { seq: number(checkpoint.seq), at: stamp(checkpoint.at) }) : null,
        t("admin.checkedAt", { at: stamp(result.at) })].filter(Boolean).join(" · ") })));
}

async function downloadExport(button) {
  button.disabled = true;
  try {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await fetch("/api/admin/audit/export", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": S.me.csrf } });
      if (response.ok) {
        const blob = await response.blob();
        const name = /filename="([^"]+)"/.exec(response.headers.get("content-disposition") || "")?.[1] || "blacksite-audit.jsonl";
        const link = el("a", { href: URL.createObjectURL(blob), download: name });
        document.body.append(link); link.click(); link.remove();
        toast(t("admin.exported"));
        return;
      }
      const data = await response.json().catch(() => ({}));
      if (response.status === 401 && data.login) { goToLogin(); return; }
      if (response.status === 403 && data.confirm && attempt === 0 && await confirmIdentity()) continue;
      throw new Error(data.error || response.statusText);
    }
  } catch (error) { toast(error.message); } finally { button.disabled = false; }
}

async function auditTab(body) {
  const health = await api("/api/admin/health");
  const users = ADMIN.members.length ? ADMIN.members : (await api("/api/admin/users")).users;
  ADMIN.members = users;
  const filters = ADMIN.audit.filters;
  const actor = el("select", {}, el("option", { value: "", text: t("admin.anyone") }),
    users.map((user) => el("option", { value: `user:${user.id}`, text: user.display_name })),
    ["system", "system:usb", "anonymous"].map((value) => el("option", { value, text: t(`admin.actor.${value.replace(":", "_")}`) })));
  actor.value = filters.actor || "";
  const action = el("select", {}, ["", "auth.", "admin.", "incident.", "usb.", "settings.", "model.", "learning.", "audit."].map((value) =>
    el("option", { value, text: value ? t(`admin.kind.${value.slice(0, -1)}`) : t("admin.anyAction") })));
  action.value = filters.action || "";
  const target = el("input", { placeholder: t("admin.targetPlaceholder"), value: filters.target || "" });
  const since = el("input", { type: "date", value: filters.since || "" });
  const until = el("input", { type: "date", value: filters.until || "" });
  const banner = el("div", {}, verifyBanner(health.last_verification));
  const tbody = el("tbody");
  const more = el("button", { class: "btn small", type: "button", text: t("admin.older"), hidden: true });
  const load = async (reset) => {
    const query = new URLSearchParams({ limit: "100" });
    for (const [key, value] of Object.entries(ADMIN.audit.filters)) {
      if (!value) continue;
      query.set(key, key === "since" ? `${value}T00:00:00Z` : key === "until" ? `${value}T23:59:59Z` : value);
    }
    if (!reset && ADMIN.audit.next) query.set("before", ADMIN.audit.next);
    const data = await api(`/api/admin/audit?${query}`);
    if (reset) tbody.replaceChildren();
    ADMIN.audit.next = data.next;
    more.hidden = !data.next;
    for (const record of data.records) tbody.append(...auditRows(record));
    if (reset && !data.records.length) tbody.append(el("tr", {}, el("td", { colspan: "6", class: "faint", text: t("admin.noRecords") })));
  };
  more.addEventListener("click", () => load(false));
  const verifyButton = el("button", { class: "btn", type: "button", text: t("admin.verifyNow"), onclick: async () => {
    verifyButton.disabled = true;
    try { banner.replaceChildren(verifyBanner(await api("/api/admin/audit/verify", { method: "POST" }))); await load(true); }
    catch (error) { toast(error.message); } finally { verifyButton.disabled = false; }
  } });
  const exportButton = el("button", { class: "btn", type: "button", text: t("admin.export"), onclick: () => downloadExport(exportButton) });
  body.replaceChildren(
    el("div", { class: "toolbar" }, banner, el("span", { class: "spacer" }), verifyButton, exportButton),
    el("form", { class: "filters card pad", onsubmit: async (event) => {
      event.preventDefault();
      ADMIN.audit.filters = { actor: actor.value, action: action.value, target: target.value.trim(), since: since.value, until: until.value };
      await load(true);
    } },
    el("label", { class: "field" }, el("span", { text: t("admin.filter.actor") }), actor),
    el("label", { class: "field" }, el("span", { text: t("admin.filter.action") }), action),
    el("label", { class: "field" }, el("span", { text: t("admin.filter.target") }), target),
    el("label", { class: "field" }, el("span", { text: t("admin.filter.since") }), since),
    el("label", { class: "field" }, el("span", { text: t("admin.filter.until") }), until),
    el("div", { class: "filter-actions" },
      el("button", { class: "btn primary", type: "submit", text: t("admin.apply") }),
      el("button", { class: "btn ghost", type: "button", text: t("admin.clear"), onclick: async () => {
        ADMIN.audit.filters = {}; await renderAdmin("audit");
      } }))),
    el("div", { class: "table-scroll card" }, el("table", { class: "data-table admin-table audit-table" },
      el("thead", {}, el("tr", {}, ["admin.col.seq", "admin.col.time", "admin.col.actor", "admin.col.action", "admin.col.target", "admin.col.detail"]
        .map((key) => el("th", { text: t(key) })))),
      tbody)),
    el("div", { class: "center" }, more),
    el("p", { class: "faint small", text: t("admin.auditHint") }));
  await load(true);
}

function auditRows(record) {
  const detail = JSON.stringify(record.detail);
  const expanded = el("tr", { class: "audit-detail", hidden: true }, el("td", { colspan: "6" },
    el("dl", { class: "kv" },
      el("dt", { text: t("admin.col.detail") }), el("dd", {}, el("pre", { class: "json", text: JSON.stringify(record.detail, null, 2) })),
      el("dt", { text: "hash" }), el("dd", {}, el("code", { class: "hash", text: record.hash })),
      el("dt", { text: "prev" }), el("dd", {}, el("code", { class: "hash", text: record.prev })),
      record.session ? el("dt", { text: t("admin.col.session") }) : null,
      record.session ? el("dd", {}, el("a", { href: `#/admin/sessions/${record.session}`, class: "mono", text: short(record.session, 8) })) : null)));
  const row = el("tr", { class: "audit-row", tabindex: "0", "aria-expanded": "false" },
    el("td", { class: "num mono", text: `#${record.seq}` }),
    el("td", {}, when(record.at)),
    el("td", {}, record.actor_name),
    el("td", {}, el("code", { class: `action ${record.action.split(".")[0]}`, text: record.action })),
    el("td", { class: "mono small", text: record.target_name || record.target || "" }),
    el("td", { class: "mono small detail-cell", text: detail === "{}" ? "" : detail }));
  const toggle = () => { expanded.hidden = !expanded.hidden; row.setAttribute("aria-expanded", String(!expanded.hidden)); };
  row.addEventListener("click", toggle);
  row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); toggle(); } });
  return [row, expanded];
}

// Incidents and access -------------------------------------------------------------------

async function incidentsTab(body) {
  const [{ incidents }, { users }] = await Promise.all([api("/api/admin/incidents"), api("/api/admin/users")]);
  const active = users.filter((user) => user.status === "active");
  const change = async (incident, payload) => {
    try { await api(`/api/admin/incidents/${encodeURIComponent(incident.id)}`, { json: payload }); toast(t("admin.done")); await renderAdmin("incidents"); }
    catch (error) { toast(error.message); }
  };
  const rows = incidents.map((incident) => {
    const owner = el("select", { "aria-label": t("admin.col.owner"), onchange: (event) => change(incident, { owner_id: event.target.value ? Number(event.target.value) : null }) },
      el("option", { value: "", text: t("incident.unassigned") }),
      active.map((user) => el("option", { value: String(user.id), text: user.display_name })));
    owner.value = incident.owner ? String(incident.owner.id) : "";
    const sharedIds = new Set(incident.shares.map((share) => share.id));
    const add = el("select", { "aria-label": t("share.add"), onchange: (event) => { if (event.target.value) change(incident, { share: Number(event.target.value) }); } },
      el("option", { value: "", text: t("admin.addShare") }),
      active.filter((user) => !sharedIds.has(user.id) && user.id !== incident.owner?.id).map((user) => el("option", { value: String(user.id), text: user.display_name })));
    return el("tr", {},
      el("td", {}, el("a", { href: `#/incidents/${encodeURIComponent(incident.id)}`, text: incident.title }),
        el("div", { class: "faint small mono", text: incident.id }), incident.sandbox ? el("span", { class: "badge usb", text: t("usb.badge") }) : null),
      el("td", {}, el("span", { class: "badge", text: t(`incident.status.${incident.status}`) })),
      el("td", {}, when(incident.created_at)),
      el("td", {}, owner),
      el("td", {}, el("div", { class: "chips" }, incident.shares.map((share) => el("span", { class: "chip" }, share.name,
        el("button", { type: "button", "aria-label": t("share.remove"), text: "×", onclick: () => change(incident, { unshare: share.id }) }))), add)));
  });
  body.replaceChildren(
    el("p", { class: "faint", text: t("admin.incidentsIntro") }),
    el("div", { class: "table-scroll card" }, el("table", { class: "data-table admin-table" },
      el("thead", {}, el("tr", {}, ["admin.col.incident", "admin.col.status", "admin.col.created", "admin.col.owner", "admin.col.shared"]
        .map((key) => el("th", { text: t(key) })))),
      el("tbody", {}, rows.length ? rows : el("tr", {}, el("td", { colspan: "5", class: "faint", text: t("side.none") }))))));
}

// Security health ------------------------------------------------------------------------

async function healthTab(body) {
  const health = await api("/api/admin/health");
  const check = (ok, titleKey, detail) => el("div", { class: `health-item ${ok === null ? "unknown" : ok ? "ok" : "bad"}` },
    el("span", { class: "status-mark", "aria-hidden": "true", text: ok === null ? "–" : ok ? "✓" : "!" }),
    el("div", {}, el("b", { text: t(titleKey) }), el("div", { class: "faint small", text: detail })));
  const verification = health.last_verification;
  const anchor = health.anchor;
  body.replaceChildren(
    el("div", { class: "health-grid" },
      el("section", { class: "card pad" }, el("h3", { text: t("health.protection") }),
        check(health.private, "health.private", health.private === null ? t("health.privateWindows") : health.private_paths.join(" · ")),
        check(health.loopback, "health.loopback", t("health.loopbackDetail", { host: health.host })),
        check(health.keys, "health.keys", t("health.keysDetail")),
        totpAvailable()
          ? check(health.admins_without_totp === 0, "health.adminTotp", t("health.adminTotpDetail", { count: health.admins_without_totp, admins: health.admins }))
          : check(null, "account.twoStep", t("account.totpDisabled")),
        check(!health.ledger.broken, "health.ledgerWritable", t("health.ledgerDetail", { count: number(health.ledger.records) }))),
      el("section", { class: "card pad" }, el("h3", { text: t("health.accounts") }),
        el("div", { class: "big-stats" },
          el("div", { class: "big-stat" }, el("b", { text: number(health.members) }), el("span", { text: t("health.members") })),
          el("div", { class: "big-stat" }, el("b", { text: number(health.active_sessions) }), el("span", { text: t("health.sessions") })),
          el("div", { class: `big-stat ${health.failed_24h ? "warn" : ""}` }, el("b", { text: number(health.failed_24h) }), el("span", { text: t("health.failed") })),
          el("div", { class: `big-stat ${health.locked ? "warn" : ""}` }, el("b", { text: number(health.locked) }), el("span", { text: t("health.locked") }))),
        el("p", { class: "faint small", text: t("health.policy", { hours: health.session_hours, minutes: health.idle_minutes }) })),
      el("section", { class: "card pad anchor-card" }, el("h3", { text: t("health.anchor") }),
        anchor ? [el("div", { class: "fingerprint", text: anchor.fingerprint }),
          el("p", { class: "faint small", text: t("health.anchorDetail", { seq: number(anchor.seq), at: stamp(anchor.at) }) }),
          el("p", { class: "small", text: t("health.anchorHint") }),
          el("div", { class: "row-actions" },
            el("button", { class: "btn small primary", type: "button", text: t("health.signNow"), onclick: async () => {
              try { await api("/api/admin/audit/anchor", { method: "POST" }); toast(t("health.signed")); await renderAdmin("health"); }
              catch (error) { toast(error.message); }
            } }),
            el("button", { class: "btn small", type: "button", text: t("copy.button"), onclick: () => copy(`${anchor.fingerprint} (record ${anchor.seq}, ${anchor.at})`) }))]
          : el("p", { class: "faint", text: t("health.noAnchor") })),
      el("section", { class: "card pad" }, el("h3", { text: t("health.signingKey") }),
        el("div", { class: "fingerprint small-print", text: health.signing_key }),
        el("p", { class: "small", text: t("health.signingHint") }),
        el("div", { class: "cmd plain" }, el("pre", { text: "blacksite verify <SOLUTION folder>" })))),
    el("section", { class: "card pad" }, el("h3", { text: t("health.verification") }), verifyBanner(verification),
      el("p", { class: "faint small", text: t("health.verificationHint") })));
}
