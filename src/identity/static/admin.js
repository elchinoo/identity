import { api } from "/kit/api.js";
import { bootSession, renderLogin, renderSetup, renderVaultBanner, state } from "/kit/session.js";
import { initInsights } from "/kit/insights.js";
import { $, confirmDialog, copy, field, fill, fmtDate, h, promptDialog, scrollRegion, toast } from "/kit/ui.js";

const TABS = { overview: "Overview", users: "Users", groups: "Groups", apps: "Apps", federation: "Federation", keys: "Keys", audit: "Audit", insights: "Database", settings: "Settings" };
const VIEWS = { overview, users, groups, apps, federation, keys, audit, insights, settings };
const PRODUCT = "Identity";

function table(heads, rows, empty = "Nothing yet.") {
  return rows.length ? h("div", { class: "card flush" }, h("table", {}, h("thead", {}, h("tr", {}, ...heads.map((t) => h("th", {}, t || h("span", { class: "sr-only" }, "Actions"))))), h("tbody", {}, ...rows)))
    : h("div", { class: "card" }, h("p", { class: "empty" }, empty));
}
const fail = (e) => toast(e.message, true);
const btn = (label, cls, fn) => h("button", { class: `${cls} small`, type: "button", onclick: fn }, label);
const csv = (v) => v.split(",").map((x) => x.trim()).filter(Boolean);

// ---- boot --------------------------------------------------------------------------------------------------
async function boot(notice = "") {
  for (const id of ["auth-card", "nav", "signout", "view", "vault-banner"]) $(id).hidden = true;
  $("auth-card").hidden = false;   // bootSession paints the loading state (and a retry on failure) here
  await bootSession($("auth-card"), { text: "Loading\u2026", onReady: (s) => {
    if (s.state === "setup_required") return renderSetup(() => boot(), PRODUCT);
    if (s.state === "logged_out") return renderLogin(() => boot(), notice, PRODUCT);
    $("auth-card").hidden = true;
    $("nav").replaceChildren(...Object.entries(TABS).map(([k, label]) => h("a", { href: `#${k}`, "data-tab": k }, label)));
    $("nav").hidden = $("signout").hidden = false;
    renderVaultBanner();
    route();
  } });
}

function route() {
  if (!state.session || state.session.state !== "logged_in") return;
  const tab = location.hash.slice(1) in TABS ? location.hash.slice(1) : "overview";
  for (const a of document.querySelectorAll("#nav a")) a.classList.toggle("active", a.dataset.tab === tab);
  $("view").hidden = false;
  VIEWS[tab]().catch(fail);
}
$("signout").addEventListener("click", async () => { try { await api("/api/logout", { method: "POST" }); } catch { /* cleared anyway */ } boot(); });
window.addEventListener("hashchange", route);
window.addEventListener("apg-auth-lost", () => boot("Your session ended. Please sign in again."));
window.addEventListener("apg-unlocked", () => { boot(); });

// ---- views ---------------------------------------------------------------------------------------------------
async function overview() {
  const d = await api("/api/overview");
  const stat = (n, l) => h("div", { class: "stat" }, h("strong", {}, String(n)), h("span", {}, l));
  fill($("view"), h("h1", {}, "Overview"),
    h("div", { class: "stats" }, stat(d.active_users + "/" + d.users, "active users"), stat(d.groups, "groups"), stat(d.apps, "apps"), stat(d.grants, "role grants"), stat(d.live_refresh_tokens, "live refresh tokens")),
    !state.session.signing_key ? h("div", { class: "banner" }, "There is no signing key yet: unlock the vault (sign in with the admin password, or set IDENTITY_ENCRYPTION_KEY) so tokens can be issued.") : null,
    h("div", { class: "card" }, h("h2", {}, "How apps connect"),
      h("p", { class: "muted" }, "Discovery document:"), scrollRegion(h("pre", { class: "code" }, h("code", {}, `${location.origin}/.well-known/openid-configuration`)), "Discovery document URL"),
      h("p", { class: "muted" }, "Register an app under Apps, give people roles in it, and point the app at this issuer. Sign-in for people is at /login; their launcher is /apps.")),
    h("p", { class: "muted" }, `Sign-in providers: ${d.providers.map((p) => p.label).join(", ") || "none (password only)"}.`));
}

async function users() {
  const list = await api("/api/users");
  const form = h("form", { class: "card", onsubmit: async (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(e.target));
    try {
      await api("/api/users", { method: "POST", json: { username: f.username, email: f.email, name: f.name, password: f.password || null, groups: csv(f.groups || "") } });
      toast("User created"); users();
    } catch (err) { fail(err); }
  } },
  h("h2", {}, "Add a person"),
  h("div", { class: "grid3" }, field("Username", h("input", { name: "username", required: true, maxlength: "64" })), field("E-mail", h("input", { name: "email", type: "email", required: true })), field("Name", h("input", { name: "name", maxlength: "120" }))),
  h("div", { class: "grid2" }, field("Password (optional)", h("input", { name: "password", type: "password", autocomplete: "new-password" }), "12+ characters. Leave empty if they will sign in with Google or GitHub."),
    field("Groups (comma separated)", h("input", { name: "groups" }))),
  h("div", { class: "btns" }, h("button", { class: "primary", type: "submit" }, "Add")));
  fill($("view"), h("h1", {}, "Users"), form, table(["Username", "Name", "E-mail", "Groups", "Status", ""], list.map((u) => h("tr", {},
    h("td", { class: "title" }, u.username), h("td", {}, u.name), h("td", {}, u.email), h("td", {}, u.groups.join(", ")),
    h("td", {}, h("span", { class: "badge " + (u.status === "active" ? "ok" : "bad") }, u.status)),
    h("td", { class: "actions" }, h("div", { class: "btns" },
      btn("Roles", "secondary", () => userDetail(u.id)),
      btn(u.status === "active" ? "Disable" : "Enable", "secondary", async () => { try { await api(`/api/users/${u.id}`, { method: "PATCH", json: { status: u.status === "active" ? "disabled" : "active" } }); users(); } catch (e) { fail(e); } }),
      btn("Password", "secondary", async () => { const p = await promptDialog(`New password for ${u.username} (12+ characters)`, { title: "Change password", label: "New password", inputType: "password", required: true, confirmLabel: "Change password", validate: (v) => (v.length < 12 ? "Use at least 12 characters." : null) }); if (p) try { await api(`/api/users/${u.id}/password`, { method: "PUT", json: { password: p } }); toast("Password changed"); } catch (e) { fail(e); } }),
      btn("Delete", "danger", async () => { if (await confirmDialog(`Delete ${u.username}?`, { title: "Delete user", confirmLabel: "Delete", danger: true })) try { await api(`/api/users/${u.id}`, { method: "DELETE" }); users(); } catch (e) { fail(e); } }))))), "No users yet."));
}

async function userDetail(id) {
  const [u, appList] = await Promise.all([api(`/api/users/${id}`), api("/api/apps")]);
  const app = h("select", {}, ...appList.map((a) => h("option", { value: a.client_id }, a.name)));
  const role = h("input", { placeholder: "role name, e.g. approver", maxlength: "40" });
  fill($("view"), h("p", {}, h("a", { href: "#users" }, "← users")), h("h1", {}, u.username),
    h("p", { class: "muted" }, `${u.name} · ${u.email} · groups: ${u.groups.join(", ") || "none"} · federated: ${u.federated.map((f) => f.provider).join(", ") || "no"}`),
    table(["App", "Role", ""], u.grants.map((g) => h("tr", {}, h("td", {}, g.client_id), h("td", {}, g.role), h("td", { class: "actions" }, btn("Remove", "danger", async () => { try { await api(`/api/grants/${g.id}`, { method: "DELETE" }); userDetail(id); } catch (e) { fail(e); } })))), "No direct roles. Groups and app defaults may still grant some."),
    h("div", { class: "card" }, h("h2", {}, "Grant a role"), h("div", { class: "grid3" }, field("App", app), field("Role", role),
      h("div", { class: "btns" }, h("button", { class: "primary", onclick: async () => { try { await api("/api/grants", { method: "POST", json: { subject_type: "user", subject: id, client_id: app.value, role: role.value } }); userDetail(id); } catch (e) { fail(e); } } }, "Grant")))));
}

async function groups() {
  const [list, appList] = await Promise.all([api("/api/groups"), api("/api/apps")]);
  const name = h("input", { maxlength: "63", required: true });
  fill($("view"), h("h1", {}, "Groups"),
    h("form", { class: "card", onsubmit: async (e) => { e.preventDefault(); try { await api("/api/groups", { method: "POST", json: { name: name.value } }); groups(); } catch (err) { fail(err); } } },
      h("div", { class: "grid-inline" }, field("New group", name), h("span"), h("button", { class: "primary", type: "submit" }, "Create"))),
    table(["Group", "Members", "Grant a role to the whole group", ""], list.map((g) => {
      const app = h("select", { "aria-label": `App for group ${g.name}` }, ...appList.map((a) => h("option", { value: a.client_id }, a.name)));
      const role = h("input", { placeholder: "role", maxlength: "40", size: "10", "aria-label": `Role to grant to group ${g.name}` });
      return h("tr", {}, h("td", { class: "title" }, g.name), h("td", {}, String(g.members)),
        h("td", {}, h("div", { class: "btns" }, app, role, btn("Grant", "secondary", async () => { try { await api("/api/grants", { method: "POST", json: { subject_type: "group", subject: g.name, client_id: app.value, role: role.value } }); toast("Granted"); } catch (e) { fail(e); } }))),
        h("td", { class: "actions" }, btn("Delete", "danger", async () => { if (await confirmDialog(`Delete group ${g.name}?`, { title: "Delete group", confirmLabel: "Delete", danger: true })) try { await api(`/api/groups/${g.name}`, { method: "DELETE" }); groups(); } catch (e) { fail(e); } })));
    }), "No groups yet. Add people to groups with the Users tab (comma separated at creation)."));
}

async function apps() {
  const list = await api("/api/apps");
  const f = (n, attrs = {}) => h("input", { name: n, ...attrs });
  const kind = h("select", { name: "kind" }, h("option", { value: "web" }, "web (server-side app with a secret)"), h("option", { value: "public" }, "public (browser/mobile, PKCE only)"), h("option", { value: "service" }, "service (machine to machine)"));
  fill($("view"), h("h1", {}, "Apps"),
    h("form", { class: "card", onsubmit: async (e) => {
      e.preventDefault();
      const d = Object.fromEntries(new FormData(e.target));
      try {
        const r = await api("/api/apps", { method: "POST", json: { client_id: d.client_id, name: d.name, kind: d.kind, url: d.url, redirect_uris: csv(d.redirects), post_logout_uris: csv(d.logout), allowed_scopes: csv(d.scopes), allowed_audiences: csv(d.audiences),
          roles: csv(d.roles).map((n) => ({ name: n, description: "" })), default_roles: csv(d.defaults) } });
        if (r.client_secret) showSecret(d.client_id, r.client_secret); else { toast("App registered"); apps(); }
      } catch (err) { fail(err); }
    } },
    h("h2", {}, "Register an app"),
    h("div", { class: "grid3" }, field("Client id", f("client_id", { required: true, maxlength: "40", placeholder: "trustdesk" }), "Also the role namespace in tokens."), field("Name", f("name", { required: true })), field("Kind", kind)),
    h("div", { class: "grid2" }, field("App URL", f("url", { placeholder: "https://…" })), field("Redirect URIs (comma separated)", f("redirects", { placeholder: "https://app/auth/callback" }), "Exact match. https, or http on localhost.")),
    h("div", { class: "grid3" }, field("Roles it defines", f("roles", { placeholder: "admin, approver, viewer" })), field("Default roles (everyone)", f("defaults")), field("Post-logout URIs", f("logout"))),
    h("div", { class: "grid2" }, field("Allowed scopes", f("scopes", { placeholder: "trustdesk.requests.write" }), "Services only need these."), field("May call (service)", f("audiences", { placeholder: "trustdesk, pagerlens" }))),
    h("div", { class: "btns" }, h("button", { class: "primary", type: "submit" }, "Register"))),
    table(["App", "Kind", "URL", "Roles", "Grants", "Status", ""], list.map((a) => h("tr", {}, h("td", { class: "title" }, a.name, h("div", { class: "muted small-text" }, a.client_id)), h("td", {}, a.kind), h("td", { class: "wrap" }, a.url || ""),
      h("td", {}, String(a.roles)), h("td", {}, String(a.grants)), h("td", {}, h("span", { class: "badge " + (a.status === "active" ? "ok" : "bad") }, a.status)),
      h("td", { class: "actions" }, h("div", { class: "btns" }, a.kind !== "public" ? btn("New secret", "secondary", async () => { if (await confirmDialog("The old secret stops working at once.", { title: "New secret", confirmLabel: "Issue new secret", danger: true })) try { showSecret(a.client_id, (await api(`/api/apps/${a.client_id}/secret`, { method: "POST" })).client_secret); } catch (e) { fail(e); } }) : null,
        btn(a.status === "active" ? "Disable" : "Enable", "secondary", async () => { try { await api(`/api/apps/${a.client_id}`, { method: "PATCH", json: { status: a.status === "active" ? "disabled" : "active" } }); apps(); } catch (e) { fail(e); } }),
        btn("Delete", "danger", async () => { if (await confirmDialog(`Delete ${a.name}? Its grants go too.`, { title: "Delete app", confirmLabel: "Delete", danger: true })) try { await api(`/api/apps/${a.client_id}`, { method: "DELETE" }); apps(); } catch (e) { fail(e); } }))))), "No apps registered yet."));
}

function showSecret(clientId, secret) {
  fill($("view"), h("h1", {}, `Secret for ${clientId}`), h("div", { class: "banner" }, "This is the only time the secret is shown. Put it in the app's environment (or a mounted file), never in a repository."),
    scrollRegion(h("pre", { class: "code secret-box" }, h("code", {}, secret)), "Secret value"), h("div", { class: "btns" }, h("button", { class: "primary", onclick: () => copy(secret) }, "Copy"), h("button", { class: "secondary", onclick: () => { location.hash = "#apps"; apps(); } }, "Done")));
}

async function federation() {
  const d = await api("/api/federation");
  const forms = Object.entries(d.available).map(([id, label]) => {
    const cur = d.providers.find((p) => p.provider === id);
    const cid = h("input", { value: cur?.client_id || "", maxlength: "300" });
    const sec = h("input", { type: "password", autocomplete: "off", placeholder: cur ? "(unchanged)" : "" });
    const mode = h("select", {}, h("option", { value: "invite_only" }, "invite only: the user must exist"), h("option", { value: "open" }, "open: create users for allowed domains"));
    mode.value = cur?.mode || "invite_only";
    const domains = h("input", { value: (cur?.allowed_domains || []).join(", ") });
    const groupsIn = h("input", { value: (cur?.default_groups || []).join(", ") });
    const on = h("input", { type: "checkbox", checked: cur ? cur.enabled : true });
    return h("div", { class: "card" }, h("h2", {}, label), h("p", { class: "muted small-text" }, `Callback URL to register at ${label}: ${location.origin}/login/${id}/callback`),
      h("div", { class: "grid2" }, field("Client id", cid), field("Client secret", sec)),
      h("div", { class: "grid3" }, field("Mode", mode), field("Allowed e-mail domains (open mode)", domains), field("Default groups (open mode)", groupsIn)),
      h("label", { class: "check" }, on, " Enabled"),
      h("div", { class: "btns" }, h("button", { class: "primary", onclick: async () => { try { await api(`/api/federation/${id}`, { method: "PUT", json: { client_id: cid.value, client_secret: sec.value || null, enabled: on.checked, mode: mode.value, allowed_domains: csv(domains.value), default_groups: csv(groupsIn.value) } }); toast("Saved"); federation(); } catch (e) { fail(e); } } }, "Save"),
        cur ? h("button", { class: "danger", onclick: async () => { if (await confirmDialog(`Remove ${label} sign-in and its links?`, { title: "Remove sign-in", confirmLabel: "Remove", danger: true })) { await api(`/api/federation/${id}`, { method: "DELETE" }); federation(); } } }, "Remove") : null));
  });
  fill($("view"), h("h1", {}, "Federation"), h("p", { class: "muted" }, "People can sign in with an account they already have. A verified e-mail address links them to their user here; an unverified one never does."), ...forms);
}

async function keys() {
  const list = await api("/api/keys");
  fill($("view"), h("h1", {}, "Signing keys"), h("p", { class: "muted" }, "Tokens are signed with the active key. After a rotation the old key stays published for 24 hours so tokens already issued still verify."),
    table(["Key id", "Algorithm", "Status", "Created", "Retires"], list.map((k) => h("tr", {}, h("td", {}, h("code", {}, k.kid)), h("td", {}, k.alg), h("td", {}, k.status), h("td", {}, fmtDate(k.created_at)), h("td", {}, k.retire_at ? fmtDate(k.retire_at) : ""))), "No signing key yet: unlock the vault."),
    h("div", { class: "btns" }, h("button", { class: "secondary", onclick: async () => { if (await confirmDialog("Create a new signing key?", { title: "Rotate key", confirmLabel: "Rotate key" })) try { await api("/api/keys/rotate", { method: "POST" }); keys(); } catch (e) { fail(e); } } }, "Rotate key")));
}

async function audit() {
  const rows = await api("/api/audit");
  fill($("view"), h("h1", {}, "Audit"), table(["When", "Who", "What", "Target", "Detail"], rows.map((r) => h("tr", {}, h("td", {}, new Date(r.at).toLocaleString()), h("td", {}, r.actor), h("td", {}, r.action.replaceAll("_", " ")), h("td", {}, r.target), h("td", { class: "wrap muted" }, JSON.stringify(r.detail) === "{}" ? "" : JSON.stringify(r.detail)))), "Nothing yet."));
}

async function insights() {
  await initInsights($("view"), api);          // the kit renders its own h1 ("Query insights")
}

async function settings() {
  const toks = await api("/api/tokens");
  const name = h("input", { maxlength: "60", required: true });
  const scope = h("select", {}, h("option", { value: "read" }, "read (look, never change)"), h("option", { value: "metrics" }, "metrics (scrape /metrics)"), h("option", { value: "full" }, "full access"));
  const cur = h("input", { type: "password", autocomplete: "current-password" });
  const nw = h("input", { type: "password", autocomplete: "new-password" });
  fill($("view"), h("h1", {}, "Settings"),
    h("div", { class: "card" }, h("h2", {}, "Admin password"), h("div", { class: "grid2" }, field("Current", cur), field("New (12+ characters)", nw)),
      h("div", { class: "btns" }, h("button", { class: "primary", onclick: async () => { try { await api("/api/admin-password", { method: "POST", json: { current: cur.value || null, new: nw.value } }); toast("Changed. Signing you out everywhere."); boot(); } catch (e) { fail(e); } } }, "Change password"))),
    h("h2", { class: "section-title" }, "Operator tokens"),
    h("form", { class: "card", onsubmit: async (e) => { e.preventDefault(); try { const t = await api("/api/tokens", { method: "POST", json: { name: name.value, scope: scope.value } }); showSecret("operator token", t.token); } catch (err) { fail(err); } } },
      h("div", { class: "grid-inline" }, field("Name", name), field("Scope", scope), h("button", { class: "primary", type: "submit" }, "Create"))),
    table(["Name", "Prefix", "Scope", "Last used", ""], toks.filter((t) => !t.revoked_at).map((t) => h("tr", {}, h("td", {}, t.name), h("td", {}, h("code", {}, `${t.prefix}…`)), h("td", {}, t.scope), h("td", {}, fmtDate(t.last_used_at)), h("td", { class: "actions" }, btn("Revoke", "danger", async () => { await api(`/api/tokens/${t.id}`, { method: "DELETE" }); settings(); })))), "No tokens."));
}

boot();
