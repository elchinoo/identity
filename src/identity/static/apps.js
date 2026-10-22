import { api } from "/kit/api.js";
import { $, h } from "/kit/ui.js";

$("signout").addEventListener("click", async () => {
  try { await api("/logout", { method: "POST" }); } catch { /* cleared anyway */ }
  location.assign("/login");
});
try {
  const d = await api("/api/my-apps");
  $("who").textContent = d.user.name || d.user.username;
  $("apps").replaceChildren(...(d.apps.length ? d.apps.map((a) => h("a", { class: "card app-tile", href: a.url, rel: "noopener" },
    h("h2", {}, a.name), h("p", { class: "muted" }, a.description || ""), h("div", { class: "badges" }, ...a.roles.map((r) => h("span", { class: "badge" }, r)))))
    : [h("p", { class: "empty" }, "You do not have access to any app yet. Ask an administrator.")]));
} catch { location.assign("/login?next=/apps"); }
