import { api } from "/kit/api.js";
import { $, h } from "/kit/ui.js";

const params = new URLSearchParams(location.search);
const next = params.get("next") || "/apps";
$("error").textContent = params.get("error") || "";
$("message").textContent = params.get("message") || "";

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("error").textContent = "";
  const password = $("password").value;
  $("password").value = "";
  try {
    const r = await api("/login", { method: "POST", json: { username: $("username").value, password, next } });
    location.assign(r.next);
  } catch (err) { $("error").textContent = err.message; }
});

try {
  const opts = await api("/api/login-options");
  $("providers").replaceChildren(...opts.providers.map((p) => h("a", { class: "button secondary", href: `/login/${p.provider}?next=${encodeURIComponent(next)}` }, `Continue with ${p.label}`)));
} catch { /* the password form still works */ }
