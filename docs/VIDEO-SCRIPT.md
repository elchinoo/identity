# Video script: one sign-in for every app, with Identity

**Title:** One sign-in for every app: a tour of Identity

**Length:** about 6 minutes 20 seconds (about 700 spoken words in a neural voice, written for listening, plus deliberate pauses while something happens on screen). The spoken text lives in `video/narration.txt` and is mirrored in the Narration column below (`video/script_sync.py` keeps them equal). The voice changes with the topic: scenes 1-2, 6-7, 10 `af_bella`; scenes 3-5 `am_eric`; scenes 8-9 `am_michael`.

**Audience:** customers and internal colleagues who have seen, or will see, the other apps of the AgentPG ecosystem. No knowledge of
OAuth or OpenID Connect is assumed; every term is explained the first time it is spoken.

**Goal:** after watching, the viewer can start Identity, register an app, give people roles, see a person sign in to that app and
what the app receives, give a background service its own credentials, and knows what to look after (signing keys, the vault, the audit
trail).

Read [GUIDE.md](GUIDE.md) for the details behind every scene.

---

## Prerequisites and seed data

Everything runs on one laptop, with no live URLs and no cloud account. Total set-up: about five minutes.

**Software:** Python 3.11+, the sibling checkout `../agentpg-kit`, and either Docker or a local Postgres (version 14 or newer, **UTF-8
database**). A Chrome browser (1920 x 1080 for the recording).

**1. Start a throwaway database** (pick one).

```bash
# a) Docker (the repository's Compose file; password is any local value)
printf 'POSTGRES_PASSWORD=local-only\n' > .env
docker compose up -d db
export DATABASE_URL=postgresql://identity:local-only@127.0.0.1:5436/identity

# b) native Postgres, no Docker
initdb -D /tmp/idp-pg -U identity --auth=trust -E UTF8
pg_ctl -D /tmp/idp-pg -o "-p 55436 -k /tmp -c listen_addresses=127.0.0.1" -l /tmp/idp-pg.log start
createdb -h 127.0.0.1 -p 55436 -U identity identity
export DATABASE_URL=postgresql://identity@127.0.0.1:55436/identity
```

**2. Install and start Identity** (no `IDENTITY_API_KEY`, so the first-run setup code is shown on camera).

```bash
uv venv && uv pip install -e ../agentpg-kit -e ".[dev]"
export HOST=127.0.0.1 PORT=8000 IDENTITY_PUBLIC_URL=http://localhost:8000
export IDENTITY_ENCRYPTION_KEY="$(openssl rand -base64 48)"
.venv/bin/identity start 2> /tmp/idp.log          # the setup code is printed to this log
```

Note: with `IDENTITY_ENCRYPTION_KEY` set and no admin yet, Identity creates the vault and the first signing key at start-up (so
`/readyz` is already `ready`); the admin password is still chosen in scene 2 and the setup code is still required.

**3. Two helper files** (save them in a scratch folder such as `/tmp/tutorial/`; they are not part of the repository).

`seed.py` creates one group and three people after the admin password exists:

```python
"""Seed for the tutorial recording. Usage: IDP=http://localhost:8000 IDP_ADMIN_PASSWORD=... python seed.py"""
import os
import sys

import httpx

IDP = os.environ.get("IDP", "http://localhost:8000").rstrip("/")
c = httpx.Client(base_url=IDP, headers={"X-Identity-CSRF": "1"}, timeout=20)
c.post("/api/login", json={"password": os.environ["IDP_ADMIN_PASSWORD"]}).raise_for_status()

def post(path, body):
    r = c.post(path, json=body)
    if r.status_code not in (200, 201, 422):          # 422: already exists, fine on a second run
        sys.exit(f"{path}: {r.status_code} {r.text}")
    print(path, r.status_code)

post("/api/groups", {"name": "writers", "description": "People who edit notes"})
post("/api/users", {"username": "ada", "email": "ada@example.org", "name": "Ada Lovelace", "password": "analytical engine 1843", "groups": ["writers"]})
post("/api/users", {"username": "grace", "email": "grace@example.org", "name": "Grace Hopper", "password": "nanosecond wire 1947"})
post("/api/users", {"username": "alan", "email": "alan@example.org", "name": "Alan Turing", "password": "imitation game 1950"})
```

`demo_rp.py` is "Notes", a 70-line app that signs people in through Identity. It needs only what the Identity virtualenv already has:

```python
"""A relying party for the tutorial: "Notes" signs people in through Identity (code flow + PKCE).
Run: IDP=http://localhost:8000 NOTES_SECRET=cs_... python demo_rp.py"""
import base64
import hashlib
import html
import json
import os
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from apgkit.auth.oidc import TokenError, TokenVerifier

IDP = os.environ.get("IDP", "http://localhost:8000").rstrip("/")
BASE = "http://localhost:9000"
CLIENT_ID, SECRET = "notes", os.environ["NOTES_SECRET"]
verifier = TokenVerifier(IDP, CLIENT_ID)          # checks signature (via /jwks.json), issuer, audience, expiry
conf = httpx.get(f"{IDP}/.well-known/openid-configuration").json()
PENDING, SESSIONS = {}, {}                        # state -> (pkce verifier, nonce); cookie -> claims


class H(BaseHTTPRequestHandler):
    def send(self, body, status=200, headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def redirect(self, url, *headers):
        self.send("", 302, [("Location", url), *headers])

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        sid = SimpleCookie(self.headers.get("Cookie", "")).get("notes")
        me = SESSIONS.get(sid.value) if sid else None
        if u.path == "/login":
            state, nonce, ver = secrets.token_urlsafe(16), secrets.token_urlsafe(16), secrets.token_urlsafe(48)
            PENDING[state] = (ver, nonce)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
            self.redirect(conf["authorization_endpoint"] + "?" + urlencode({
                "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": f"{BASE}/callback", "scope": "openid profile email roles",
                "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}))
        elif u.path == "/callback":
            ver, nonce = PENDING.pop(q.get("state", ""), (None, None))
            if not ver or "code" not in q:
                return self.send("Sign-in failed: " + html.escape(q.get("error", "unknown state")), 400)
            r = httpx.post(conf["token_endpoint"], auth=(CLIENT_ID, SECRET), data={
                "grant_type": "authorization_code", "code": q["code"], "redirect_uri": f"{BASE}/callback", "code_verifier": ver})
            if r.status_code != 200:
                return self.send("Token endpoint said: " + html.escape(r.text), 400)
            try:
                claims = verifier.verify(r.json()["id_token"])
            except TokenError as exc:
                return self.send("Bad ID token: " + html.escape(str(exc)), 400)
            if claims.get("nonce") != nonce:
                return self.send("Wrong nonce", 400)
            cookie = secrets.token_urlsafe(24)
            SESSIONS[cookie] = claims
            self.redirect("/", ("Set-Cookie", f"notes={cookie}; HttpOnly; Path=/; SameSite=Lax"))
        elif u.path == "/logout":
            if sid:
                SESSIONS.pop(sid.value, None)
            self.redirect(conf["end_session_endpoint"] + "?" + urlencode({"client_id": CLIENT_ID, "post_logout_redirect_uri": f"{BASE}/"}))
        elif me:
            can_edit = f"{CLIENT_ID}:editor" in me.get("roles", [])
            self.send(f"<h1>Notes</h1><p>Signed in as <b>{html.escape(me.get('name', ''))}</b> ({html.escape(me.get('email', ''))})</p>"
                      f"<p>Roles in this app: <b>{html.escape(', '.join(me.get('roles', [])) or 'none')}</b></p>"
                      f"<p>{'You can edit notes.' if can_edit else 'Read only.'}</p><pre>{html.escape(json.dumps(me, indent=2))}</pre>"
                      "<p><a href='/logout'>Sign out</a></p>")
        else:
            self.send("<h1>Notes</h1><p>Not signed in.</p><p><a href='/login'>Sign in with Identity</a></p>")

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", 9000), H).serve_forever()
```

The flow this file implements (a sign-in, a token exchange and an ID-token check, with a `notes` client registered as in scene 4,
roles `editor` and `reader`, `editor` granted to the group `writers`) was run end to end against a local Identity while preparing this
script: Ada, who is in `writers`, got `notes:editor` and `notes:reader`; Grace got only `notes:reader`.

**4. Order of recording.** Record scene 2 first (it needs the setup code), then run the seed (scene 3 shows its result), then the rest.

| Seed item | Value |
|---|---|
| Admin password (chosen in scene 2) | `tutorial admin pass 2026` |
| People | `ada` (group `writers`), `grace`, `alan` with the passwords in `seed.py` |
| Group | `writers` |
| Created live on camera | app `notes` (scene 4), role grants (scene 5), service app `notes-worker` (scene 8) |

Reset between takes: drop and recreate the `identity` database (or `docker compose down -v`), restart Identity.

---

## Scenes

Timestamps are cumulative. "Callout" is a text overlay added in editing (or a highlight box drawn by the recording tool).

| # | Time | On-screen action | Narration | Callouts |
|---|---|---|---|---|
| 1 | 0:00 - 0:35 | Title card, then the browser at `http://localhost:8000/login` (the plain sign-in page). | Every app you build has to answer two questions. Who is this person? And what may they do here? Without a shared answer, every app keeps its own list of users and passwords. Identity is the one place that answers for the whole ecosystem. People sign in once. Each app lists its roles. Administrators decide who holds them. In this video we will set it up, connect an app, and see what the app receives. | "Who is this person?" then "What may they do here?" |
| 2 | 0:35 - 1:15 | Terminal: run `.venv/bin/identity start 2> /tmp/idp.log` (already done off camera: show `grep -A1 "one-time code" /tmp/idp.log`). Switch to the browser, open `http://localhost:8000/admin`. Click the **Setup code** field, paste the code, type the admin password twice, click **Create admin password**. | Identity is one small service, with a Postgres database behind it. On first start, it prints a one-time setup code in its log. Only whoever runs the server can read it. Now the admin page. We paste the code, and choose an administrator password. That password also protects the vault, an encrypted store for secrets, such as signing keys. It needs at least twelve characters. | Highlight the code in the log. "Setup code = proof you operate the server" |
| 3 | 1:15 - 1:55 | Terminal: `IDP=http://localhost:8000 IDP_ADMIN_PASSWORD='tutorial admin pass 2026' .venv/bin/python /tmp/tutorial/seed.py`. Browser: the console opens on **Overview**; click **Users**, then **Groups**. | Next, some sample data. A small script adds three people and one group. Back in the console, the overview counts people, groups and apps. Here are the people: Ada, Grace and Alan. A group is a named set of people. We have one, called writers, with Ada in it. | Point at the stats row; at "writers: 1 member". |
| 4 | 1:55 - 2:55 | Click **Apps**. In **Register an app** fill: Client id `notes`, Name `Notes`, Kind `web`, App URL `http://localhost:9000`, Redirect URIs `http://localhost:9000/callback`, Roles `editor, reader`, Default roles `reader`, Post-logout URIs `http://localhost:9000/`. Click **Register**. The secret screen appears: click **Copy**. In the terminal: `export NOTES_SECRET=<paste>` then `IDP=http://localhost:8000 .venv/bin/python /tmp/tutorial/demo_rp.py &`. Click **Done**. | Now we register an app, a small notes application. Its client id is notes. That is also the name its roles live under. The kind is web: a server-side app that can keep a secret. The redirect address is exact. Identity only sends people back to precisely this address. We define two roles, editor and reader. Reader is the default, so everyone can at least read. Now Identity shows the app's secret, once. If it is lost, you issue a new one. We copy it, and start the app with that secret. The app is running. | Highlight "Redirect URIs: exact match". Banner: "Secret shown once". |
| 5 | 2:55 - 3:25 | Click **Groups**. On the row `writers`: choose app `Notes` in the select, type `editor` in the role box, click **Grant** (toast "Granted"). Click **Users**, click **Roles** on `grace` to show "No direct roles" and the empty table, then back. | Now, the access. On the writers group, we grant the editor role in Notes. Everyone in writers now holds it. Next, Grace. She is not in writers, and has no direct grant. So she will only hold the default role: reader. Roles always belong to one app. Editor in Notes says nothing about any other app. | Overlay: "writers -> notes:editor"; "Grace -> notes:reader (default)". |
| 6 | 3:25 - 4:25 | New browser window at `http://localhost:9000`. Click **Sign in with Identity**. The browser lands on Identity's sign-in page: username `grace`, password `nanosecond wire 1947`, **Sign in**. The Notes page shows "Roles in this app: notes:reader" and "Read only." Click **Sign out** (Identity ends its session and returns the browser to Notes, which shows "Not signed in."). Click **Sign in with Identity** again and sign in as `ada` (`analytical engine 1843`): "notes:editor, notes:reader", "You can edit notes." Then open `http://localhost:8000/apps` to show the launcher tile for Notes with the role badges. | Now the sign-in flow, the part people see. The app sends the browser to Identity. Grace signs in there, on Identity's own page. So the app never sees her password. Identity sends her back with a one-time code. The app swaps it for tokens, using its secret and a random check value called PKCE. Notes now knows her name and her roles. She is a reader, so the page says read only. Now she signs out. That ends her session at Identity too. Now Ada signs in. Ada holds the editor role, so she can edit notes. Identity also has a launcher page. It lists every app a person may open, with their roles. | Sequence overlay: "App -> Identity -> sign in -> code -> tokens". Highlight the roles line. |
| 7 | 4:25 - 5:05 | In the browser, back on the Notes page, scroll to the `<pre>` block (the claims of the ID token the app received). Then in the browser open `http://localhost:8000/.well-known/openid-configuration` and `http://localhost:8000/jwks.json`. | Back on the Notes page, this box shows what the app received. These are the claims of Ada's ID token. The app did not call Identity to ask who she is. The token is signed, and the app checks that signature. It checks the issuer, which is Identity. And the audience, which is this app and no other. The roles inside are only the ones for Notes. The signature check uses Identity's public keys. The app finds them through the discovery document. That document lists every address an app needs. The keys are published here. So connecting an app takes just three settings. Where Identity is. The client id. And the secret. | Highlight `"aud": ["notes"]`, `"roles"`, `"iss"`. |
| 8 | 5:05 - 5:45 | Console **Apps**: register `notes-worker`, Kind `service`, Allowed scopes `notes.write`, May call `notes`; **Register**, copy the secret. Terminal: `export SECRET=<paste>` then `curl -s -u notes-worker:"$SECRET" -d grant_type=client_credentials -d scope=notes.write http://localhost:8000/oauth/token \| python3 -c "import sys,json,base64;t=json.load(sys.stdin)['access_token'].split('.')[1];print(json.dumps(json.loads(base64.urlsafe_b64decode(t+'='*(-len(t)%4))),indent=2))"`. Then repeat with `-d scope=notes.read` to show `invalid_scope`. | Now, services. They need to sign in too, with no person involved. We register a service, a background worker, and say exactly what it may ask for. The scope notes.write, for the notes app only. It gets its own secret. We copy it. Now the worker asks for a token. The subject is the worker, marked as a service. The audience is notes. The scope is notes.write. Now it asks for a scope it was never given. Identity refuses: invalid scope. This replaces copying one shared password around. Tokens last ten minutes. | Highlight `"sub_type": "service"`, `"aud": "notes"`. Then the error `invalid_scope`. |
| 9 | 5:45 - 6:15 | Console **Users**: click **Disable** on `alan` (toast). In a private window try to sign in at `http://localhost:8000/login` as `alan`: error "that username or password is not right". Console **Keys**: show the active key, click **Rotate key**, confirm in the dialog (there is no toast: the table gains the new key and the old one turns `retiring`). Console **Audit**: show the latest rows (`user_updated`, `signing_key_rotated`, `app_registered`). | Day to day, three things matter. First, people. We disable Alan. Now he cannot sign in. His long-lived sessions end at once, and tokens he already holds expire within ten minutes. Second, the signing keys. Here is the active one. We rotate it. The new key is active. The old one is retiring, and stays published for twenty-four hours. Nothing breaks mid-flight. Third, the audit page. It records who changed what, in the same step as the change. | Highlight the `retiring` row and its "Retires" date (24 hours after the rotation) in Keys; the Audit rows. |
| 10 | 6:15 - 6:40 | Back on the Identity Overview page, then the title card with the repository and documentation addresses. | To recap what we covered. Sign in once. Roles per app. Exact redirect addresses. Signed tokens that apps check on their own. And service credentials with narrow scopes. Everything you saw is in the guide, in the docs folder. Clone the repository, start it on a throwaway database, and register your own first app. Thanks for watching. | End card: "docs/GUIDE.md" and "Next: register your own app". |

Narration length: about 800 words. If the take runs long, trim the narration of scene 7 first and keep the screen action.

---

## Recording notes

### Pre-flight checks

* `curl -s localhost:8000/healthz` returns `{"status":"ok",...}`; `curl -s localhost:8000/readyz` returns `{"status":"ready"}`.
* Port 9000 is free for Notes; port 8000 for Identity.
* The clock is the real clock: key creation times are shown in the Keys and Audit tables.
* Never show the real `IDENTITY_ENCRYPTION_KEY`; it is generated fresh for the recording and discarded.

### The Playwright recorder

`docs/video/record.spec.ts` performs scenes 1 to 10 in a real Chrome with Playwright video at 1920 x 1080 (rehearsed end to end on a
throwaway local database; every assertion in it passes against the current code). It starts Identity itself, takes `seed.py` and
`demo_rp.py` from the code blocks above, types with a human delay, draws the callouts of the table (a text banner at the bottom and an
orange box around the thing being talked about) and writes to `docs/video/out/` (git-ignored): `videos/console.webm`,
`videos/notes.webm`, `videos/private.webm`, `videos/terminal.webm`, `timeline.json` (when each scene starts and ends, in seconds since the
recorder started), `scene-NN.png` (one screenshot per scene) and `idp.log`.

```bash
# a throwaway UTF-8 Postgres, database name ending in "test" (the recorder drops and recreates its public schema)
initdb -D /tmp/idp-pg -U identity --auth=trust -E UTF8
pg_ctl -D /tmp/idp-pg -o "-p 55436 -c listen_addresses=127.0.0.1 -c unix_socket_directories=''" -l /tmp/idp-pg.log start
createdb -h 127.0.0.1 -p 55436 -U identity identity_test
cd docs/video && npm install && npx playwright install ffmpeg      # ffmpeg is what Playwright encodes video with
VIDEO_DATABASE_URL=postgresql://identity@127.0.0.1:55436/identity_test npx playwright test
```

Options: `VIDEO_PACE=0.2` shortens every pause for a rehearsal (1 follows the scene lengths above, about 6 minutes 40 seconds), `HEADED=1`
shows the window, `IDP_PORT` / `NOTES_PORT` replace 8000 / 9000 when something else holds them (the on-screen URLs then show the new ports,
so record with the defaults). The run fails if a port is busy, if the database name does not end in `test`, or if any browser response
is a 4xx or 5xx other than Alan's refused sign-in.

What the rehearsal showed, and the recorder does accordingly:

* Playwright cannot film a terminal. The recorder draws the real command and its real output (the setup code from the log, the seed
  output, the decoded service token, the `invalid_scope` error) on a dark page and records that, in its own video (`terminal.webm`).
  Secrets typed into the terminal in the script are shown as `cs_...` there.
* There are four videos, one per browser context (the console, the terminal page, the private window, Notes and the launcher). They all
  start within a second of each other; cut between them using `timeline.json`.
* Rotating the key: the page button `Rotate key` opens a native `<dialog>` (the kit's `confirmDialog`) with the buttons Cancel and
  `Rotate key`; click the one inside `dialog[open]`. There is no toast. Success is the keys table going from one row to two.
* The toast `Granted` (scene 5) and `Copied` (scene 4, after **Copy**) exist. **Copy** needs clipboard permission: the recorder grants
  it to its contexts, otherwise the toast says `Copy failed` (the secret is still on screen).
* The ID token the app shows also has `at_hash`, `nonce`, `auth_time`, `preferred_username` and `iat` besides the claims the narration
  names; `aud` is a one-element list.
* Identity's pages have a strict CSP, so the callouts are drawn with element style properties only (no injected style sheet); nothing
  bypasses the CSP.

Selectors verified against `static/admin.js`, `static/login.html` and the kit's `ui.js` (the same ones the recorder uses):
`#setup-code`, `#setup-pw`, `#setup-pw2`, `#nav a[data-tab=...]`, `input[name=client_id|name|url|redirects|roles|defaults|logout|scopes|audiences]`,
`select[name=kind]`, `pre.secret-box code`, `select[aria-label='App for group writers']`, `input[aria-label='Role to grant to group writers']`,
`#toast`, `#username`, `#password`, `#error`, `.app-tile`, `dialog[open]`.

Rules for any run: never use `page.on("dialog")` handlers expecting `window.confirm` (the console does not use native dialogs); wait for
`#toast` or the changed table rather than fixed sleeps, except where the narration needs a pause.

### Editing

* Add the callouts listed per scene as text overlays; keep them on screen for about three seconds.
* Blur nothing: the only secrets visible are throwaway values created for the recording. Still, rotate the secret of `notes` and delete
  the database after publishing.
* Captions: export the narration column as the subtitle track.
* Add the link to `docs/GUIDE.md` in the video description.
