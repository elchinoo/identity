/**
 * Plays docs/VIDEO-SCRIPT.md: the on-screen actions of scenes 1 to 10, in a real Chrome, with Playwright video on (1920x1080).
 *
 * Needs (all local, nothing live):
 *   - a throwaway UTF-8 Postgres whose database name ends in `test`, on 127.0.0.1, and VIDEO_DATABASE_URL pointing at it.
 *     The recorder DROPS AND RECREATES the public schema of that database before it starts.
 *   - the repository's .venv (identity + the sibling kit installed), and free ports 8000 (Identity) and 9000 (Notes) (IDP_PORT / NOTES_PORT override them).
 *
 *   cd docs/video && npm install && VIDEO_DATABASE_URL=postgresql://identity@127.0.0.1:55436/identity_test npx playwright test
 *
 * It starts Identity itself, extracts seed.py and demo_rp.py from the script's code blocks (so the script stays the single
 * source), and writes to ./out (git-ignored): videos/<role>.webm (console, notes, private, terminal), timeline.json (when each
 * scene starts, per video), scene-NN.png (one screenshot per scene), idp.log. Pauses follow the script's scene lengths; scale them
 * with VIDEO_PACE (0.2 for a quick rehearsal). The terminal cannot be filmed by Playwright, so terminal scenes are drawn on a page
 * that shows the real command and its real output.
 */
import { ChildProcess, execFileSync, spawn } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { Browser, BrowserContext, Page, expect, test } from '@playwright/test';

const HERE = __dirname;
const REPO = path.resolve(HERE, '..', '..');
const OUT = path.join(HERE, 'out');
const TUTORIAL = path.join(OUT, 'tutorial');
const VENV = path.join(REPO, '.venv', 'bin');
const PACE = Number(process.env.VIDEO_PACE ?? 1);
const IDP_PORT = Number(process.env.IDP_PORT ?? 8000);        // the script uses 8000 and 9000; override only if something else holds them
const NOTES_PORT = Number(process.env.NOTES_PORT ?? 9000);
const IDP = `http://localhost:${IDP_PORT}`;
const NOTES = `http://localhost:${NOTES_PORT}`;
const ADMIN_PW = 'tutorial admin pass 2026';
const SIZE = { width: 1920, height: 1080 };
// Review cut: build.sh passes narration.json (VIDEO_NARRATION: {id: {duration, cues:[{text,start,end}]}}, from the neural voice). A scene lasts
// audio + 0.7 s unless its actions take longer, and each action waits for the sentence it illustrates (`at`), so the screen follows the narration.
const NARRATION: Record<string, { duration: number; cues: { text: string; start: number; end: number }[] }> = process.env.VIDEO_NARRATION ? JSON.parse(fs.readFileSync(process.env.VIDEO_NARRATION, 'utf8')) : {};
let cues: { text: string; start: number; end: number }[] = [];
let sceneStart = 0;
/** Wait until the narration sentence starting with `prefix` is about to be spoken (`lead` seconds early), so the action shows what the voice says. */
async function at(prefix: string, lead = 0.2) {
  const cue = cues.find((c) => c.text.startsWith(prefix));
  if (!cue) { if (process.env.VIDEO_NARRATION) throw new Error(`no narration sentence starting with "${prefix}"`); return; }
  const wait = (cue.start - lead) * PACE * 1000 - (Date.now() - sceneStart);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
}
const TYPE_DELAY = Math.round(60 * PACE);

// ---- the overlay: a text banner and a pulsing box around what the narration talks about --------------------------
// Built with element.style assignments only, so it works under Identity's strict CSP (no inline style, no bypassCSP).
const OVERLAY = `(() => {
  if (window.__ov) return;
  const mk = (css) => { const d = document.createElement('div'); Object.assign(d.style, css); d.setAttribute('data-callout', ''); document.documentElement.append(d); return d; };
  const drop = (el, ms) => setTimeout(() => el.remove(), ms);
  // Playwright writes video frames only while the page changes, which compresses still pages in time: keep every page "changing" with a
  // 6px dot (body colour +-2 on one channel, invisible) so each video runs on the wall clock and cutting by timeline.json is exact.
  let dot = null, flip = 0;
  setInterval(() => {
    if (!document.documentElement) return;
    if (!dot || !dot.isConnected) dot = mk({ position: 'fixed', right: '0', bottom: '0', width: '6px', height: '6px', zIndex: 2147483645, pointerEvents: 'none' });
    const m = /rgba?\\((\\d+), (\\d+), (\\d+)(?:, ([\\d.]+))?/.exec(getComputedStyle(document.body || document.documentElement).backgroundColor);
    const c = m && (m[4] === undefined || Number(m[4]) > 0) ? [Number(m[1]), Number(m[2]), Number(m[3])] : [255, 255, 255];
    flip ^= 1;
    dot.style.background = 'rgb(' + c[0] + ', ' + c[1] + ', ' + (c[2] - (c[2] > 2 ? 2 * flip : -2 * flip)) + ')';
  }, 100);
  window.__ov = {
    banner(text, ms) {
      const d = mk({ position: 'fixed', left: '50%', bottom: '56px', transform: 'translateX(-50%)', zIndex: 2147483647, background: 'rgba(17,24,39,0.94)', color: '#fff',
        font: '600 38px/1.3 system-ui, sans-serif', padding: '18px 34px', borderRadius: '16px', boxShadow: '0 8px 30px rgba(0,0,0,.45)', maxWidth: '1500px', textAlign: 'center', pointerEvents: 'none' });
      d.textContent = text; drop(d, ms);
    },
    box(rect, ms) {
      const d = mk({ position: 'fixed', left: rect.x - 10 + 'px', top: rect.y - 8 + 'px', width: rect.width + 20 + 'px', height: rect.height + 16 + 'px', zIndex: 2147483646,
        border: '5px solid #ff9f1c', borderRadius: '12px', boxShadow: '0 0 0 9999px rgba(0,0,0,.18), 0 0 24px 6px rgba(255,159,28,.8)', pointerEvents: 'none' });
      drop(d, ms);
    },
    text(needle, ms) {                                 // box around the first visible occurrence of a string
      const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let n = w.nextNode(); n; n = w.nextNode()) {
        const i = n.nodeValue.indexOf(needle);
        if (i < 0) continue;
        const r = document.createRange(); r.setStart(n, i); r.setEnd(n, i + needle.length);
        const b = r.getBoundingClientRect();
        if (b.width) { this.box(b, ms); return true; }
      }
      return false;
    },
  };
})()`;

async function install(page: Page) {
  await page.context().addInitScript(OVERLAY);
  await page.evaluate(OVERLAY);
}
const banner = (page: Page, text: string, ms = 3500) => page.evaluate(([t, m]) => (window as any).__ov.banner(t, m), [text, ms * PACE > 1200 ? ms * PACE : 1200] as const);
async function mark(page: Page, target: string | ReturnType<Page['locator']>, ms = 3500) {
  const dur = Math.max(1200, ms * PACE);
  if (typeof target === 'string') {
    const ok = await page.evaluate(([t, m]) => (window as any).__ov.text(t, m), [target, dur] as const);
    expect(ok, `text to highlight not found: ${target}`).toBeTruthy();
  } else {
    await target.first().scrollIntoViewIfNeeded();
    const b = (await target.first().boundingBox())!;
    await page.evaluate(([r, m]) => (window as any).__ov.box(r, m), [b, dur] as const);
  }
}
const hold = (page: Page, ms: number) => page.waitForTimeout(Math.round(ms * PACE));
async function typeInto(page: Page, sel: string, text: string) {
  const l = page.locator(sel);
  await l.click();
  await l.pressSequentially(text, { delay: TYPE_DELAY });
}

// ---- the "terminal": Playwright cannot film one, so draw the real command and its real output on a page -----------
const TERM_HTML = `<!doctype html><meta charset=utf-8><body style="margin:0;background:#0d1117;color:#e6edf3;font:30px/1.45 ui-monospace,Menlo,monospace">
<div id=t style="padding:40px 56px;white-space:pre-wrap;word-break:break-all"></div>`;
async function term(page: Page, cmd: string, output: string) {
  cmd = cmd.replaceAll('http://localhost:8000', IDP);       // the drawn command shows the port actually used
  await page.evaluate(async ([c, o, delay]) => {
    const t = document.getElementById('t')!;
    const line = document.createElement('div');
    t.append(line, document.createElement('br'));
    const prompt = document.createElement('span'); prompt.textContent = '$ '; prompt.style.color = '#7ee787'; line.append(prompt);
    const typed = document.createElement('span'); line.append(typed);
    for (const ch of c) { typed.textContent += ch; await new Promise((r) => setTimeout(r, delay)); }
    await new Promise((r) => setTimeout(r, 300));
    const out = document.createElement('div'); out.textContent = o; out.style.color = '#c9d1d9'; line.after(out);
    window.scrollTo(0, document.body.scrollHeight);
  }, [cmd, output.trimEnd(), Math.max(8, Math.round(25 * PACE))] as const);
}

const CARD = (title: string, sub: string) => `<!doctype html><meta charset=utf-8><body style="margin:0;height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;background-color:#1e3a8a;background-image:linear-gradient(135deg,#0f172a,#1e3a8a);color:#fff;font-family:system-ui,sans-serif;text-align:center">
<div style="font-size:92px;font-weight:700;max-width:1500px;line-height:1.15">${title}</div><div style="font-size:48px;margin-top:36px;color:#bfdbfe">${sub}</div>`;

const showHtml = (page: Page, html: string) => page.goto('data:text/html;charset=utf-8,' + encodeURIComponent(html));

// ---- processes -------------------------------------------------------------------------------------------------------------------
const procs: ChildProcess[] = [];
function startProc(cmd: string, args: string[], env: Record<string, string>, logFile: string): ChildProcess {
  const fd = fs.openSync(logFile, 'a');
  const p = spawn(cmd, args, { env: { ...cleanEnv(), ...env }, cwd: REPO, stdio: ['ignore', fd, fd] });
  procs.push(p);
  return p;
}
const cleanEnv = (): Record<string, string> => ({ PATH: '/usr/bin:/bin', HOME: OUT, LANG: 'en_US.UTF-8', PYTHONUNBUFFERED: '1', PYTHONDONTWRITEBYTECODE: '1', NO_COLOR: '1' });
function run(cmd: string, args: string[], env: Record<string, string> = {}): string {
  return execFileSync(cmd, args, { env: { ...cleanEnv(), ...env }, cwd: REPO, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}
const isBusy = (port: number) => new Promise<boolean>((res) => {
  const s = net.connect(port, '127.0.0.1');
  s.once('connect', () => { s.destroy(); res(true); });
  s.once('error', () => res(false));
});
async function waitUntil(fn: () => Promise<boolean> | boolean, what: string, ms = 30_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return; await new Promise((r) => setTimeout(r, 250)); }
  throw new Error(`timed out waiting for ${what}`);
}
/** The code blocks of the script, by the first words of their docstring: the script stays the single source of seed.py and demo_rp.py. */
function scriptBlock(startsWith: string): string {
  const md = fs.readFileSync(path.join(HERE, '..', 'VIDEO-SCRIPT.md'), 'utf8');
  const block = [...md.matchAll(/```python\n([\s\S]*?)```/g)].map((m) => m[1]).find((b) => b.startsWith(startsWith));
  if (!block) throw new Error(`no python block starting with ${startsWith} in VIDEO-SCRIPT.md`);
  return block;
}

// ---- the run -------------------------------------------------------------------------------------------------------------------------
const bad: string[] = [];                                    // unexpected 4xx/5xx seen by any browser page
const timeline: { scene: number; title: string; video: Record<string, number>; cuts: { role: string; at_s: number }[] }[] = [];
const offsets: Record<string, number> = {};            // when each video started, in seconds since the recorder started   // seconds since the recorder started
const t0 = Date.now();
const nowS = () => Math.round((Date.now() - t0) / 100) / 10;

function watch(page: Page, allow: RegExp[] = []) {
  page.on('response', (r) => {
    const line = `${r.status()} ${r.request().method()} ${r.url()}`;
    if (r.status() >= 400 && !allow.some((a) => a.test(line))) bad.push(line);
  });
}
async function context(browser: Browser, role: string, allow: RegExp[] = []) {
  const ctx = await browser.newContext({
    viewport: SIZE, deviceScaleFactor: 1, recordVideo: { dir: path.join(OUT, 'videos', role), size: SIZE },
    permissions: ['clipboard-read', 'clipboard-write'], locale: 'en-US', colorScheme: 'light',
  });
  const page = await ctx.newPage();
  watch(page, allow);
  await install(page);
  offsets[role] = nowS();
  return { ctx, page };
}

test.describe.configure({ mode: 'serial' });

test('record docs/VIDEO-SCRIPT.md', async ({ browser }) => {
  const dsn = process.env.VIDEO_DATABASE_URL ?? '';
  const dbName = (/\/([^/?]+)(\?|$)/.exec(dsn) ?? [])[1] ?? '';
  const hostOk = /@(127\.0\.0\.1|localhost)(:\d+)?\//.test(dsn);
  if (!dsn || !dbName.endsWith('test') || !hostOk) {
    throw new Error('set VIDEO_DATABASE_URL to a throwaway database on 127.0.0.1 whose name ends in "test" (its public schema is dropped)');
  }
  for (const port of [IDP_PORT, NOTES_PORT]) if (await isBusy(port)) throw new Error(`port ${port} is in use; the script needs it`);
  for (const f of fs.existsSync(OUT) ? fs.readdirSync(OUT) : []) if (f !== 'narration' && f !== 'final') fs.rmSync(path.join(OUT, f), { recursive: true, force: true });   // keep build.sh's narration
  fs.mkdirSync(TUTORIAL, { recursive: true });
  fs.writeFileSync(path.join(TUTORIAL, 'seed.py'), scriptBlock('"""Seed for the tutorial'));
  fs.writeFileSync(path.join(TUTORIAL, 'demo_rp.py'), scriptBlock('"""A relying party').replaceAll('localhost:9000', `localhost:${NOTES_PORT}`).replace('("127.0.0.1", 9000)', `("127.0.0.1", ${NOTES_PORT})`));
  const py = path.join(VENV, 'python');
  const log = path.join(OUT, 'idp.log');
  const idpEnv = { DATABASE_URL: dsn, HOST: '127.0.0.1', PORT: String(IDP_PORT), IDENTITY_PUBLIC_URL: IDP, IDENTITY_ENCRYPTION_KEY: crypto.randomBytes(48).toString('base64') };

  // throwaway state: clean schema, then Identity as in the script's prerequisites (no IDENTITY_API_KEY: the setup code is shown)
  run(py, ['-I', '-c', 'import sys,psycopg\nwith psycopg.connect(sys.argv[1], autocommit=True) as c: c.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public")', dsn]);
  startProc(path.join(VENV, 'identity'), ['start'], idpEnv, log);
  await waitUntil(async () => (await fetch(`${IDP}/readyz`).catch(() => null))?.status === 200, 'Identity to be ready');

  const consoleV = await context(browser, 'console', [/\/api\/session$/]);
  const terminalV = await context(browser, 'terminal');
  const notesV = await context(browser, 'notes');
  const con = consoleV.page, tty = terminalV.page, notes = notesV.page;
  let privateV: Awaited<ReturnType<typeof context>>;      // opened only when scene 9 needs it: an idle page's video would stop early
  let priv: Page;
  await showHtml(tty, TERM_HTML);
  await install(tty);

  const shot = (page: Page, n: number) => page.screenshot({ path: path.join(OUT, `scene-${String(n).padStart(2, '0')}.png`) });
  /** The final video shows this browser context from now on (until the next show). */
  const show = (role: string) => { timeline[timeline.length - 1].cuts.push({ role, at_s: nowS() }); };
  const resetTerm = async () => { await showHtml(tty, TERM_HTML); await tty.evaluate(OVERLAY); };
  /** One scene: `at(prefix)` waits for the narration sentence that starts with `prefix`; the scene lasts the audio + 0.7 s unless its actions take longer. */
  async function scene(n: number, title: string, body: () => Promise<void>) {
    const started = Date.now();
    const nar = NARRATION[String(n)];
    if (process.env.VIDEO_NARRATION && !nar) throw new Error(`no narration for scene ${n}`);
    cues = nar?.cues ?? [];
    sceneStart = started;
    timeline.push({ scene: n, title, video: { start_s: nowS() }, cuts: [] });
    await body();
    const rest = ((nar?.duration ?? 10) + 0.7) * PACE * 1000 - (Date.now() - started);
    if (rest > 0) await con.waitForTimeout(rest);
    timeline[timeline.length - 1].video.end_s = nowS();
  }

  // 1 ---------------------------------------------------------------------------------------------------------------
  // Every action below waits for the sentence it illustrates (`at`), so the screen follows the voice; `scene` holds each scene to audio + 0.7 s.
  await scene(1, 'Title card, then the sign-in page', async () => {
    await showHtml(tty, CARD('One sign-in for every app', 'A tour of Identity'));
    show('terminal');
    await con.goto(`${IDP}/login`);
    await expect(con.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await at('Who is this person?', 0.3);
    show('console');
    await banner(con, 'Who is this person?', 3000);
    await at('And what may they do here?');
    await banner(con, 'What may they do here?', 3500);
    await shot(con, 1);
  });

  // 2 ---------------------------------------------------------------------------------------------------------------
  let code = '';
  await scene(2, 'First start: setup code, admin password', async () => {
    const m = /\b[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}\b/.exec(fs.readFileSync(log, 'utf8'));
    expect(m, 'setup code in the log').toBeTruthy();
    code = m![0];
    await resetTerm();
    show('terminal');
    await term(tty, 'grep -A1 "one-time code" /tmp/idp.log',
      fs.readFileSync(log, 'utf8').split('\n').flatMap((l, i, a) => (l.includes('one-time code') ? [l, a[i + 1]] : [])).join('\n'));
    await at('On first start');
    await mark(tty, code, 4500);
    await at('Only whoever');
    await banner(tty, 'Setup code = proof you operate the server', 4000);
    await at('Now the admin page');
    await con.goto(`${IDP}/admin`);
    await expect(con.getByRole('heading', { name: 'Set up Identity' })).toBeVisible();
    show('console');
    await at('We paste the code');
    await typeInto(con, '#setup-code', code);
    await typeInto(con, '#setup-pw', ADMIN_PW);
    await typeInto(con, '#setup-pw2', ADMIN_PW);
    await at('That password also protects', 0.5);
    await con.getByRole('button', { name: 'Create admin password' }).click();
    await expect(con.locator('#nav a[data-tab=overview]')).toBeVisible();
    await shot(con, 2);
  });

  // 3 ---------------------------------------------------------------------------------------------------------------
  const seeded = run(py, ['-I', path.join(TUTORIAL, 'seed.py')], { IDP, IDP_ADMIN_PASSWORD: ADMIN_PW });   // the script's seed step, done between the scenes
  await scene(3, 'Seed, then Overview, Users, Groups', async () => {
    await resetTerm();
    show('terminal');
    await term(tty, "IDP=http://localhost:8000 IDP_ADMIN_PASSWORD='tutorial admin pass 2026' .venv/bin/python /tmp/tutorial/seed.py", seeded);
    await at('Back in the console');
    await con.locator('#nav a[data-tab=overview]').click();
    show('console');
    await expect(con.locator('.stats')).toBeVisible();
    await mark(con, con.locator('.stats'), 2800);
    await at('Here are the people');
    await con.locator('#nav a[data-tab=users]').click();
    await expect(con.getByRole('row', { name: /ada/ })).toBeVisible();
    await at('A group is a named set');
    await con.locator('#nav a[data-tab=groups]').click();
    const writers = con.getByRole('row', { name: /writers/ });
    await expect(writers).toBeVisible();
    await at('We have one, called writers');
    await mark(con, writers, 4000);
    await banner(con, 'writers: 1 member', 4000);
    await shot(con, 3);
  });

  // 4 ---------------------------------------------------------------------------------------------------------------
  let notesSecret = '';
  await scene(4, 'Register the app Notes', async () => {
    show('console');
    await at('Now we register an app', 0.1);
    await con.locator('#nav a[data-tab=apps]').click();
    await expect(con.getByRole('heading', { name: 'Apps', level: 1 })).toBeVisible();
    await at('Its client id');
    await typeInto(con, 'input[name=client_id]', 'notes');
    await typeInto(con, 'input[name=name]', 'Notes');
    await at('The kind is web');
    await con.locator('select[name=kind]').selectOption('web');
    await typeInto(con, 'input[name=url]', NOTES);
    await typeInto(con, 'input[name=redirects]', `${NOTES}/callback`);
    await at('The redirect address');
    await mark(con, con.locator('input[name=redirects]'), 4500);
    await banner(con, 'Redirect URIs: exact match', 4500);
    await at('We define two roles');
    await typeInto(con, 'input[name=roles]', 'editor, reader');
    await typeInto(con, 'input[name=defaults]', 'reader');
    await typeInto(con, 'input[name=logout]', `${NOTES}/`);
    await at('Now Identity shows', 0.1);
    await con.getByRole('button', { name: 'Register', exact: true }).click();
    const box = con.locator('pre.secret-box code');
    await expect(box).toBeVisible();
    notesSecret = (await box.innerText()).trim();
    await banner(con, 'Secret shown once', 4500);
    await at('We copy it');
    await con.getByRole('button', { name: 'Copy' }).click();
    await expect(con.locator('#toast')).toContainText('Copied');
    await hold(con, 1200);
    show('terminal');
    await resetTerm();
    startProc(py, [path.join(TUTORIAL, 'demo_rp.py')], { IDP, NOTES_SECRET: notesSecret }, path.join(OUT, 'notes.log'));
    await term(tty, 'export NOTES_SECRET=cs_…   # pasted; not shown\nIDP=http://localhost:8000 .venv/bin/python /tmp/tutorial/demo_rp.py &', '');
    await waitUntil(async () => (await fetch(NOTES).catch(() => null))?.status === 200, 'Notes to answer');
    await at('The app is running');
    show('console');
    await con.getByRole('button', { name: 'Done' }).click();
    await expect(con.getByRole('cell', { name: /Notes/ })).toBeVisible();
    await shot(con, 4);
  });

  // 5 ---------------------------------------------------------------------------------------------------------------
  await scene(5, 'Grant editor to writers; Grace has nothing direct', async () => {
    show('console');
    await at('Now, the access', 0.1);
    await con.locator('#nav a[data-tab=groups]').click();
    const row = con.getByRole('row', { name: /writers/ });
    await at('On the writers group');
    await row.locator("select[aria-label='App for group writers']").selectOption('notes');
    await row.locator("input[aria-label='Role to grant to group writers']").click();
    await row.locator("input[aria-label='Role to grant to group writers']").pressSequentially('editor', { delay: TYPE_DELAY });
    await at('Everyone in writers', 0.1);
    await row.getByRole('button', { name: 'Grant' }).click();
    await expect(con.locator('#toast')).toContainText('Granted');
    await banner(con, 'writers -> notes:editor', 3500);
    await at('Next, Grace');
    await con.locator('#nav a[data-tab=users]').click();
    await con.getByRole('row', { name: /grace/ }).getByRole('button', { name: 'Roles' }).click();
    await expect(con.getByRole('heading', { name: 'grace', level: 1 })).toBeVisible();
    await expect(con.getByText('No direct roles')).toBeVisible();
    await at('So she will only hold');
    await banner(con, 'Grace -> notes:reader (default)', 4000);
    await shot(con, 5);
    await at('Roles always belong');
    await con.locator('#nav a[data-tab=users]').click();
  });

  // 6 ---------------------------------------------------------------------------------------------------------------
  const signIn = async (user: string, pw: string) => {          // up to typing the password; `submit` is the click that sends the browser back
    await notes.getByRole('link', { name: 'Sign in with Identity' }).click();
    await expect(notes).toHaveURL(new RegExp(`localhost:${IDP_PORT}/login`));
    await typeInto(notes, '#username', user);
    await typeInto(notes, '#password', pw);
  };
  const submit = async () => {
    await notes.getByRole('button', { name: 'Sign in' }).click();
    await expect(notes).toHaveURL(NOTES + '/');
  };
  await scene(6, 'Sign in to Notes as Grace, then Ada; the launcher', async () => {
    await notes.goto(NOTES);
    show('notes');
    await expect(notes.locator('body')).toContainText('Not signed in.');
    await banner(notes, 'App -> Identity -> sign in -> code -> tokens', 5500);
    await at('The app sends the browser');
    await signIn('grace', 'nanosecond wire 1947');
    await at('Identity sends her back', 0.1);
    await submit();
    await expect(notes.locator('body')).toContainText('notes:reader');
    await expect(notes.locator('body')).toContainText('Read only.');
    await at('Notes now knows');
    await mark(notes, notes.getByText('Roles in this app'), 4500);
    await shot(notes, 6);
    await at('Now she signs out');
    await notes.getByRole('link', { name: 'Sign out' }).click();
    await expect(notes.locator('body')).toContainText('Not signed in.');
    await at('Now Ada signs in');
    await signIn('ada', 'analytical engine 1843');
    await at('Ada holds the editor', 0.5);
    await submit();
    await expect(notes.locator('body')).toContainText('notes:editor');
    await expect(notes.locator('body')).toContainText('You can edit notes.');
    await mark(notes, notes.getByText('Roles in this app'), 4000);
    await at('Identity also has a launcher');
    await notes.goto(`${IDP}/apps`);
    await expect(notes.locator('.app-tile').first()).toBeVisible();
  });

  // 7 ---------------------------------------------------------------------------------------------------------------
  await scene(7, 'The ID token the app received (browser); discovery; JWKS', async () => {
    await notes.goto(NOTES);
    show('notes');
    await expect(notes.locator('pre')).toBeVisible();
    await notes.locator('pre').scrollIntoViewIfNeeded();
    await at('It checks the issuer');
    await mark(notes, '"iss"', 3500);
    await at('And the audience');
    await mark(notes, '"aud"', 3500);
    await at('The roles inside');
    await mark(notes, '"roles"', 4500);
    await shot(notes, 7);
    await at('The app finds them');
    await notes.goto(`${IDP}/.well-known/openid-configuration`);
    await at('The keys are published');
    await notes.goto(`${IDP}/jwks.json`);
  });

  // 8 ---------------------------------------------------------------------------------------------------------------
  await scene(8, 'A service client: client_credentials', async () => {
    show('console');
    await con.locator('#nav a[data-tab=apps]').click();
    await at('We register a service');
    await typeInto(con, 'input[name=client_id]', 'notes-worker');
    await typeInto(con, 'input[name=name]', 'Notes worker');
    await con.locator('select[name=kind]').selectOption('service');
    await at('The scope notes.write');
    await typeInto(con, 'input[name=scopes]', 'notes.write');
    await typeInto(con, 'input[name=audiences]', 'notes');
    await at('It gets its own secret', 0.1);
    await con.getByRole('button', { name: 'Register', exact: true }).click();
    const box = con.locator('pre.secret-box code');
    await expect(box).toBeVisible();
    const secret = (await box.innerText()).trim();
    const decode = 'import sys,json,base64;t=json.load(sys.stdin)[\'access_token\'].split(\'.\')[1];print(json.dumps(json.loads(base64.urlsafe_b64decode(t+\'=\'*(-len(t)%4))),indent=2))';
    const token = (scope: string) => run('/usr/bin/curl', ['-s', '-u', `notes-worker:${secret}`, '-d', 'grant_type=client_credentials', '-d', `scope=${scope}`, `${IDP}/oauth/token`]);
    const good = execFileSync('/usr/bin/python3', ['-c', decode], { input: token('notes.write'), encoding: 'utf8' });
    const bad403 = token('notes.read');
    expect(JSON.parse(bad403).error).toBe('invalid_scope');
    await at('We copy it');
    await con.getByRole('button', { name: 'Copy' }).click();
    await at('Now the worker asks');
    await resetTerm();
    show('terminal');
    await term(tty, 'export SECRET=cs_…   # pasted; not shown\ncurl -s -u notes-worker:"$SECRET" -d grant_type=client_credentials -d scope=notes.write http://localhost:8000/oauth/token | python3 -c "…decode the token…"', good);
    await at('The subject is the worker');
    await mark(tty, '"sub_type": "service"', 3500);
    await at('The audience is notes');
    await mark(tty, '"aud": "notes"', 3000);
    await at('The scope is');
    await mark(tty, '"scope": "notes.write"', 3000);
    await at('Now it asks for a scope');
    await term(tty, 'curl -s -u notes-worker:"$SECRET" -d grant_type=client_credentials -d scope=notes.read http://localhost:8000/oauth/token', bad403);
    await at('Identity refuses');
    await mark(tty, 'invalid_scope', 3500);
    await shot(tty, 8);
    await con.getByRole('button', { name: 'Done' }).click();
  });

  // 9 ---------------------------------------------------------------------------------------------------------------
  await scene(9, 'Disable a person; rotate the signing key; audit', async () => {
    show('console');
    await con.locator('#nav a[data-tab=users]').click();
    await at('We disable Alan');
    await con.getByRole('row', { name: /alan/ }).getByRole('button', { name: 'Disable' }).click();
    await expect(con.getByRole('row', { name: /alan/ }).getByRole('button', { name: 'Enable' })).toBeVisible();
    privateV = await context(browser, 'private', [new RegExp(`401 POST ${IDP}/login$`)]);
    priv = privateV.page;
    await priv.goto(`${IDP}/login`);
    await at('Now he cannot sign in', 0.3);
    show('private');
    await typeInto(priv, '#username', 'alan');
    await typeInto(priv, '#password', 'imitation game 1950');
    await priv.getByRole('button', { name: 'Sign in' }).click();
    await expect(priv.locator('#error')).toContainText('that username or password is not right');
    await at('Second, the signing keys', 0.3);
    show('console');
    await con.locator('#nav a[data-tab=keys]').click();
    await expect(con.getByRole('heading', { name: 'Signing keys' })).toBeVisible();
    await at('Here is the active one');
    await mark(con, con.locator('table'), 3000);
    await at('We rotate it');
    await con.getByRole('button', { name: 'Rotate key' }).click();
    const dlg = con.locator('dialog[open]');
    await expect(dlg).toBeVisible();
    await expect(dlg).toContainText('Create a new signing key?');
    await hold(con, 1500);
    await dlg.getByRole('button', { name: 'Rotate key' }).click();
    await expect(con.locator('tbody tr')).toHaveCount(2);               // the new active key and the retiring one (there is no toast)
    await at('The new key is active');
    await mark(con, con.locator('tbody tr').nth(1), 4500);
    await banner(con, 'Retires: 24 h after rotation', 4500);
    await at('Third, the audit page');
    await con.locator('#nav a[data-tab=audit]').click();
    await expect(con.getByRole('cell', { name: 'signing key rotated' })).toBeVisible();
    await mark(con, con.locator('table'), 4000);
    await shot(con, 9);
  });

  // 10 --------------------------------------------------------------------------------------------------------------
  await scene(10, 'Recap on the Overview', async () => {
    show('console');
    await con.locator('#nav a[data-tab=overview]').click();
    await expect(con.locator('.stats')).toBeVisible();
    await shot(con, 10);
    await at('Everything you saw');
    await showHtml(tty, CARD('docs/GUIDE.md', 'Next: register your own app'));
    show('terminal');
  });

  // ---- finish: close contexts (this writes the videos), name them, write the timeline ---------------------------------------
  const roles: [string, BrowserContext, Page][] = [['console', consoleV.ctx, con], ['terminal', terminalV.ctx, tty], ['private', privateV!.ctx, priv!], ['notes', notesV.ctx, notes]];
  fs.mkdirSync(path.join(OUT, 'videos'), { recursive: true });
  for (const [role, ctx, page] of roles) {
    const v = page.video();
    await ctx.close();
    await v!.saveAs(path.join(OUT, 'videos', `${role}.webm`));
    fs.rmSync(path.join(OUT, 'videos', role), { recursive: true, force: true });
  }
  fs.writeFileSync(path.join(OUT, 'timeline.json'), JSON.stringify({ size: SIZE, pace: PACE, offsets, note: 'seconds since the recorder started; every video starts at about 0', scenes: timeline }, null, 2));
  expect(bad, 'unexpected 4xx/5xx responses in the browser').toEqual([]);
});

test.afterAll(() => {
  for (const p of procs) p.kill('SIGTERM');
});
