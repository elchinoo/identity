# Tutorial video: review cut

One command builds the narrated, captioned video from `../VIDEO-SCRIPT.md` and `record.spec.ts`:

```bash
cd docs/video
PATH=/path/to/postgres/bin:$PATH ./build.sh        # about 15 minutes with narration synthesis; result: out/final/identity.mp4 + identity.srt
```

Needs macOS, Google Chrome, `ffmpeg`/`ffprobe`, node/npm, Postgres binaries (`initdb`, `pg_ctl`, `createdb`), the repository `.venv`
(identity plus `../agentpg-kit`) and the shared local TTS tool in `../../../videos/tts` (Kokoro neural voice: its `.venv` and models are already
there; set `TTS_DIR` to use another copy). Nothing is downloaded except the pinned devDependencies (`npm install`, done by the script when `node_modules` is missing).
Do not run `npx playwright install`: the script gives Playwright a private browsers directory whose `ffmpeg` is the system one.

What it does:

1. Narration: `narration.txt` is the text written for listening, one `## <scene id> <voice>` section per scene of `../VIDEO-SCRIPT.md`. The voice changes with the topic (US voices, alternating female and male: scenes 1-2 and 6-7 and 10 `af_bella`, 3-5 `am_eric`, 8-9 `am_michael`), never inside a scene; `--voice` is only the fallback. A blank line is a
   natural pause, a line `...` a short beat, `[pause 1.5]` a deliberate long pause (used while something happens on screen). `script_sync.py check`
   makes sure the NARRATION column of the script table equals it (`script_sync.py write` copies it there). Then
   `narrate.py scenes narration.txt out/narration --voice af_bella --pronounce pronounce.json` (shared tool) writes `scene-<id>.wav` and
   `narration.json` (duration and the start/end of every sentence). `check_gaps.py` fails the build on silence longer than 3.5 s that is not a
   deliberate `[pause]`, or on a long tail after the last sentence.
2. Scene length = audio + 0.7 s. The recorder reads `narration.json` (`VIDEO_NARRATION`) and starts each on-screen action when the sentence that
   explains it begins (`at('Its client id')` in `record.spec.ts` waits for the sentence starting with those words and fails if none exists, so
   changing the narration without the recorder is caught). Actions that take longer than the audio lengthen the scene.
3. A fresh throwaway Postgres under `$WORK/pg` (default `$TMPDIR/identity-video-work`), then the recorder (real Chrome, 1920x1080) which writes the four
   videos and `timeline.json` (with the cuts: which context is on screen when, and the offsets of each video).
4. `assemble.py`: cuts the videos along the timeline into one continuous H.264/AAC mp4 (+faststart), places each scene's wav at its scene start,
   and writes `identity.srt` (one caption per spoken sentence, timed by the voice; a long sentence is split at a comma). Title and end cards are drawn by the recorder.

Pronunciation: neural voices mangle acronyms. `../../../videos/tts/pronounce.json` (shared) and `pronounce.json` here (project words such as
`notes.write`) are respellings applied to the spoken text only; captions keep the written form. Prefer rewording the narration to a fragile respelling.

Settings (environment): `NAME` (default `identity`), `VOICE` (`af_bella`), `TTS_DIR`, `IDP_PORT` (41100), `NOTES_PORT` (41101), `PG_PORT` (41102), `WORK`,
`OUT_COPY` (folder to copy mp4 and srt to). The drawn terminals and the URL labels show the ports actually used.
Everything under `out/` is git-ignored; do not commit media.
