#!/usr/bin/env bash
# One command from docs/VIDEO-SCRIPT.md + record.spec.ts to the finished review cut:
#   docs/video/build.sh            -> docs/video/out/final/identity.mp4 + identity.srt  (about 6 minutes of recording, then encoding)
# Steps: narration (Kokoro, local neural TTS, voice af_bella) -> throwaway Postgres -> recorder (real Chrome) -> assemble.py (ffmpeg).
# Local only. Needs: macOS, the shared TTS tool ../../../videos/tts (its .venv and models; nothing is downloaded), Google Chrome, ffmpeg/ffprobe, node/npm, Postgres binaries (initdb, pg_ctl, createdb) on PATH,
# the repository's .venv (identity + ../agentpg-kit installed). Does not download anything beyond `npm install` of the pinned devDependencies.
# Settings (environment): NAME=identity  IDP_PORT=41100  NOTES_PORT=41101  PG_PORT=41102  WORK=<scratch dir for Postgres + browsers shim>
#                         VOICE=af_bella  TTS_DIR=<folder holding narrate.py, .venv, models>  OUT_COPY=<folder to copy the mp4 and srt into after the build>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NAME="${NAME:-identity}"
export IDP_PORT="${IDP_PORT:-41100}" NOTES_PORT="${NOTES_PORT:-41101}"
PG_PORT="${PG_PORT:-41102}"
VOICE="${VOICE:-af_bella}"
TTS_DIR="${TTS_DIR:-$(cd "$HERE/../../.." && pwd)/videos/tts}"
WORK="${WORK:-${TMPDIR:-/tmp}/identity-video-work}"
OUT="$HERE/out"
mkdir -p "$WORK" "$OUT"
cd "$HERE"

[ -d node_modules ] || npm install
# Playwright's own ffmpeg build is not installed on this machine: point it at the system ffmpeg through a private browsers dir.
FFREV="$(node -p "require('./node_modules/playwright-core/browsers.json').browsers.find(b=>b.name==='ffmpeg').revision")"
export PLAYWRIGHT_BROWSERS_PATH="$WORK/browsers"
mkdir -p "$PLAYWRIGHT_BROWSERS_PATH/ffmpeg-$FFREV"
ln -sf "$(command -v ffmpeg)" "$PLAYWRIGHT_BROWSERS_PATH/ffmpeg-$FFREV/ffmpeg-mac"
touch "$PLAYWRIGHT_BROWSERS_PATH/ffmpeg-$FFREV/"{INSTALLATION_COMPLETE,DEPENDENCIES_VALIDATED}

# 1. narration: docs/video/narration.txt (written for listening) -> Kokoro neural voice -> out/narration/scene-<id>.wav + narration.json.
#    narration.json (duration and per-sentence cues of every scene) drives the scene lengths, the audio placement, the captions and the
#    moment every on-screen action starts. The recorder holds each scene to audio + 0.7 s.
python3 script_sync.py check            # the NARRATION column of docs/VIDEO-SCRIPT.md must equal narration.txt (python3 script_sync.py write fixes it)
mkdir -p "$OUT/narration"
"$TTS_DIR/.venv/bin/python" "$TTS_DIR/narrate.py" scenes narration.txt "$OUT/narration" --voice "$VOICE" --pronounce pronounce.json
python3 check_gaps.py "$OUT/narration"

# 2. a fresh throwaway database for this take
PGDIR="$WORK/pg"
if [ -d "$PGDIR" ]; then pg_ctl -D "$PGDIR" -m fast stop >/dev/null 2>&1 || true; rm -rf "$PGDIR"; fi
initdb -D "$PGDIR" -U identity --auth=trust -E UTF8 >/dev/null
pg_ctl -D "$PGDIR" -o "-p $PG_PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories=''" -l "$WORK/pg.log" -w start >/dev/null
trap 'pg_ctl -D "$PGDIR" -m fast stop >/dev/null 2>&1 || true' EXIT
createdb -h 127.0.0.1 -p "$PG_PORT" -U identity identity_test

# 3. record (the recorder starts and stops Identity and Notes itself)
VIDEO_DATABASE_URL="postgresql://identity@127.0.0.1:$PG_PORT/identity_test" VIDEO_NARRATION="$OUT/narration/narration.json" \
  node_modules/.bin/playwright test

# 4. cut, narrate, caption
python3 assemble.py "$OUT" "$NAME"
if [ -n "${OUT_COPY:-}" ]; then mkdir -p "$OUT_COPY"; cp "$OUT/final/$NAME.mp4" "$OUT/final/$NAME.srt" "$OUT_COPY/"; fi
echo "done: $OUT/final/$NAME.mp4"
