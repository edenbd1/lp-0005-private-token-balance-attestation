#!/usr/bin/env bash
# Helper for recording the submission demo video.
# Wraps scripts/demo.sh inside `script` (BSD/macOS) or `asciinema` so the terminal
# session — including the RISC0_DEV_MODE=0 indicator and proving timing — is
# captured into a single artifact reviewers can replay.
#
# macOS (default): produces an asciinema cast at artifacts/demo-recording.cast.
# Linux: same; falls back to `script` if asciinema isn't installed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p artifacts
OUT="${OUT:-$ROOT/artifacts/demo-recording.cast}"

if command -v asciinema >/dev/null 2>&1; then
    echo "Recording with asciinema → $OUT"
    asciinema rec --overwrite --command "RISC0_DEV_MODE=0 ./scripts/demo.sh" "$OUT"
    echo
    echo "Replay: asciinema play \"$OUT\""
    echo "Upload: asciinema upload \"$OUT\""
elif command -v script >/dev/null 2>&1; then
    OUT_TXT="${OUT%.cast}.txt"
    echo "asciinema not found; falling back to plain \`script\` → $OUT_TXT"
    script -q "$OUT_TXT" bash -c "RISC0_DEV_MODE=0 ./scripts/demo.sh"
    echo
    echo "Open: less -R \"$OUT_TXT\""
else
    echo "Neither asciinema nor script is available; running the demo without recording." >&2
    RISC0_DEV_MODE=0 ./scripts/demo.sh
fi
