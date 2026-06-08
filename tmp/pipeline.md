# KJIT Explorer Milestones

## Goal
Replace the old harness TUI with an OpenTUI-backed explorer while keeping the
translation/runtime harness untouched.

## Milestones

1. Load the OpenTUI native library from a local checkout or explicit env var.
2. Keep the existing explorer state machine and trace inspection logic shared.
3. Render the explorer with OpenTUI as the only interactive backend.
4. Preserve stepping, command input, export, and fixture checking.
5. Verify the interactive TUI and the noninteractive `--dump --check` path.

## Current status

- OpenTUI backend is wired into `trace-tui`.
- `scripts/run-trace-tui.sh` defaults to OpenTUI and auto-detects a nearby
  OpenTUI checkout if present.
- Mouse wheel scrolling now follows the pane under the pointer, and mouse drag
  selection copies the selected rows to the system clipboard plus
  `tmp/trace-copy.txt`.
- Fixture validation still passes with `scripts/run-asm-fixture.sh`.
