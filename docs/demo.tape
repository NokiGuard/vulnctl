# docs/demo.tape — vulnctl README demo GIF (charmbracelet/vhs).
#
# Record with:   vhs docs/demo.tape
# Requires:      vhs (https://github.com/charmbracelet/vhs) and vulnctl on PATH,
#                run from the repo root so examples/context.yaml resolves.
# Produces:      docs/demo.gif
#
# The on-camera command hits live intel APIs. A Hidden block warms the cache
# first so the recorded run is fast and deterministic (and non-degraded: the
# live CVSS vector resolves `automatable` from data instead of the default).
# On-camera runtime stays well under 30s. For a network-free recording, swap
# the command for the --offline variant noted at the bottom.

Output docs/demo.gif

Require vulnctl

Set Shell bash
Set FontSize 18
Set Width 1240
Set Height 760
Set Padding 24
Set TypingSpeed 45ms

# --- Warm the cache off-camera (no frames captured during Hidden) -----------
Hidden
Type "vulnctl enrich CVE-2021-44228 --context examples/context.yaml --show-path > /dev/null 2>&1"
Enter
Sleep 10s
Ctrl+L
Show

# --- The shot: one CVE, a verdict, and the full decision path ---------------
Type "vulnctl enrich CVE-2021-44228 --context examples/context.yaml --show-path"
Sleep 600ms
Enter
Sleep 2s
Sleep 7s

# Offline alternative (fully deterministic, no network — note the path shows
# `automatable = yes [default]` and a "degraded" flag because there is no live
# CVSS vector to derive it from):
#   Type "vulnctl enrich CVE-2021-44228 --offline --show-path"
