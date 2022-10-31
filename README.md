# Symbolic Triage

This repository contains the supporting materials for the “Symbolic Triage” blog post.
- `triage.py` is the main utility, which implements the symbolic execution and tracing of the `Procmon64.exe` crashes
  - Targets Process Monitor version 3.91
  - Is intended to be used as an example of using Triton hand in hand with the Windows debugging API
- `win_types.py` contains windows types used for using the debugger API
- `procmoncrash.xx` contains an [xx](https://github.com/netspooky/xx) file of a minimized crash, [as described here](https://forum.spacehey.com/topic?id=93101)

