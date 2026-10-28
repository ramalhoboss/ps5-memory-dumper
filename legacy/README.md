# Original script

`ps5_dumper_original_pt.py` is the first version of this tool, written by **RamalhoBoss**: a single Python
script, in Portuguese, that dumps process regions and kernel ranges over ps5debug, with block reads, page
bisection for unreadable memory and a `mapas.json` manifest.

PS5 Memory Dumper grew out of it: the same ideas, translated to English and split into an engine, a command
line and a desktop app, plus resume, auto-reconnect, ELF export and dump analysis. The app still reads dumps
made by this script (`mapas.json` is converted automatically).

It is kept here unchanged, for reference. To run it: `python ps5_dumper_original_pt.py` (needs `ps5dbg`).
