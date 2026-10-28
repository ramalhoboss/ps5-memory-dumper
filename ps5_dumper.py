"""Command-line entry point, kept so `python ps5_dumper.py ...` works as before.

The code lives in the ps5dumper package; `python -m ps5dumper` opens the desktop app.
"""
from ps5dumper.cli import interactive_dumper, main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
