"""`python -m ps5dumper` opens the desktop app; with arguments it runs the command line."""
import sys


def main():
    if len(sys.argv) > 1:
        from .cli import main as cli_main
        return cli_main()
    from .gui.app import main as gui_main
    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
