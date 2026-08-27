"""Single shared rich Console (plus its stderr twin for progress output), so
the --color/--no-color toggle in cli.py's global callback can flip every
command's output at once instead of hunting down one Console() per module."""

from rich.console import Console

CONSOLE = Console(no_color=True)
STDERR_CONSOLE = Console(stderr=True, no_color=True)


def set_color(enabled: bool) -> None:
    CONSOLE.no_color = not enabled
    STDERR_CONSOLE.no_color = not enabled
