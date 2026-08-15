import functools

import typer
from rich.console import Console

# Shared console for diagnostic (verbose) output
_console = Console()


def vprint(message: str) -> None:
    from entruder.globals import STATE
    if STATE.verbose:
        _console.print(f"[dim][*] {message}[/dim]")


def report_error(exc: Exception, console: Console = None) -> None:
    from entruder.globals import STATE
    console = console or _console
    if STATE.verbose:
        console.print_exception()
    else:
        # an exception object is always truthy, so test its message, not the object
        console.print(f"[bold red][-][/] {str(exc) or type(exc).__name__}")


def handle_cli_errors(func):
    """
    Wraps a typer command body with the standard error-reporting boilerplate:
    let explicit typer.Exit calls through untouched, report anything else via
    report_error and exit(1). functools.wraps preserves the original signature
    (via __wrapped__) so typer can still read the command's Option definitions.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except typer.Exit:
            raise
        except Exception as e:
            report_error(e)
            raise typer.Exit(1)
    return wrapper
