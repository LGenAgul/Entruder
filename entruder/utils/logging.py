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
