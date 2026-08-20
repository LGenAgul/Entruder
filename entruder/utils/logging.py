import functools
from concurrent.futures import as_completed

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, MofNCompleteColumn

# Shared console for diagnostic (verbose) output
_console = Console()

# Progress feedback goes to stderr, not the main console, so it never lands
# in piped -output json/csv/xml (that's stdout only) and stays visible on
# screen even when stdout is redirected to a file.
_status_console = Console(stderr=True)


def vprint(message: str) -> None:
    from entruder.static import STATE
    if STATE.verbose:
        _console.print(f"[dim][*] {message}[/dim]")


def iter_with_progress(items, description: str, key=None):
    """Wrap an iterable with a transient spinner so loops that make one API
    call per item (checking access on N storage accounts, listing secrets on
    N vaults, fetching config for N web apps) give feedback while they run
    instead of hanging silently. Not gated by -verbose, unlike vprint, since
    this is progress the user usually wants, not request-level debug detail,
    but -no-progress (STATE.no_progress) turns it off for anyone who'd rather
    not see it, e.g. when capturing a clean terminal recording.

    key(item) -> a short label for the item currently being processed
    (account name, vault name, ...); omit for a plain counter. Clears itself
    once the loop finishes rather than leaving scrollback clutter.
    """
    from entruder.static import STATE

    items = list(items)
    if not items:
        return
    if STATE.no_progress:
        yield from items
        return
    with Progress(
        SpinnerColumn(),
        TextColumn("[dim]{task.description}[/dim]"),
        MofNCompleteColumn(),
        console=_status_console,
        transient=True,
    ) as progress:
        task = progress.add_task(description, total=len(items))
        for item in items:
            if key:
                progress.update(task, description=f"{description}: {key(item)}")
            yield item
            progress.advance(task)


def iter_futures_with_progress(futures: dict, description: str, label=None):
    """Like iter_with_progress, but for concurrent.futures.Future objects:
    yields (future, value) pairs as each future actually completes (via
    as_completed) instead of materializing the whole iterable up front.
    iter_with_progress's `list(items)` would drain as_completed() before the
    loop even starts, since consuming an as_completed generator into a list
    means waiting for every future to finish first — the progress bar would
    then sit idle and jump straight to 100% instead of tracking completions
    live, which defeats the point for a thread-pooled brute-force loop.

    `futures` maps future -> whatever value the caller wants back alongside
    it. `label(value)` renders the live per-future line in the progress bar;
    omit for a plain counter."""
    from entruder.static import STATE

    total = len(futures)
    if not total:
        return
    if STATE.no_progress:
        for future in as_completed(futures):
            yield future, futures[future]
        return
    with Progress(
        SpinnerColumn(),
        TextColumn("[dim]{task.description}[/dim]"),
        MofNCompleteColumn(),
        console=_status_console,
        transient=True,
    ) as progress:
        task = progress.add_task(description, total=total)
        for future in as_completed(futures):
            value = futures[future]
            if label:
                progress.update(task, description=f"{description}: {label(value)}")
            yield future, value
            progress.advance(task)


def report_error(exc: Exception, console: Console = None) -> None:
    from entruder.static import STATE
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
