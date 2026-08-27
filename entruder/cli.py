import typer
from entruder.static import BANNER
from entruder.console import CONSOLE, set_color




from entruder.modules.enum import enum_app
from entruder.modules.login import login_app
from entruder.modules.brute import brute_app
from entruder.modules.info import info_app
from entruder.modules.exploit import exploit_app
from entruder.modules.azsync import azsync_app
from entruder.modules.set import set_app
from entruder.modules.get import get_app
from entruder.modules.sharepoint import sharepoint_app
from entruder.static import CACHE_DIR,SESSIONS_DIR,STATE

import typer.core as tc
import typer.rich_utils as ru
from rich.console import Group
from rich.padding import Padding
from rich.text import Text


_section_state = {"first": True}

_rich_format_help = ru.rich_format_help
def _rich_format_help_reset_sections(*args, **kwargs):
    _section_state["first"] = True
    return _rich_format_help(*args, **kwargs)
ru.rich_format_help = _rich_format_help_reset_sections

def _plain_section(renderable, *, border_style=None, title=None, title_align=None, **_ignored):
    # The error panel is a standalone print (not preceded by help text's own
    # trailing blank line), so it always wants its own leading blank line.
    top_pad = 1 if (title == ru.ERRORS_PANEL_TITLE or not _section_state["first"]) else 0
    _section_state["first"] = False
    parts = [Text(str(title), style="bold")] if title else []
    parts.append(renderable)
    return Padding(Group(*parts), (top_pad, 0, 0, 1))
ru.Panel = _plain_section


_get_default_string = tc._get_default_string
def _get_default_string_no_none(obj, *, ctx, show_default_is_str, default_value):
    if not show_default_is_str and default_value is None:
        return ""
    return _get_default_string(obj, ctx=ctx, show_default_is_str=show_default_is_str, default_value=default_value)
tc._get_default_string = _get_default_string_no_none

app = typer.Typer(
    name = "entruder",
    help = BANNER,
    no_args_is_help=True,
)


@app.callback()
def main(
    color: bool = typer.Option(False, "--color/--no-color", help="Enable colored output (Optional, default: no color)"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show full tracebacks for internal errors"),
    no_progress: bool = typer.Option(False, "-n", "--no-progress", help="Don't show the live progress spinner for multi call commands")
):
    """Global options applied to every command."""

    set_color(color)
    STATE.verbose = verbose
    STATE.no_progress = no_progress


# Initializing modules
app.add_typer(enum_app,name="enum")
app.add_typer(login_app,name="login")
app.add_typer(brute_app,name="brute")
app.add_typer(info_app,name="info")
app.add_typer(exploit_app,name="exploit")
app.add_typer(azsync_app,name="azsync")
app.add_typer(set_app,name="set")
app.add_typer(get_app,name="get")
app.add_typer(sharepoint_app,name="sharepoint")

# initializing the cache directory
CACHE_DIR.mkdir(mode=0o700, exist_ok=True)
SESSIONS_DIR.mkdir(mode=0o700, exist_ok=True)




