import typer
from rich.console import Console

BANNER = r"""
 ███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗██████╗ ███████╗██████╗
 ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██║   ██║██╔══██╗██╔════╝██╔══██╗
 █████╗  ██╔██╗ ██║   ██║   ██████╔╝██║   ██║██║  ██║█████╗  ██████╔╝
 ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║   ██║██║  ██║██╔══╝  ██╔══██╗
 ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██████╔╝███████╗██║  ██║
 ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
 Made in Georgia
"""

Console().print(BANNER, style="bold cyan", highlight=False)

from entruder.modules.enum import enum_app
from entruder.modules.login import login_app
from entruder.modules.brute import brute_app
from entruder.modules.analyze import analyze_app
from entruder.modules.exploit import exploit_app
from entruder.modules.azsync import azsync_app
from entruder.modules.set import set_app
from entruder.static import CACHE_DIR,SESSIONS_DIR,STATE

import typer.core as tc
import typer.rich_utils as ru
from rich.console import Group
from rich.padding import Padding
from rich.text import Text

# Keep rich's coloring (option names, metavars, etc.) but drop the panel
# border box itself, and align section headings with their rows. typer
# always wraps the options/commands tables in a rich.Panel with no public
# way to opt out of the border, and the panel's own edge padding is what
# used to put the "Options"/"Commands" title one column deeper than the
# table rows below it (the table itself renders flush-left). Swapping the
# Panel for a plain heading + table, both under the same 1-space left
# margin used by the rest of the help text (Usage:/description), fixes
# both the border and the mismatched indentation in one place.
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

# rich_utils._get_parameter_help() renders "[default: ...]" for EVERY option
# with show_default (the typer.Option default) whenever it has a default at
# all — unlike click's own get_help_record(), it skips the "is the default
# actually None" check, so every `typer.Option(None, ...)` in this codebase
# (i.e. every optional flag with no real default) showed a literal
# "[default: None]". Patching the shared default-stringifier to treat None
# as "no default to show" fixes it everywhere without touching every module.
_get_default_string = tc._get_default_string
def _get_default_string_no_none(obj, *, ctx, show_default_is_str, default_value):
    if not show_default_is_str and default_value is None:
        return ""
    return _get_default_string(obj, ctx=ctx, show_default_is_str=show_default_is_str, default_value=default_value)
tc._get_default_string = _get_default_string_no_none

app = typer.Typer(
    name = "entruder",
    help = "Azure/Entra ID testing toolkit",
    no_args_is_help=True,
)


@app.callback()
def main(
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show full tracebacks for internal errors"),
    no_progress: bool = typer.Option(False, "-n", "--no-progress", help="Don't show the live progress spinner for multi call commands")
):
    """Global options applied to every command."""
    
    STATE.verbose = verbose
    STATE.no_progress = no_progress


# Initializing modules
app.add_typer(enum_app,name="enum")
app.add_typer(login_app,name="login")
app.add_typer(brute_app,name="brute")
app.add_typer(analyze_app,name="analyze")
app.add_typer(exploit_app,name="exploit")
app.add_typer(azsync_app,name="azsync")
app.add_typer(set_app,name="set")

# initializing the cache directory
CACHE_DIR.mkdir(mode=0o700, exist_ok=True)
SESSIONS_DIR.mkdir(mode=0o700, exist_ok=True)




