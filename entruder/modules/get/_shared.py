import typer

from entruder.columns import Columns
from entruder.console import CONSOLE as console
from entruder.globals import (
    prepare_session,
    resolve_user_id,
    resolve_group_id,
    resolve_app_roles,
)


get_app = typer.Typer(help="Fetch a single directory object by id", no_args_is_help=True)
columns = Columns()


def graph_get(headers, url, params=None):
    """GET a single Graph object, raising a clean CLI error if Graph hands back
    an error payload instead of the object. Mirrors the error-surfacing the
    enum commands do inline, kept here once since every get command needs it."""
    from entruder.utils import request_json, vprint, parse_error

    vprint(f"GET {url}")
    result = request_json("GET", url, headers=headers, params=params)
    if isinstance(result, dict) and "error" in result:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        console.print(f"[bold red][-][/] Graph request failed: {parse_error(message)}")
        raise typer.Exit(1)
    return result


def object_columns(obj):
    """Build a (label, key) column list from an object's own fields so the
    table/csv views work for any Graph object without a hand-written column
    spec. json/xml already emit the full nested body and ignore columns; this
    just keeps -o table/csv useful. @odata.* control fields are transport
    noise, not object data, so they're dropped."""
    if not isinstance(obj, dict):
        return []
    return [(key, key) for key in obj if not key.startswith("@odata")]
