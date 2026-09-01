import typer

from entruder.static import API_VERSIONS
from entruder.utils import (
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import get_app, console, prepare_session, resolve_group_id, graph_get, object_columns


@get_app.command("group")
@handle_cli_errors
def get_group(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    group: str = typer.Option(..., "-g", "--group-id", help="Group object id or displayName (Mandatory)"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Fetch a single group by object id or displayName via Microsoft Graph (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    base = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"
    # Graph's /groups/{id} only accepts an object id, so a displayName has to be
    # resolved to an id first (unlike /users/{id|upn}, which takes either).
    group_id = resolve_group_id(headers, base, group)
    result = graph_get(headers, f"{base}/groups/{group_id}")

    render(console, f"Group {group}", object_columns(result), result, output=output, xml_item_tag="group")
