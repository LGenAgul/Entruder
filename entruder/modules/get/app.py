import typer

from entruder.static import API_VERSIONS
from entruder.utils import (
    request_json,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import get_app, console, prepare_session, object_columns


@get_app.command("app")
@handle_cli_errors
def get_application(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    app_id: str = typer.Option(..., "-a", "--appid", help="Application or service principal object id"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Fetch a single application or service principal by object id via Microsoft Graph (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    base = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"
    # An object id can be either an application registration or a service
    # principal, so try both (same fallback set/owner uses) and return the
    # first that resolves.
    for resource in ("applications", "servicePrincipals"):
        vprint(f"GET {base}/{resource}/{app_id}")
        result = request_json("GET", f"{base}/{resource}/{app_id}", headers=headers)
        if isinstance(result, dict) and "error" not in result:
            render(console, f"{resource} {app_id}", object_columns(result), result, output=output, xml_item_tag="app")
            return

    console.print(f"[bold red][-][/] No application or service principal found with id {app_id}")
    raise typer.Exit(1)
