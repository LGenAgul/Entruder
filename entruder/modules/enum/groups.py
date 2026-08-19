import typer

from entruder.globals import API_VERSIONS, GROUP_PARAMS
from entruder.utils import (
    parse_error,
    request_json,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import enum_app, console, columns, prepare_session


@enum_app.command("groups")
@handle_cli_errors
def enum_groups(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    output: OutputFormat = output_option(),
    ):
    """Enumerate directory groups via Microsoft Graph, using a saved graph session"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/groups"
    params = GROUP_PARAMS

    groups = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)
        params = None  # nextLink already carries $select; don't re-send it

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Graph request failed: {parse_error(message)}")
            raise typer.Exit(1)

        groups.extend(result["value"])
        url = result.get("@odata.nextLink")
    render(console, f"Groups in {tenant}", columns.GROUP, groups, output=output, xml_root_tag="groups", xml_item_tag="group")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(groups)}[/] groups total")
