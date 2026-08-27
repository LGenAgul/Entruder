import typer

from entruder.static import (
    API_VERSIONS,
    BASIC_PARAMS,
)
from entruder.utils import (
    request_json,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
    parse_error,
)

from ._shared import enum_app, console, columns, prepare_session


@enum_app.command("users")
@handle_cli_errors
def enum_users(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    output: OutputFormat = output_option(),
):
    """Enumerate directory users via Microsoft Graph, using a saved graph session"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/users"
    params = BASIC_PARAMS

    users = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)
        params = None

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Graph request failed: {parse_error(message)}")
            raise typer.Exit(1)

        users.extend(result["value"])
        url = result.get("@odata.nextLink")
    render(console, f"Users in {tenant}", columns.USER, users, output=output, xml_root_tag="users", xml_item_tag="user")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(users)}[/] users total")
