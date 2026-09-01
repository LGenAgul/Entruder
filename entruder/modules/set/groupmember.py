import typer
import httpx
from entruder.static import API_VERSIONS
from entruder.utils import (
    handle_cli_errors,
    OutputFormat,
    output_option,
    vprint
)

from ._shared import set_app, console, prepare_session, resolve_user_id, resolve_group_id


@set_app.command("group-member")
@handle_cli_errors
def set_groupMember(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    group_id: str = typer.Option(..., "-g", "--group-id", help="Group ID or display name to add the member to (Mandatory)"),
    user_id: str = typer.Option(..., "-u", "--user-id", help="User ID or UPN of the user to add (Mandatory)"),
):
    """Add a user to a group (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"

    user_id = resolve_user_id(headers, url, user_id)
    group_id = resolve_group_id(headers, url, group_id)
    json={
                "@odata.id": f"https://graph.microsoft.com/{API_VERSIONS['graph']}/directoryObjects/{user_id}"
            }
    response = httpx.post(
        f"{url}/groups/{group_id}/members/$ref",
        headers=headers,
        json=json
    )

    vprint(f"[dim] POST {url}/groups/{group_id}/members/$ref")
    vprint(f"json={json}")
    if response.status_code != 204:
        console.print(f"[bold red][-][/] Failed to change add {user_id[0:16]}... to the {group_id} group: {response.text}")
        raise typer.Exit(1)
    console.print(f"[bold green][+][/] {user_id[0:16]}... successfully added to {group_id}")

