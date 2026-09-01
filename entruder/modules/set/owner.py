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


@set_app.command("owner")
@handle_cli_errors
def set_groupMember(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    app_id: str = typer.Option(..., "--appid", "-a", help="Application or Service Principal ID to add the owner to (Mandatory)"),
    user_id: str = typer.Option(..., "-u", "--user-id", help="User ID or UPN of the user to add (Mandatory)"),
):
    """Add a user as an owner of an application or service principal (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"

    user_id = resolve_user_id(headers, url, user_id)
   
    vprint(f"[dim] Using user id {user_id}")

    for resource in ("applications", "servicePrincipals"):
        json={"@odata.id": f"https://graph.microsoft.com/{API_VERSIONS['graph']}/directoryObjects/{user_id}"}
        response = httpx.post(
            f"{url}/{resource}/{app_id}/owners/$ref",
            headers=headers,
            json={
                "@odata.id": f"https://graph.microsoft.com/{API_VERSIONS['graph']}/directoryObjects/{user_id}"
            }
        )
        vprint(f"[dim] POST {url}/{resource}/{app_id}/owners/$ref")
        vprint(f"json={json}")
        if response.status_code == 204:
            console.print(f"[bold green][+][/] Successfully added {user_id[0:16]}... as owner of {resource}/{app_id}")
            return
        elif response.status_code == 400 and "already exist" in response.text.lower():
            console.print(f"[bold yellow][!][/] {user_id[0:16]}... is already an owner of {app_id}")
            return

    console.print(f"[bold red][-][/] Failed to add owner: {response.status_code} {response.text}")
    raise typer.Exit(1)

