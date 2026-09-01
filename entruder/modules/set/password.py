import typer
import httpx
from entruder.static import API_VERSIONS
from entruder.utils import (
    handle_cli_errors,
    OutputFormat,
    output_option,
    vprint
)

from ._shared import set_app, console, prepare_session, resolve_user_id


@set_app.command("password")
@handle_cli_errors
def set_password(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    user_id: str = typer.Option(..., "-u", "--user-id", help="User ID or userPrincipalName of the target user (Mandatory)"),
    password: str = typer.Option(..., "-p", "--password", help="New Password for the user (Mandatory)"),
):
    """Change a users password (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"

    user_id = resolve_user_id(headers, url, user_id)
    vprint(f"[dim] Using user id {user_id}")
    
    response = httpx.patch(
        f"{url}/users/{user_id}",
        headers=headers,
        json={
            "passwordProfile":{
                "password": password,
                "forceChangePasswordNextSignIn": False
            }
        }
    )
    vprint(f"[dim] POST {url}/users/{user_id}")
    if response.status_code != 204:
        console.print(f"[bold red][-][/] Failed to change the password: {response.text}")
        raise typer.Exit(1)
    console.print(f"[bold green][+][/] Password for {user_id[0:16]}... successfully changed to {password}")

