import typer
import httpx
from entruder.static import API_VERSIONS, MSGRAPH_SP_ID
from entruder.utils import (
    handle_cli_errors,
    OutputFormat,
    output_option,
    vprint
)

from ._shared import set_app, console, prepare_session, resolve_user_id, resolve_group_id, resolve_app_role_id


@set_app.command("app-role")
@handle_cli_errors
def set_app_role(
    tenant: str = typer.Option(None, "--tenant", "-t", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "--clientid", "-c", help="Client ID (will be cached upon explicit use)"),
    user_id: str = typer.Option(None, "--userid", "-u", help="User ID or UPN to assign the role to (Mandatory if --spid is not provided)"),
    sp_id: str = typer.Option(None, "--spid", "-s", help="Service Principal ID to assign the role to (Mandatory if --userid is not provided)"),
    resource_id: str = typer.Option(None, "--resourceid", "-r", help="Resource Service Principal ID (the app that defines the role); defaults to MS Graph's own SP"),
    role_id: str = typer.Option(..., "--roleid", "-R", help="App Role ID to assign, or a well-known MS Graph app role name (e.g. Mail.ReadWrite.All)"),
):
    """Assign an app role to a user or service principal (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")
    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"

    if not user_id and not sp_id:
        console.print("[bold red][-][/] Either --userid or --spid must be provided")
        raise typer.Exit(1)

    resource_id = resource_id or MSGRAPH_SP_ID
    role_id = resolve_app_role_id(role_id)

    vprint(f"Using resource id: {resource_id} and role id: {role_id}")
    # Resolve principal
    if user_id:
        principal_id = resolve_user_id(headers, url, user_id)
        endpoint = f"{url}/users/{principal_id}/appRoleAssignments"
    else:
        principal_id = sp_id
        endpoint = f"{url}/servicePrincipals/{principal_id}/appRoleAssignments"

    vprint(f"resolved principal id to {principal_id}")

    data = {
            "principalId": principal_id,
            "resourceId": resource_id,
            "appRoleId": role_id
        }
    response = httpx.post(
        endpoint,
        headers=headers,
        json = data
    )
    vprint(f"POST {endpoint}")
    vprint(f"with json body: {data}")

    if response.status_code == 201:
        console.print(f"[bold green][+][/] Successfully assigned app role {role_id} to {principal_id[0:16]}...")
    elif response.status_code == 400 and "already exist" in response.text.lower():
        console.print(f"[bold yellow][!][/] Principal already has this app role assigned")
    else:
        console.print(f"[bold red][-][/] Failed to assign app role: {response.status_code} {response.text}")
        raise typer.Exit(1)

