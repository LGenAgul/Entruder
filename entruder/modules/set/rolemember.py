import typer
import httpx
from entruder.static import API_VERSIONS
from entruder.utils import (
    handle_cli_errors,
    OutputFormat,
    output_option,
)

from ._shared import set_app, console, prepare_session, resolve_user_id, resolve_role_id


@set_app.command("role-member")
@handle_cli_errors
def set_roleMember(
    tenant: str = typer.Option(None,    "-t", "--tenant"   , help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    role_id: str = typer.Option(...,    "-r", "--role-id"  , help="Role ID or display name to assign (e.g. 'Global Administrator')"),
    user_id: str = typer.Option(...,    "-u", "--user-id"  , help="User ID or UPN of the user to add"),
    scope: str = typer.Option("/",      "-s", "--scope"    , help="Assignment scope (default: tenant-wide)"),
    output: OutputFormat = output_option(),
):
    """Add a user to a directory role"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"

    user_id = resolve_user_id(headers, url, user_id)
    role_id = resolve_role_id(headers, url, role_id)

    response = httpx.post(
        f"{url}/roleManagement/directory/roleAssignments",
        headers=headers,
        json={
            "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
            "roleDefinitionId": role_id,
            "principalId": user_id,
            "directoryScopeId": scope
        }
    )

    if response.status_code == 201:
        console.print(f"[bold green][+][/] Successfully assigned role {role_id} to {user_id[0:16]}...")
    elif response.status_code == 400 and "already exist" in response.text.lower():
        console.print(f"[bold yellow][!][/] {user_id[0:16]}... already has role {role_id}")
    else:
        console.print(f"[bold red][-][/] Failed to assign role: {response.status_code} {response.text}")
        raise typer.Exit(1)

