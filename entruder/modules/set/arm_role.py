import uuid
import typer
import httpx
from entruder.static import API_VERSIONS, WELL_KNOWN_ARM_ROLES
from entruder.utils import (
    handle_cli_errors,
    vprint
)

from ._shared import set_app, console, prepare_session, resolve_user_id


@set_app.command("arm-role")
@handle_cli_errors
def set_arm_role(
    tenant: str = typer.Option(None, "--tenant", "-t", help="Tenant ID"),
    client_id: str = typer.Option(None, "--clientid", "-c", help="Client ID"),
    sub: str = typer.Option(..., "--sub", "-s", help="Subscription ID"),
    rg: str = typer.Option(None, "--resource-group", "-rg", help="Resource group (optional, omit for subscription scope)"),
    resource: str = typer.Option(None, "--resource", "-res", help="Resource path relative to the resource group, e.g. 'Microsoft.Storage/storageAccounts/mystorageacct' (requires --resource-group)"),
    user_id: str = typer.Option(..., "--userid", "-u", help="User ID or UPN to assign the role to"),
    role: str = typer.Option(..., "--role", "-r", help="Role definition ID or well-known name (e.g. 'Contributor', 'Owner', 'Reader')"),
):
    """Assign an Azure RBAC role to a user at subscription, resource group, or individual resource scope (requires a management token)"""
    tenant, headers = prepare_session(tenant, client_id, "management")


    _, graph_headers = prepare_session(tenant, client_id, "graph")
    graph_url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"
    user_id = resolve_user_id(graph_headers, graph_url, user_id)

    role_id = WELL_KNOWN_ARM_ROLES.get(role.lower().replace(" ", "")) or role

    if resource and not rg:
        console.print("[bold red][-][/] --resource requires --resource-group")
        raise typer.Exit(1)

    # Build scope
    scope = f"/subscriptions/{sub}"
    if rg:
        scope += f"/resourceGroups/{rg}"
    if resource:
        scope += f"/providers/{resource}"

    # Generate unique role assignment name
    assignment_name = str(uuid.uuid4())
    assignment_url = (
        f"https://management.azure.com{scope}/providers/"
        f"Microsoft.Authorization/roleAssignments/{assignment_name}"
    )

    vprint(f"PUT {assignment_url}")
    response = httpx.put(
        assignment_url,
        headers=headers,
        params={"api-version": API_VERSIONS["authorization"]},
        json={
            "properties": {
                "roleDefinitionId": f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{role_id}",
                "principalId": user_id
            }
        }
    )

    if response.status_code == 409:
        console.print(f"[bold yellow][!][/] Role assignment already exists for {user_id}")
        return

    if response.status_code not in (200, 201):
        console.print(f"[bold red][-][/] Failed to assign role: {response.status_code} {response.text}")
        raise typer.Exit(1)

    if resource:
        scope_desc = f"resource {resource}"
    elif rg:
        scope_desc = f"resource group {rg}"
    else:
        scope_desc = f"subscription {sub}"
    console.print(f"[bold green][+][/] Successfully assigned {role} to {user_id} on {scope_desc}")