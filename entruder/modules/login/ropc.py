import typer

from entruder.static import RESOURCE_SHORTCUTS
from entruder.utils import (
    acquire_for_resources,
    handle_cli_errors,
    request_json,
    save_session,
    vprint,
    require_tenant,
    resolve_client_id,
    initialize_tenant_cache,
)

from ._shared import login_app, console


@login_app.command("ropc")
@handle_cli_errors
def login_ropc(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(..., "-c", "--client-id", help="Client ID (Mandatory here, will be cached upon explicit use)"),
    username: str = typer.Option(..., "-u", "--upn", help="Username (userPrincipalName/email) of the target user (Mandatory)"),
    password: str = typer.Option(..., "-p", "--password", help="Password (Mandatory)"),
    resource: str = typer.Option(None, "-r", "--resource", help="Target resource for the token (Optional, default: all planes)"),
    output_tokens: bool = typer.Option(False, "-o", "--output", help="Output tokens to console (Optional)"),
    user_agent: str = typer.Option(None, "-a", "--user-agent", help="Override the User-Agent header sent during authentication (Optional)")):
    """
        Authenticate with username and password via Resource Owner Password Credentials
    """
    tenant =  require_tenant(tenant,console)
    client_id = resolve_client_id(client_id)

    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())
    headers = {"User-Agent": user_agent} if user_agent else None
    def acquire(plane, res):
        resource_url = RESOURCE_SHORTCUTS.get(res, res)
        vprint(f"ROPC: requesting {plane} token for {resource_url} as {username}")
        return request_json(
            "POST",
            f"https://login.microsoftonline.com/{tenant}/oauth2/token",
            data={
                "grant_type": "password",
                "client_id": client_id,
                "username": username,
                "password": password,
                "resource": resource_url
            },
            headers=headers,
        )

    tokens = acquire_for_resources(resources, acquire, console, output_tokens=output_tokens)

    if tokens:
        save_session(tenant, client_id, tokens)
        initialize_tenant_cache(tenant, client_id)
        console.print(f"[bold green][+][/] Session saved for tenant: {tenant}")
