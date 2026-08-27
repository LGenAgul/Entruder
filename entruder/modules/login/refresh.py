import typer

from entruder.static import RESOURCE_SHORTCUTS
from entruder.utils import (
    acquire_for_resources,
    handle_cli_errors,
    refresh_access_token,
    save_session,
    vprint,
    require_tenant,
    resolve_client_id,
    initialize_tenant_cache,
)

from ._shared import login_app, console


@login_app.command("refresh")
@handle_cli_errors
def login_refresh(
     tenant: str = typer.Option(..., "-t", "--tenant", help="Tenant ID"),
     client_id: str = typer.Option(..., "-c", "--client-id", help="Client ID"),
     refresh_token: str = typer.Option(..., "-o", "--token", help="Refresh Token"),
     resource: str = typer.Option(None, "-r", "--resource", help="Target resource for the token"),
     output_tokens: bool = typer.Option(False, "-u", "--output", help="Output tokens to console"),
     user_agent: str = typer.Option(None, "-a", "--user-agent", help="Override the User-Agent header sent during authentication (Optional)"),
):
    """
    Acquire new access tokens using a refresh token.
    """
    tenant =  require_tenant(tenant,console)
    client_id = resolve_client_id(client_id)
    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())
    headers = {"User-Agent": user_agent} if user_agent else None
    # AAD may rotate the refresh token per request; keep a mutable holder so
    # `acquire` can chain the newest one across resources in this loop
    rt_state = {"token": refresh_token}

    def acquire(plane, res):
        resource_url = RESOURCE_SHORTCUTS.get(res, res)
        result = refresh_access_token(tenant, client_id, rt_state["token"], resource_url, headers=headers)
        if result.get("refresh_token"):
            rt_state["token"] = result["refresh_token"]
            vprint(f"{plane}: refresh token was rotated")
        return result

    tokens = acquire_for_resources(resources, acquire, console, output_tokens=output_tokens)

    if tokens:
        save_session(tenant, client_id, tokens)
        initialize_tenant_cache(tenant, client_id)
        console.print(f"[bold green][+][/] Session saved for tenant: {tenant}")
