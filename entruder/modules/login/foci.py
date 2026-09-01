import typer

from entruder.static import RESOURCE_SHORTCUTS, FOCI_CLIENTS
from entruder.utils import (
    acquire_for_resources,
    handle_cli_errors,
    refresh_access_token,
    save_session,
    vprint,
    require_tenant,
    initialize_tenant_cache,
    get_tenant_cache,
    get_session,
)

from ._shared import login_app, console


@login_app.command("foci")
@handle_cli_errors
def login_foci(
    tenant:        str = typer.Option(None,  "-t", "--tenant",  help="Tenant ID (will be cached upon explicit use)"),
    refresh_token: str = typer.Option(None,  "-o", "--token",   help="Refresh token to test across FOCI family (defaults to the active session's saved refresh token)"),
    resource:      str = typer.Option(None, "-r", "--resource", help="Target resource (Optional, default: all planes)"),
    output_tokens: bool = typer.Option(False, "-u", "--output", help="Output tokens to console (Optional)"),
    user_agent:    str = typer.Option(None, "-a", "--user-agent", help="Override the User-Agent header sent during authentication (Optional)"),
):
    """Use the Microsoft Family of Client IDs to acquire a Family Refresh Token (FRT)"""
    if refresh_token is None:
        session_tenant, session_client_id = get_tenant_cache(tenant, None)
        session = get_session(session_tenant, session_client_id) if session_tenant and session_client_id else {}
        refresh_token = session.get("refresh_token")
        if not refresh_token:
            console.print("[bold red][-][/] No --token provided and no active session with a saved refresh token was found")
            console.print("[dim] Pass --token explicitly, or run a login command first to set an active session[/dim]")
            raise typer.Exit(1)
        tenant = tenant or session_tenant
        console.print(f"[dim][*] Using refresh token from active session ({session_tenant} / {session_client_id})[/dim]")

    tenant =  require_tenant(tenant,console)
    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())
    headers = {"User-Agent": user_agent} if user_agent else None
    family = {}
    # AAD rotates the RT on every redemption, invalidating whatever was passed
    # in — chain the newest one across every client/plane, not just within one
    # client's own loop, or every client after the first fails with a stale RT.
    rt_state = {"token": refresh_token}

    for name, client_id in FOCI_CLIENTS.items():

        def acquire(plane, res, name=name, client_id=client_id):
            resource_url = RESOURCE_SHORTCUTS.get(res, res)
            vprint(f"FOCI: redeeming RT as {name} ({client_id}) for {plane}")
            result = refresh_access_token(tenant, client_id, rt_state["token"], resource_url, headers=headers)
            if result.get("refresh_token"):
                rt_state["token"] = result["refresh_token"]
            return result

        client_tokens = acquire_for_resources(
            resources, acquire, console,
            output_tokens=output_tokens, label=f"{name} ({client_id})",
        )

        if client_tokens:
            family[name] = client_tokens
            # each family member is a distinct identity — save it under its own
            # client_id so the per-identity session files don't overwrite each other
            save_session(tenant, client_id, client_tokens)
            # last accepted family member wins as the active session, consistent
            # with "whatever you just successfully logged in as" everywhere else
            initialize_tenant_cache(tenant, client_id)
            console.print(f"[bold green][+][/] {name} ({client_id}) accepted — planes: {', '.join(client_tokens)}")
        else:
            console.print(f"[dim][-] {name} rejected the token[/dim]")

    if not family:
        console.print(f"[bold red][-][/] Not a FOCI refresh token — no family client accepted it")
        raise typer.Exit(1)

    console.print(f"\n[bold]{len(family)}/{len(FOCI_CLIENTS)} FOCI clients accepted the refresh token, sessions saved for tenant: {tenant}[/]")
    last_accepted = FOCI_CLIENTS[next(reversed(family))]
    console.print(f"[dim]Active session set: tenant={tenant}, client_id={last_accepted}[/dim]")
