import typer

from entruder.utils import (
    decode_jwt,
    handle_cli_errors,
    initialize_tenant_cache,
    parse_token,
    resolve_plane_from_resource,
    save_session,
)

from ._shared import login_app, console


@login_app.command("token")
@handle_cli_errors
def login_token(
    token:         str = typer.Option(..., "-token", help="Raw access token obtained out-of-band (e.g. an internal metadata endpoint, a captured request, another tool)"),
    tenant:        str = typer.Option(None, "-tenant", help="Tenant ID (Optional, default: read from the token's tid claim)"),
    client_id:     str = typer.Option(None, "-clientid", help="Client ID to file the session under (Optional, default: read from the token's appid/azp claim)"),
    resource:      str = typer.Option(None, "-resource", help="Plane/resource this token is for, e.g. graph (Optional, default: read from the token's aud claim)"),
    refresh_token: str = typer.Option(None, "-refreshtoken", help="Refresh token to store alongside it, if you have one (Optional)"),
    output_tokens: bool = typer.Option(False, "-output", help="Output the token to console (Optional)"),
):
    """
    Use a previously acquired access token to initialize a session here.
    """
    claims = decode_jwt(token)

    resolved_tenant = tenant or claims.get("tid")
    resolved_client_id = client_id or claims.get("appid") or claims.get("azp")
    aud = resource or claims.get("aud")

    missing = [flag for flag, value in (
        ("-tenant", resolved_tenant),
        ("-clientid", resolved_client_id),
        ("-resource", aud),
    ) if not value]
    if missing:
        console.print(f"[bold red][-][/] Missing {', '.join(missing)} — the token didn't carry a usable claim for it")
        console.print("[dim]Pass whatever's missing explicitly (decoding failed entirely if none of the claims came through — double check the token)[/dim]")
        raise typer.Exit(1)

    if aud.startswith("http") and not aud.endswith("/"):
        aud += "/"
    plane = resolve_plane_from_resource(aud)

    parsed = parse_token({"access_token": token, "refresh_token": refresh_token})
    save_session(resolved_tenant, resolved_client_id, {plane: parsed}, refresh_token=refresh_token)
    initialize_tenant_cache(resolved_tenant, resolved_client_id)

    console.print(f"[bold green][+][/] {plane} session saved for tenant: {resolved_tenant}")
    if parsed.get("upn"):
        console.print(f"[dim]Token belongs to: {parsed['upn']}[/dim]")

    if output_tokens:
        console.print(f"[bold]Access Token:[/]\n{token}\n")
