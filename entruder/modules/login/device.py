import typer

from entruder.utils import (
    device_login_v1,
    device_login_v2,
    handle_cli_errors,
    parse_token,
    resolve_plane_from_resource,
    save_session,
    initialize_tenant_cache,
)

from ._shared import login_app, console


@login_app.command("device")
@handle_cli_errors
def login_device(
    v2: bool = typer.Option(False, "-v2", help="Use v2 endpoint with scopes instead of resource, required for some tenants"),
    scopes: str = typer.Option("User.Read", "-scopes", help="Scopes for v2 endpoint, comma-separated"),
    tenant: str = typer.Option(..., "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(..., "-clientid", help="Client ID"),
    resource: str = typer.Option("https://graph.microsoft.com/", "-resource", help="Resource ID"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console"),
    user_agent: str = typer.Option(None, "-useragent", help="Override the User-Agent header sent during authentication (Optional)"),

):
    """
    Authenticate via device code flow. Default flow is v1, with -v2 for scope-based flow
    """
    tokens = {}
    if v2:
        plane = "graph"
        tokens[plane] = parse_token(device_login_v2(tenant, client_id, scopes, user_agent=user_agent))
    else:
        plane = resolve_plane_from_resource(resource)
        tokens[plane] = parse_token(device_login_v1(resource, tenant, client_id, user_agent=user_agent))

    # continue with session write logic after these
    if tokens:
        save_session(tenant, client_id, tokens)
        initialize_tenant_cache(tenant, client_id)
        console.print(f"[bold green][+][/] {plane.capitalize()} Session saved for tenant: {tenant}")

    if output_tokens:
        console.print(f"[bold]Access Token:[/]\n{tokens[plane]['value']}\n")
