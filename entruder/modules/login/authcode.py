import typer

from entruder.utils import (
    auth_code_login,
    csv_to_list,
    handle_cli_errors,
    parse_token,
    resolve_plane_from_scope,
    save_session,
    require_tenant,
    initialize_tenant_cache,
)

from ._shared import login_app, console


@login_app.command("authcode")
@handle_cli_errors
def login_authcode(
    tenant:        str = typer.Option(...,  "-t", "--tenant",       help="Tenant ID (Mandatory here, will be cached upon explicit use)"),
    client_id:     str = typer.Option(...,  "-c", "--client-id",     help="Client ID (Mandatory here, will be cached upon explicit use)"),
    scopes:        str = typer.Option("https://graph.microsoft.com/User.Read", "-p", "--scopes",
                                       help="Comma-separated delegated scopes to request (v2 endpoint, without .default) (Default: 'User.Read')"),
    redirect_uri:  str = typer.Option("http://localhost:8400", "-r", "--redirect-uri",
                                       help="Redirect URI registered on the target app (must match exactly) (Default: 'http://localhost:8400')"),
    client_secret: str = typer.Option(None, "-s", "--secret", help="Client secret, if redeeming as a confidential client (Optional)"),
    code:          str = typer.Option(None, "-d", "--code",
                                       help="Skip the interactive flow and redeem a code captured out-of-band, e.g. via AiTM phishing (Optional)"),
    verifier:      str = typer.Option(None, "-v", "--verifier",
                                       help="PKCE code_verifier to pair with --code (Optional, only if the original request used PKCE)"),
    no_pkce:       bool = typer.Option(False, "-n", "--no-pkce", help="Disable PKCE for the interactive flow (Optional)"),
    no_browser:    bool = typer.Option(False, "-b", "--no-browser", help="Don't auto-open a browser, just print the URL to open manually (Optional)"),
    output_tokens: bool = typer.Option(False, "-o", "--output", help="Output tokens to console (Optional)"),
    user_agent:    str = typer.Option(None, "-u", "--user-agent",
                                       help="Override the User-Agent header sent on the token exchange (Optional, the interactive /authorize leg still goes through your real browser)"),
):
    """
    Authenticate via the OAuth2 authorization code flow (v2 endpoint, PKCE by default).
    """
    tenant =  require_tenant(tenant,console)
    result = auth_code_login(
        tenant, client_id, scopes, redirect_uri,
        client_secret=client_secret,
        code=code,
        verifier=verifier,
        pkce=not no_pkce,
        open_browser=not no_browser,
        user_agent=user_agent,
    )

    plane = resolve_plane_from_scope(csv_to_list(scopes)[0])
    tokens = {plane: parse_token(result)}

    save_session(tenant, client_id, tokens)
    initialize_tenant_cache(tenant, client_id)
    console.print(f"[bold green][+][/] {plane.capitalize()} Session saved for tenant: {tenant}")

    if output_tokens:
        console.print(f"[bold]Access Token:[/]\n{tokens[plane]['value']}\n")
