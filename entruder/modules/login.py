import typer
from rich.console import Console
from entruder.globals import PLANES, RESOURCE_SHORTCUTS, FOCI_CLIENTS
from entruder.utils import (
    acquire_for_resources,
    auth_code_login,
    build_cert_credential,
    csv_to_list,
    device_login_v1,
    device_login_v2,
    handle_cli_errors,
    parse_token,
    request_json,
    resolve_plane_from_resource,
    resolve_plane_from_scope,
    save_session,
    vprint,
    require_tenant
)
import msal
import os

login_app = typer.Typer(help="Login", no_args_is_help=True)
console = Console()

"""
Does Authentication via a secret token, acting as a password and bypassing MFA, used for service principals.
"""
@login_app.command("secret")
@handle_cli_errors
def login_secret(
    tenant: str = typer.Option(..., "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(..., "-clientid", help="Client ID"),
    client_secret: str = typer.Option(..., "-secret", help="Client Secret"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console"),
    resource: str = typer.Option(None, "-resource", help="Target resource for the token"),
):
    """
    Authenticate with a Service Principal's client credentials, via a client ID and a secret
    """
    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())

    # initialize the MSAL confidential client application auth flow
    authority = f"https://login.microsoftonline.com/{tenant}"
    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=authority
    )

    def acquire(plane, res):
        scope = PLANES.get(plane)
        vprint(f"Acquiring {plane} token (scope={scope})")
        return app.acquire_token_for_client(scopes=[scope])

    tokens = acquire_for_resources(resources, acquire, console, output_tokens=output_tokens)

    # if the tokens dictionary is not empty, save the session
    if tokens:
        save_session(tenant, client_id, tokens)
        console.print(f"[bold green][+][/] Session saved for tenant: {tenant}")


@login_app.command("ropc")
@handle_cli_errors
def login_ropc(
    tenant: str = typer.Option(..., "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(..., "-clientid", help="Client ID"),
    username: str = typer.Option(..., "-upn", help="Username"),
    password: str = typer.Option(..., "-password", help="Password"),
    resource: str = typer.Option(None, "-resource", help="Target resource for the token"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console")):
    """
        Authenticate with username and password via Resource Owner Password Credentials
    """
    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())
    resolved_tenant = require_tenant(tenant,console)
    def acquire(plane, res):
        resource_url = RESOURCE_SHORTCUTS.get(res, res)
        vprint(f"ROPC: requesting {plane} token for {resource_url} as {username}")
        return request_json(
            "POST",
            f"https://login.microsoftonline.com/{resolved_tenant}/oauth2/token",
            data={
                "grant_type": "password",
                "client_id": client_id,
                "username": username,
                "password": password,
                "resource": resource_url
            }
        )

    tokens = acquire_for_resources(resources, acquire, console, output_tokens=output_tokens)

    if tokens:
        save_session(resolved_tenant, client_id, tokens)
        console.print(f"[bold green][+][/] Session saved for tenant: {resolved_tenant}")


@login_app.command("device")
@handle_cli_errors
def login_device(
    v2: bool = typer.Option(False, "-v2", help="Use v2 endpoint with scopes instead of resource, required for some tenants"),
    scopes: str = typer.Option("User.Read", "-scopes", help="Scopes for v2 endpoint, comma-separated"),
    tenant: str = typer.Option(..., "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(..., "-clientid", help="Client ID"),
    resource: str = typer.Option("https://graph.microsoft.com/", "-resource", help="Resource ID"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console")

):
    """
    Authenticate via device code flow. Default flow is v1, with -v2 for scope-based flow
    """
    # a single interactive poll producing exactly one token, not a per-resource
    # sweep like the other flows — doesn't fit acquire_for_resources
    tokens = {}
    if v2:
        plane = "graph"
        tokens[plane] = parse_token(device_login_v2(tenant, client_id, scopes))
    else:
        plane = resolve_plane_from_resource(resource)
        tokens[plane] = parse_token(device_login_v1(resource, tenant, client_id))

    # continue with session write logic after these
    if tokens:
        save_session(tenant, client_id, tokens)
        console.print(f"[bold green][+][/] {plane.capitalize()} Session saved for tenant: {tenant}")
    if output_tokens:
        console.print(f"[bold]Access Token:[/]\n{tokens[plane]['value']}\n")


@login_app.command("refresh")
@handle_cli_errors
def login_refresh(
     tenant: str = typer.Option(..., "-tenant", help="Tenant ID"),
     client_id: str = typer.Option(..., "-clientid", help="Client ID"),
     refresh_token: str = typer.Option(..., "-token", help="Refresh Token"),
     resource: str = typer.Option(None, "-resource", help="Target resource for the token"),
     output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console")
):
    """
    Acquire new access tokens using a refresh token.
    """
    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())
    # AAD may rotate the refresh token per request; keep a mutable holder so
    # `acquire` can chain the newest one across resources in this loop
    rt_state = {"token": refresh_token}

    def acquire(plane, res):
        resource_url = RESOURCE_SHORTCUTS.get(res, res)
        vprint(f"Refreshing {plane} token for {resource_url}")
        result = request_json(
            "POST",
            f"https://login.microsoftonline.com/{tenant}/oauth2/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": rt_state["token"],
                "resource": resource_url
            }
        )
        if result.get("refresh_token"):
            rt_state["token"] = result["refresh_token"]
            vprint(f"{plane}: refresh token was rotated")
        return result

    tokens = acquire_for_resources(resources, acquire, console, output_tokens=output_tokens)

    if tokens:
        save_session(tenant, client_id, tokens)
        console.print(f"[bold green][+][/] Session saved for tenant: {tenant}")


@login_app.command("cert")
@handle_cli_errors
def login_cert(
    tenant:    str = typer.Option(...,  "-tenant",   help="Tenant ID"),
    client_id: str = typer.Option(...,  "-clientid", help="Client ID"),
    cert:      str = typer.Option(...,  "-cert",     help="Path to certificate file (.pem/.crt)"),
    key:       str = typer.Option(...,  "-key",      help="Path to private key file (.pem)"),
    keypass:   str = typer.Option(None, "-keypass",  help="Passphrase for an encrypted private key (Optional)"),
    resource:  str = typer.Option(None, "-resource", help="Target resource (Optional, default: all planes)"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console (Optional)"),
):
    """
    Authenticate with a Service Principal's client certificate (certificate-based auth)
    """
    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())

    # certificate credentials swap in for a secret; everything else mirrors `login secret`
    authority = f"https://login.microsoftonline.com/{tenant}"
    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=build_cert_credential(cert, key, keypass),
        authority=authority
    )

    def acquire(plane, res):
        scope = PLANES.get(plane)
        vprint(f"Acquiring {plane} token (scope={scope})")
        return app.acquire_token_for_client(scopes=[scope])

    tokens = acquire_for_resources(resources, acquire, console, output_tokens=output_tokens)

    # if the tokens dictionary is not empty, save the session
    if tokens:
        save_session(tenant, client_id, tokens)
        console.print(f"[bold green][+][/] Session saved for tenant: {tenant}")


@login_app.command("foci")
@handle_cli_errors
def login_foci(
    tenant:        str = typer.Option(...,  "-tenant",  help="Tenant ID"),
    refresh_token: str = typer.Option(...,  "-token",   help="Refresh token to test across FOCI family"),
    resource:      str = typer.Option(None, "-resource", help="Target resource (Optional, default: all planes)"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console (Optional)"),
):
    """Use the Microsoft Family of Client IDs to acquire a Family Refresh Token (FRT)"""
    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())
    family = {}

    for name, client_id in FOCI_CLIENTS.items():
        # AAD may rotate the RT per redemption; chain the newest one within this client
        rt_state = {"token": refresh_token}

        def acquire(plane, res, name=name, client_id=client_id):
            resource_url = RESOURCE_SHORTCUTS.get(res, res)
            vprint(f"FOCI: redeeming RT as {name} ({client_id}) for {plane}")
            result = request_json("POST",
                f"https://login.microsoftonline.com/{tenant}/oauth2/token",
                data={
                    "grant_type":    "refresh_token",
                    "client_id":     client_id,
                    "refresh_token": rt_state["token"],
                    "resource":      resource_url,
                }
            )
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
            console.print(f"[bold green][+][/] {name} ({client_id}) accepted — planes: {', '.join(client_tokens)}")
        else:
            console.print(f"[dim][-] {name} rejected the token[/dim]")

    if not family:
        console.print(f"[bold red][-][/] Not a FOCI refresh token — no family client accepted it")
        raise typer.Exit(1)

    console.print(f"\n[bold]{len(family)}/{len(FOCI_CLIENTS)} FOCI clients accepted the refresh token, sessions saved for tenant: {tenant}[/]")


@login_app.command("kerberos")
@handle_cli_errors
def login_kerberos(
        tenant:        str = typer.Option(...,  "-tenant",  help="Tenant ID"),
        client_id: str = typer.Option(...,  "-clientid", help="Client ID"),
        ccache: str = typer.Option(None,  "-ccache", help="The Kerberos ticket cache file needed for authentication (By Default will extract the $KRB5CCNAME environment variable)"),
        domain: str = typer.Option(...,  "-domain",   help="AD domain (e.g. test.local)"),
        resource:  str = typer.Option(None, "-resource", help="Target resource (Optional, default: all planes)"),
        output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console (Optional)"),
):
    """Authenticate using Kerberos ticket via Seamless SSO (pass-the-ticket)"""
    # resolve the ccache and assign it to the KRB5CCNAME env variable
    if ccache:
        ccache = os.path.realpath(ccache)
        if not os.path.exists(ccache):
            console.print(f"[bold red][-][/] ccache file not found: {ccache}")
            raise typer.Exit(1)
        os.environ["KRB5CCNAME"]=f"FILE:{ccache}"

    from entruder.utils.kerberos import get_kerberos_service_ticket
    spn = f"HTTP/autologon.microsoftazuread-sso.com@{domain.upper()}"
    service_ticket = get_kerberos_service_ticket(spn)

    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())

    def acquire(plane, res):
        resource_url = RESOURCE_SHORTCUTS.get(res, res)
        return request_json("POST",
                              f"https://login.microsoftonline.com/{tenant}/oauth2/token",
                              data={
                                  "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                  "client_id":  client_id,
                                  "resource":   resource_url,
                                  "assertion":  service_ticket,
                                  "client_info": 1,
                              })

    
    tokens = acquire_for_resources(resources, acquire, console, output_tokens=output_tokens)
    
    if tokens:
        save_session(tenant, client_id, tokens)
        console.print(f"\n[bold green][+][/] Session saved for tenant: {tenant}")
    else:
        console.print(f"\n[bold red][-][/] No tokens acquired")
        raise typer.Exit(1)


@login_app.command("authcode")
@handle_cli_errors
def login_authcode(
    tenant:        str = typer.Option(...,  "-tenant",       help="Tenant ID"),
    client_id:     str = typer.Option(...,  "-clientid",     help="Client ID"),
    scopes:        str = typer.Option("https://graph.microsoft.com/User.Read", "-scopes",
                                       help="Comma-separated delegated scopes to request (v2 endpoint); openid/profile/offline_access are appended automatically. Don't use .default here — that's for app-only grants (see `login secret`/`login cert`), and AAD rejects it mixed with other scopes"),
    redirect_uri:  str = typer.Option("http://localhost:8400", "-redirecturi",
                                       help="Redirect URI registered on the target app (must match exactly)"),
    client_secret: str = typer.Option(None, "-secret", help="Client secret, if redeeming as a confidential client (Optional)"),
    code:          str = typer.Option(None, "-code",
                                       help="Skip the interactive flow and redeem a code captured out-of-band, e.g. via AiTM phishing (Optional)"),
    verifier:      str = typer.Option(None, "-verifier",
                                       help="PKCE code_verifier to pair with -code (Optional, only if the original request used PKCE)"),
    no_pkce:       bool = typer.Option(False, "-nopkce", help="Disable PKCE for the interactive flow (Optional)"),
    no_browser:    bool = typer.Option(False, "-nobrowser", help="Don't auto-open a browser, just print the URL to open manually (Optional)"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console (Optional)"),
):
    """
    Authenticate via the OAuth2 authorization code flow (v2 endpoint, PKCE by default).
    """
    result = auth_code_login(
        tenant, client_id, scopes, redirect_uri,
        client_secret=client_secret,
        code=code,
        verifier=verifier,
        pkce=not no_pkce,
        open_browser=not no_browser,
    )

    plane = resolve_plane_from_scope(csv_to_list(scopes)[0])
    tokens = {plane: parse_token(result)}

    save_session(tenant, client_id, tokens)
    console.print(f"[bold green][+][/] {plane.capitalize()} Session saved for tenant: {tenant}")
    if output_tokens:
        console.print(f"[bold]Access Token:[/]\n{tokens[plane]['value']}\n")
