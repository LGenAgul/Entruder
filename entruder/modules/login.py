import typer
from rich.console import Console
from entruder.globals import PLANES, RESOURCE_SHORTCUTS, FOCI_CLIENTS
from entruder.utils import build_cert_credential, device_login_v1, device_login_v2, parse_error, parse_token, report_error, request_json, resolve_plane_from_resource, save_session, vprint
import msal

login_app = typer.Typer(help="Login", no_args_is_help=True)
console = Console()

"""
Does Authentication via a secret token, acting as a password and bypassing MFA, used for service principals.
"""
@login_app.command("secret")
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
    try:
        tokens = {}
        resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())

        # initialize the MSAL confidential client application auth flow
        authority = f"https://login.microsoftonline.com/{tenant}"
        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority
        )
        # acquring tokens for each plane, packing them into a dictionary and saving to a session file
        for res in resources:
            plane = resolve_plane_from_resource(res)
            scope = PLANES.get(plane)
            vprint(f"Acquiring {plane} token (scope={scope})")
            result = app.acquire_token_for_client(scopes=[scope])
            if "access_token" in result:
                tokens[plane] = parse_token(result)
                vprint(f"{plane} token expires at {tokens[plane]['expires_at']}")
                console.print(f"[bold green][+][/] {plane.capitalize()} Token acquired successfully!")
                if output_tokens:
                    console.print(f"[bold]Access Token:[/]\n{result['access_token']}\n")
            else:
                console.print(f"[bold red][-][/] Failed to acquire token for {plane.capitalize()}\n{parse_error(result.get('error_description', 'Unknown error'))}\n")
                continue

        # if the tokens dictionary is not empty, save the session
        if tokens:
            save_session(tenant, client_id, tokens)
            console.print(f"[bold green][+][/] Session saved for tenant: {tenant}")

    except typer.Exit:
        raise  
    except Exception as e:
        report_error(e, console)
        raise typer.Exit(1)


@login_app.command("ropc")
def login_ropc(
    tenant: str = typer.Option(..., "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(..., "-clientid", help="Client ID"),
    username: str = typer.Option(..., "-username", help="Username"),
    password: str = typer.Option(..., "-password", help="Password"),
    resource: str = typer.Option(None, "-resource", help="Target resource for the token"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console")):
    """
        Authenticate with username and password via Resource Owner Password Credentials
    """
    try:
        tokens = {}
        resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())
        for res in resources:
            plane = resolve_plane_from_resource(res)
            resource_url = RESOURCE_SHORTCUTS.get(res, res)
            vprint(f"ROPC: requesting {plane} token for {resource_url} as {username}")
            result = request_json(
                "POST",
                f"https://login.microsoftonline.com/{tenant}/oauth2/token",
                data={
                    "grant_type": "password",
                    "client_id": client_id,
                    "username": username,
                    "password": password,
                    "resource": resource_url
                }
            )
            if "access_token" not in result:
                console.print(f"[bold red][-][/] {plane.capitalize()} token failed to acquire: {parse_error(result.get('error_description', 'Unknown error'))}")
                continue

            tokens[plane] = parse_token(result)
            vprint(f"{plane} token expires at {tokens[plane]['expires_at']}")
            console.print(f"[bold green][+][/] {plane.capitalize()} Session saved for tenant: {tenant}")

            if output_tokens:
                console.print(f"[bold]Access Token:[/]\n{tokens[plane]['value']}\n")

        if tokens:
            save_session(tenant, client_id, tokens)
        
        
    except typer.Exit:
        raise  
    except Exception as e:
        report_error(e, console)
        raise typer.Exit(1)

@login_app.command("device")
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
    try:
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
    except typer.Exit:
        raise  
    except Exception as e:
        report_error(e, console)
        raise typer.Exit(1)



@login_app.command("refresh")
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
    try:
        tokens = {}
        resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())
        for res in resources:
            plane = resolve_plane_from_resource(res)
            resource_url = RESOURCE_SHORTCUTS.get(res, res)
            vprint(f"Refreshing {plane} token for {resource_url}")
            result = request_json(
                "POST",
                f"https://login.microsoftonline.com/{tenant}/oauth2/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "refresh_token": refresh_token,
                    "resource": resource_url
                }
            )

            if "access_token" not in result:
                console.print(f"[bold red][-][/] {plane.capitalize()} token failed to acquire: {parse_error(result.get('error_description', 'Unknown error'))}")
                continue

            tokens[plane] = parse_token(result)
            # AAD may rotate the refresh token per request, use the newest one
            if "refresh_token" in result:
                refresh_token = result.get("refresh_token")
                vprint(f"{plane}: refresh token was rotated")
            console.print(f"[bold green][+][/] {plane.capitalize()} Session refreshed for tenant: {tenant}")
            
            if output_tokens:
                console.print(f"[bold]Access Token:[/]\n{tokens[plane]['value']}\n")
        if tokens:
            save_session(tenant, client_id, tokens)
            console.print(f"[bold green][+][/] Session saved for tenant: {tenant}")
    except typer.Exit:
        raise  # let explicit exits (with their own message) through the catch-all
    except Exception as e:
        report_error(e, console)
        raise typer.Exit(1)


@login_app.command("cert")
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
    try:
        tokens = {}
        resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())

        # certificate credentials swap in for a secret; everything else mirrors `login secret`
        authority = f"https://login.microsoftonline.com/{tenant}"
        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=build_cert_credential(cert, key, keypass),
            authority=authority
        )
        # acquiring tokens for each plane, packing them into a dictionary and saving to a session file
        for res in resources:
            plane = resolve_plane_from_resource(res)
            scope = PLANES.get(plane)
            vprint(f"Acquiring {plane} token (scope={scope})")
            result = app.acquire_token_for_client(scopes=[scope])
            if "access_token" in result:
                tokens[plane] = parse_token(result)
                vprint(f"{plane} token expires at {tokens[plane]['expires_at']}")
                console.print(f"[bold green][+][/] {plane.capitalize()} Token acquired successfully!")
                if output_tokens:
                    console.print(f"[bold]Access Token:[/]\n{result['access_token']}\n")
            else:
                console.print(f"[bold red][-][/] Failed to acquire token for {plane.capitalize()}\n{parse_error(result.get('error_description', 'Unknown error'))}\n")
                continue

        # if the tokens dictionary is not empty, save the session
        if tokens:
            save_session(tenant, client_id, tokens)
            console.print(f"[bold green][+][/] Session saved for tenant: {tenant}")

    except typer.Exit:
        raise
    except Exception as e:
        report_error(e, console)
        raise typer.Exit(1)


@login_app.command("foci")
def login_foci(
    tenant:        str = typer.Option(...,  "-tenant",  help="Tenant ID"),
    refresh_token: str = typer.Option(...,  "-token",   help="Refresh token to test across FOCI family"),
    resource:      str = typer.Option(None, "-resource", help="Target resource (Optional, default: all planes)"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console (Optional)"),
):
    try:
        resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())
        family = {}          # client name -> {plane: token} for every accepting client

        for name, client_id in FOCI_CLIENTS.items():
            # FOCI redeems the SAME original refresh token as each family member,
            # independently — never carry a rotated RT across clients
            rt = refresh_token
            client_tokens = {}

            for res in resources:
                plane = resolve_plane_from_resource(res)
                resource_url = RESOURCE_SHORTCUTS.get(res, res)
                vprint(f"FOCI: redeeming RT as {name} ({client_id}) for {plane}")
                result = request_json("POST",
                    f"https://login.microsoftonline.com/{tenant}/oauth2/token",
                    data={
                        "grant_type":    "refresh_token",
                        "client_id":     client_id,
                        "refresh_token": rt,
                        "resource":      resource_url,
                    }
                )

                if "access_token" not in result:
                    # a rejection just means this client is not a family member (or the
                    # plane is unauthorized) — keep sweeping, do not abort
                    vprint(f"{name}/{plane} rejected: {parse_error(result.get('error_description', result.get('error', 'unknown')))}")
                    continue

                token = parse_token(result)
                client_tokens[plane] = token
                # AAD may rotate the RT per redemption; chain the newest one within this client
                if result.get("refresh_token"):
                    rt = result["refresh_token"]
                if output_tokens:
                    console.print(f"[bold]{name} {plane} Access Token:[/]\n{token['value']}\n")

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

        console.print(f"\n[bold]{len(family)}/{len(FOCI_CLIENTS)} FOCI clients accepted the refresh token — sessions saved for tenant: {tenant}[/]")

    except typer.Exit:
        raise
    except Exception as e:
        report_error(e, console)
        raise typer.Exit(1)