import typer
from rich.console import Console
from entruder.globals import PLANES, RESOURCE_SHORTCUTS
from entruder.utils import csv_to_list, parse_error, parse_token, report_error, request_json, resolve_plane_from_resource, save_session, vprint
import msal
import time

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



# temporarly store auth functions here
def device_login_v1(resource, tenant, client_id) -> dict:
    """
    Authenticate using device code flow for v1 endpoint, done directly via raw http requests.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/103.0.0.0 Safari/537.36"
    }
    resource_url = RESOURCE_SHORTCUTS.get(resource, resource)
    # Initialize device code flow to receive the user code
    initial_response = request_json(
            "POST",
            f"https://login.microsoftonline.com/{tenant}/oauth2/devicecode",
            params={"api-version": "1.0"},
            data={
                "client_id": client_id,
                "resource": resource_url
            },
            headers=headers
        )

    if "user_code" not in initial_response:
        console.print(f"[bold red][-][/] Failed to initiate device code flow: {parse_error(initial_response.get('error_description', 'Unknown error'))}")
        raise typer.Exit(1)

    interval = int(initial_response.get("interval", 5))
    device_code = initial_response["device_code"]
    # the device code is only valid for a limited window, stop polling once it expires
    deadline = time.monotonic() + int(initial_response.get("expires_in", 900))

    console.print(f"{initial_response['message']}")
    vprint(f"Polling every {interval}s for up to {int(deadline - time.monotonic())}s")

    # wait for the user to authenticate and poll for the access token
    result = None
    while time.monotonic() < deadline:
        time.sleep(interval)
        result = request_json(
            "POST",
            f"https://login.microsoftonline.com/{tenant}/oauth2/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "resource": resource_url,
                "code": device_code
            },
            headers=headers
        )

        if "access_token" in result:
            return result

        if "error" in result:
            error = result["error"]
            if error == "authorization_pending":
                vprint("authorization_pending — user has not completed sign-in yet")
                continue
            elif error == "slow_down":
                # AAD is telling us to back off, increase the interval as required
                interval += 5
                vprint(f"slow_down — backing off, interval now {interval}s")
                continue
            else:
                console.print(f"[bold red][-][/] Error during token acquisition: {parse_error(result.get('error_description', 'Unknown error'))}")
                raise typer.Exit(1)

    console.print("[bold red][-][/] Device code expired before authentication completed.")
    raise typer.Exit(1)
        
    



def device_login_v2(tenant, client_id, scopes) -> dict:
    """
    Authenticate using device code flow for v2 endpoint, using MSAL library for handling the flow.
    """
    app = msal.PublicClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant}")

    vprint(f"Initiating v2 device flow (scopes={csv_to_list(scopes)})")
    flow = app.initiate_device_flow(scopes=csv_to_list(scopes))
    if "user_code" not in flow:
        console.print(f"[bold red][-][/] Failed to initiate device code flow: {parse_error(flow.get('error_description', 'Unknown error'))}")
        raise typer.Exit(1)

    console.print(f"\n[bold yellow][*][/] {flow['message']}\n")

    result = app.acquire_token_by_device_flow(flow)

    if "access_token" not in result:
        console.print(f"[bold red][-][/] Error during token acquisition: {parse_error(result.get('error_description', 'Unknown error'))}")
        raise typer.Exit(1)

    return result



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
    resource:  str = typer.Option(None, "-resource", help="Target resource (Optional, default: all planes)"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console (Optional)"),
):
    """
    Authenticate using client certificate (certificate-based auth)
    """
