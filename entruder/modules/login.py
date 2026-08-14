import typer
from rich.console import Console
from entruder.globals import PLANES, RESOURCE_SHORTCUTS, SESSIONS_DIR
from entruder.helpers import csv_to_list, parse_token, resolve_plane_from_resource, resolve_resource, save_session
import msal
import json
import httpx
import time

login_app = typer.Typer(help="Login", no_args_is_help=True)
console = Console()

@login_app.command("token")
def login_tenant(
    tenant: str = typer.Option(..., "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(..., "-clientid", help="Client ID"),
    client_secret: str = typer.Option(..., "-secret", help="Client Secret"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console")
):  
    try:
        tokens = {}
        console.print(f"[bold green][+][/] Attempting to acquire token for tenant: {tenant}\n")

        # initialize the MSAL confidential client application auth flow
        authority = f"https://login.microsoftonline.com/{tenant}"
        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority
        )
        # acquring tokens for each plane, packing them into a dictionary and saving to a session file
        for plane, scope in PLANES.items():
            result = app.acquire_token_for_client(scopes=[scope])
            if "access_token" in result: 
                tokens[plane] = parse_token(result)
                console.print(f"[bold green][+][/] {plane.capitalize()} Token acquired successfully!")
                if output_tokens:
                    console.print(f"[bold]Access Token:[/]\n{result['access_token']}\n")
            else:
                console.print(f"[bold red][-][/] Failed to acquire token for {plane.capitalize()}\n{result.get('error_description', 'Unknown error')}\n")

        # if the tokens dictionary is not empty, save the session
        if tokens:
            save_session(tenant, client_id, tokens)
            console.print(f"[bold green][+][/] Session saved for tenant: {tenant}\n")

    except Exception as e:
        console.print(e)
        raise typer.Exit(1)


@login_app.command("device")
def login_device(
    resource: str = typer.Option("https://graph.microsoft.com/", "-resource", help="Resource ID"),
    v2: bool = typer.Option(False, "-v2", help="Use v2 endpoint with scopes instead of resource, required for some tenants"),
    scopes: str = typer.Option("User.Read", "-scopes", help="Scopes for v2 endpoint, comma-separated"),
    tenant: str = typer.Option(..., "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(..., "-clientid", help="Client ID"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console")

):  
    try:
        tokens = {}
        if v2:
            plane = "graph"
            tokens[plane] = parse_token(device_login_v2(tenant, client_id, scopes))
        else:
            plane = resolve_plane_from_resource(resource)
            tokens[plane] = parse_token(device_login_v1(resource, tenant, client_id))

        # continue with session write logic after these
        save_session(tenant, client_id, tokens)
        console.print(f"[bold green][+][/] Session saved for tenant: {tenant}\n")
    except Exception as e:
        console.print(e)
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
    initial_response = httpx.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/devicecode",
            params={"api-version": "1.0"},
            data={
                "client_id": client_id,
                "resource": resource_url
            },
            headers=headers
        ).json()

    if "user_code" not in initial_response:
        console.print(f"[bold red][-][/] Failed to initiate device code flow: {initial_response.get('error_description', 'Unknown error')}")
        raise typer.Exit(1)

    interval = int(initial_response.get("interval", 5))
    device_code = initial_response["device_code"]

    console.print(f"{initial_response['message']}")

    # wait for the user to authenticate and poll for the access token
    result = None
    while True:
        time.sleep(interval)
        result = httpx.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "resource": resource_url,
                "code": device_code
            },
            headers=headers
        ).json()

        if "access_token" in result:
            return result
        
        if "error" in result:
            if result["error"] == "authorization_pending":
                continue
            else:
                console.print(f"[bold red][-][/] Error during token acquisition: {result.get('error_description', 'Unknown error')}")
                raise typer.Exit(1)
        
    



def device_login_v2(tenant, client_id, scopes) -> dict:
    """
    Authenticate using device code flow for v2 endpoint, done directly via raw http requests.
    """
    app = msal.PublicClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant}")

    flow = app.initiate_device_flow(scopes=csv_to_list(scopes))
    if "user_code" not in flow:
        console.print(f"[bold red][-][/] Failed to initiate device code flow: {flow.get('error_description', 'Unknown error')}")
        raise typer.Exit(1)

    console.print(f"\n[bold yellow][*][/] {flow['message']}\n")

    result = app.acquire_token_by_device_flow(flow)

    if "access_token" not in result:
        console.print(f"[bold red][-][/] Error during token acquisition: {result.get('error_description', 'Unknown error')}")
        raise typer.Exit(1)

    return result

    