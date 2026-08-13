from logging import config

import typer
from rich.console import Console
from entruder.globals import PLANES, SESSIONS_DIR
from entruder.helpers import decode_jwt
import msal
import json


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
                claims = decode_jwt(result['access_token'])
                console.print(f"[bold green][+][/] {plane} Token acquired successfully!")
                tokens[plane] = {
                    "value": result['access_token'],
                    "expires_at": claims.get("exp"),
                    "wids": claims.get("wids", [])
                }
                if output_tokens:
                    console.print(f"[bold]Access Token:[/]\n{result['access_token']}\n")
            else:
                console.print(f"[bold red][-][/] Failed to acquire token for {plane}\n{result.get('error_description', 'Unknown error')}\n")

        if tokens:
            session_file = SESSIONS_DIR / f"{tenant}.json"
            session_data = {
                "tenant": tenant,
                "client_id": client_id,
                "tokens": tokens
            }
            with open(session_file, "w") as f:
                console.print(f"[bold green][+][/] Acquired Tokens saved to {session_file}.")
                f.write(json.dumps(session_data, indent=2))

    except Exception as e:
        console.print(e)
        raise typer.Exit(1)


@login_app.command("device")
def login_device(
    tenant: str = typer.Option(..., "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(..., "-clientid", help="Client ID"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console")
):  
    try:
        tokens = {}
        config = {
            "client_id": client_id,
            "scope": ["User.Read"],
        }
        authority = f"https://login.microsoftonline.com/{tenant}"
        app = msal.PublicClientApplication(
            client_id=client_id,
            authority=authority,
            token_cache=msal.SerializableTokenCache()
        )
        result = None
        accounts = app.get_accounts()
        if accounts:
            # Use the first account to acquire a token silently.
            result = app.acquire_token_silent(config["scope"], account=accounts[0])

        if not result:
            # If a token is not available in the cache, use the device flow to acquire a new token.
            flow = app.initiate_device_flow(scopes=config["scope"])
            print(flow["message"])
            result = app.acquire_token_by_device_flow(flow)

        # Use the access token to call the Microsoft Graph API.
        if "access_token" in result:
            access_token = result["access_token"]
            print(access_token)
        else:
            error = result.get("error")
            if error == "invalid_client":
                print("Invalid client ID.Please check your Azure AD application configuration")
            else:
                print(error)    

    except Exception as e:
        console.print(e)
        raise typer.Exit(1)