import typer
import httpx
from entruder.static import API_VERSIONS, CACHE_DIR
from entruder.utils import (
    handle_cli_errors,
    OutputFormat,
    output_option,
    vprint
)

from ._shared import set_app, console, prepare_session, resolve_user_id, resolve_group_id, resolve_app_role_id
from json import dumps

@set_app.command("app-secret")
@handle_cli_errors
def set_app_secret(
    tenant: str = typer.Option(None, "--tenant", "-t", help="Tenant ID"),
    client_id: str = typer.Option(None, "--clientid", "-c", help="Client ID"),
    app_id: str = typer.Option(..., "--appid", "-a", help="Application object ID to add the secret to"),
    description: str = typer.Option("backup", "--description", "-d", help="Secret display name"),
    years: int = typer.Option(1, "--years", "-y", help="Secret lifetime in years"),
    write: bool = typer.Option(True, "--write", "-w", help="Write secret to cache directory")
):
    """Add a client secret to an application. Enables authentication as that app's service principal (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")
    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"

    from datetime import datetime, timezone, timedelta
    end_datetime = (datetime.now(timezone.utc) + timedelta(days=365 * years)).strftime("%Y-%m-%dT%H:%M:%SZ")

    vprint(f"POST {url}/applications/{app_id}/addPassword")
    response = httpx.post(
        f"{url}/applications/{app_id}/addPassword",
        headers=headers,
        json={
            "passwordCredential": {
                "displayName": description,
                "endDateTime": end_datetime
            }
        }
    )

    if response.status_code != 200:
        console.print(f"[bold red][-][/] Failed to add secret: {response.status_code} {response.text}")
        raise typer.Exit(1)
    
    data = response.json()
    secret_value = data.get("secretText")
    key_id = data.get("keyId")
    expiry = data.get("endDateTime")

    console.print(f"[bold green][+][/] Client secret added successfully")
    console.print(f"[bold green] App ID:  {app_id}[/]")
    console.print(f"[bold green] Key ID:  {key_id}[/]")
    console.print(f"[bold green] Secret:  {secret_value}[/]")
    console.print(f"[bold green] Expires: {expiry}[/]")

    if write:
        body = {
            "app_id": app_id,
            "key_id": key_id,
            "secret": secret_value,
            "expiry": expiry
        }
        with open(f"{CACHE_DIR}/{app_id}.json","w") as f:
            vprint(f"[dim] writing {dumps(body,indent=2)} to {f.name}")
            f.write(dumps(body,indent=2))
        console.print(f"[bold green] Secrets successfully written to {CACHE_DIR}/{app_id}.json[/]")
