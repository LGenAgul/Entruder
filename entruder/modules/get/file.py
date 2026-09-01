import typer
import httpx

from entruder.static import API_VERSIONS
from entruder.utils import (
    request_json,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    parse_error,
    output_option,
)

from ._shared import get_app, console, prepare_session, object_columns


@get_app.command("file")
@handle_cli_errors
def get_file(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    drive_item_id: str = typer.Option(..., "-d", "--drive-item-id",
        help="Drive item ID in driveId:itemId format from sharepoint files output (Mandatory)"),
    output_path: str = typer.Option(None, "-o", "--output",
        help="Save to this path (default: current directory using the original filename)"),
):
    """Download a file from SharePoint or OneDrive by its drive item ID. To find drive item IDs use: entruder sharepoint files (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    if ":" not in drive_item_id:
        console.print("[bold red][-][/] --drive-item-id must be in driveId:itemId format")
        raise typer.Exit(1)

    drive_id, item_id = drive_item_id.split(":", 1)

    # Get metadata first including filenames
    meta = request_json(
        "GET",
        f"https://graph.microsoft.com/{API_VERSIONS['graph']}/drives/{drive_id}/items/{item_id}",
        headers=headers,
        params={"$select": "name,size,file"}
    )

    if "error" in meta:
        console.print(f"[bold red][-][/] {parse_error(meta['error'].get('message', ''))}")
        raise typer.Exit(1)

    filename = meta.get("name", item_id)
    size = meta.get("size", 0)

    # Resolve output path
    from pathlib import Path
    dest = Path(output_path) if output_path else Path(filename)
    if dest.is_dir():
        dest = dest / filename

    console.print(f"[yellow][*][/] Downloading {filename} ({size} bytes)...")

    # Download content
    response = httpx.get(
        f"https://graph.microsoft.com/{API_VERSIONS['graph']}/drives/{drive_id}/items/{item_id}/content",
        headers=headers,
        follow_redirects=True,
        timeout=120
    )

    if response.status_code != 200:
        console.print(f"[bold red][-][/] Download failed: {response.status_code} {response.text[:200]}")
        raise typer.Exit(1)

    dest.write_bytes(response.content)
    console.print(f"[bold green][+][/] Saved to {dest} ({len(response.content)} bytes)")
