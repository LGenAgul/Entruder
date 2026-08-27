import typer
import httpx
import xml.etree.ElementTree as etree
from urllib.parse import parse_qsl

from entruder.static import API_VERSIONS, HTTP_TIMEOUT
from entruder.utils import (
    parse_xml_tag,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
    get_tenant_cache,
    get_session,
)

from ._shared import get_app, console, columns


def _parse_sas(sas):
    """Split a SAS token into its query params so they can be merged into a
    data-plane request. Accepts the token with or without a leading '?'.
    Returns {} for an empty/None token."""
    if not sas:
        return {}
    return dict(parse_qsl(sas.lstrip("?"), keep_blank_values=True))


def _storage_headers(tenant, client_id, sas=None):
    """Best-effort auth for the blob data-plane. An explicit SAS token wins
    (it authenticates via the query string, no Authorization header needed);
    otherwise attach a cached storage token if a tenant/client resolves to
    one. Missing auth is not fatal, running with neither exercises the
    anonymous/public-access path, which is usually the interesting security
    question for this tool."""
    headers = {"x-ms-version": API_VERSIONS["storage_data"]}
    if sas:
        vprint("Using provided SAS token for storage data-plane auth")
        return headers
    resolved_tenant, resolved_client_id = get_tenant_cache(tenant, client_id)
    token = None
    if resolved_tenant and resolved_client_id:
        session = get_session(resolved_tenant, resolved_client_id)
        token = session.get("tokens", {}).get("storage", {}).get("value")
    if token:
        headers["Authorization"] = f"Bearer {token}"
        vprint(f"Using cached storage token for {resolved_tenant} / {resolved_client_id}")
    else:
        vprint("No storage session found/provided, trying anonymous access")
    return headers


@get_app.command("blob")
@handle_cli_errors
def get_blob(
    account: str = typer.Option(..., "-a", "--account", help="Storage account name (without .blob.core.windows.net)"),
    container: str = typer.Option(..., "-n", "--container", help="Container name"),
    blob: str = typer.Option(..., "-b", "--blob", help="Blob name (full path within the container)"),
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (optional, used to attach a cached storage token)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (optional, used to attach a cached storage token)"),
    sas: str = typer.Option(None, "-s", "--sas", help="Account or service SAS token to authenticate with instead of a session token (needs blob read permission)"),
    output: OutputFormat = output_option(),
):
    """Retrieve a single blob's actual content via the Blob Service Get Blob operation.
    Run with no --tenant/--client-id and no --sas to test anonymous/public exposure directly."""
    headers = _storage_headers(tenant, client_id, sas)
    sas_params = _parse_sas(sas)
    url = f"https://{account}.blob.core.windows.net/{container}/{blob}"

    vprint(f"GET {url}")
    response = httpx.get(url, headers=headers, params=sas_params, timeout=HTTP_TIMEOUT)
    vprint(f"  -> HTTP {response.status_code} ({len(response.content)} bytes)")

    if response.status_code == 404:
        console.print("[bold red][-][/] Not found (account, container, or blob doesn't exist, or DNS didn't resolve)")
        raise typer.Exit(1)
    if response.status_code in (401, 403):
        console.print("[bold red][-][/] Access denied: not publicly readable, and no valid storage token was used. "
                      "Anonymous reads only work if the container's public access level allows blob or container access")
        raise typer.Exit(1)
    if response.status_code != 200:
        try:
            root = etree.fromstring(response.text)
            code = parse_xml_tag(root, "Code")
            message = parse_xml_tag(root, "Message")
            console.print(f"[bold red][-][/] Request failed: HTTP {response.status_code} {code} - {message}")
        except etree.ParseError:
            console.print(f"[bold red][-][/] Request failed: HTTP {response.status_code}: {response.text[:200]}")
        raise typer.Exit(1)

    row = {
        "name":         blob,
        "container":    container,
        "account":      account,
        "content_type": response.headers.get("Content-Type"),
        "size":         len(response.content),
        "content":      response.text,
    }
    render(console, f"{account}/{container}/{blob}", columns.BLOB_CONTENT, row, output=output, xml_item_tag="blob")
