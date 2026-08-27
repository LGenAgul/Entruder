import typer
import httpx

from entruder.static import RESOURCE_SHORTCUTS, HTTP_TIMEOUT
from entruder.utils import (
    acquire_for_resources,
    decode_jwt,
    handle_cli_errors,
    initialize_tenant_cache,
    save_session,
    vprint,
)

from ._shared import get_app, console

IMDS_TOKEN_URL = "http://169.254.169.254/metadata/identity/oauth2/token"
IMDS_API_VERSION = "2018-02-01"


def _imds_acquire(resource_url, client_id=None):
    """GET the Instance Metadata Service token endpoint available to any Azure
    VM, VMSS, or Container Instance with a managed identity attached. Only
    reachable from inside that resource, not exposed anywhere else."""
    params = {"api-version": IMDS_API_VERSION, "resource": resource_url}
    if client_id:
        params["client_id"] = client_id
    vprint(f"GET {IMDS_TOKEN_URL} (resource={resource_url})")
    try:
        response = httpx.get(IMDS_TOKEN_URL, headers={"Metadata": "true"}, params=params, timeout=HTTP_TIMEOUT)
    except httpx.HTTPError as e:
        return {"error": "imds_unreachable", "error_description": f"Could not reach the IMDS endpoint: {e}"}
    try:
        return response.json()
    except Exception:
        return {"error": "imds_bad_response", "error_description": f"HTTP {response.status_code}: {response.text[:200]}"}


@get_app.command("token")
@handle_cli_errors
def get_managed_identity_token(
    resource: str = typer.Option(None, "-r", "--resource", help="Target resource for the token (Optional, default: every plane in graph/management/storage/keyvault)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID of a user-assigned managed identity (Optional, default: the system-assigned identity)"),
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID to file the session under (Optional, default: read from the token's tid claim)"),
    output_tokens: bool = typer.Option(False, "-o", "--output", help="Output tokens to console"),
):
    """
    Acquire access token(s) from this host's Azure Managed Identity via the IMDS
    endpoint. Only works when run on an Azure resource with a managed identity
    attached (VM, VMSS, Container Instance, etc).
    """
    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())

    def acquire(plane, res):
        resource_url = RESOURCE_SHORTCUTS.get(res, res)
        return _imds_acquire(resource_url, client_id)

    tokens = acquire_for_resources(resources, acquire, console, output_tokens=output_tokens, label="Managed Identity")

    if not tokens:
        console.print("[dim]No managed identity is attached here, or IMDS is unreachable from this host[/dim]")
        raise typer.Exit(1)

    claims = decode_jwt(next(iter(tokens.values()))["value"])
    resolved_tenant = tenant or claims.get("tid")
    resolved_client_id = client_id or claims.get("appid") or claims.get("azp") or claims.get("oid")

    if resolved_tenant and resolved_client_id:
        save_session(resolved_tenant, resolved_client_id, tokens)
        initialize_tenant_cache(resolved_tenant, resolved_client_id)
        console.print(f"[bold green][+][/] Session saved for tenant: {resolved_tenant}")
    else:
        console.print("[dim]Could not save a session, pass --tenant explicitly (the token did not carry a usable tid claim)[/dim]")
