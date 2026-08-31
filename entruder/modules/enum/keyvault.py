import typer
import httpx

from entruder.static import API_VERSIONS, HTTP_TIMEOUT
from entruder.utils import (
    parse_error,
    request_json,
    vprint,
    iter_with_progress,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import enum_app, console, columns, prepare_session, resource_group_from_id


def _project_vault(vault):
    """Flatten a raw ARM Key Vault resource into the exposure-relevant shape
    the VAULT columns expect, mirroring _project_storage in storage.py. `id`
    is carried through (unused by the table) so json consumers can drive
    follow-up per-vault calls."""
    props = vault.get("properties", {}) or {}
    acls = props.get("networkAcls", {}) or {}
    sku = props.get("sku", {}) or {}
    return {
        "id":                  vault.get("id"),
        "name":                vault.get("name"),
        "resource_group":      resource_group_from_id(vault.get("id")),
        "location":            vault.get("location"),
        "vault_uri":           props.get("vaultUri"),
        "sku":                 sku.get("name"),
        "rbac_authorization":  props.get("enableRbacAuthorization", False),
        "access_policies":     props.get("accessPolicies", []),
        "soft_delete":         props.get("enableSoftDelete"),
        "purge_protection":    props.get("enablePurgeProtection"),
        "public_network":      props.get("publicNetworkAccess"),
        "network_default":     acls.get("defaultAction"),
    }


def _check_secret_listing(vault_uri, kv_headers):
    """Ground-truth probe: attempt List Secrets (maxresults=1) with the
    caller's own keyvault-scoped token, mirroring _check_container_listing in
    storage.py. Access policies and RBAC data-actions are two different
    permission models that can both apply depending on enableRbacAuthorization,
    so a live probe beats trying to evaluate either one by hand."""
    if not vault_uri:
        return "unknown"
    try:
        response = httpx.get(f"{vault_uri.rstrip('/')}/secrets", headers=kv_headers,
                              params={"api-version": API_VERSIONS["keyvault"], "maxresults": "1"},
                              timeout=HTTP_TIMEOUT)
    except httpx.HTTPError as e:
        vprint(f"secret-listing probe failed for {vault_uri}: {e}")
        return "unknown"
    return response.status_code == 200


def _annotate_vault_access(kv_headers, vault):
    vault["can_list_secrets"] = _check_secret_listing(vault.get("vault_uri"), kv_headers)
    return vault


def _kv_item_name(item_id):
    """Key Vault list responses only give the full item id
    (https://vault.vault.azure.net/{kind}/{name}) — the name is the last
    path segment."""
    return (item_id or "").rstrip("/").rsplit("/", 1)[-1]


def _kv_collect(url, headers, params):
    """Follow Key Vault's nextLink paging and return the merged `value` list.
    Unlike the blob data-plane, Key Vault's data-plane responses are already
    JSON, so request_json works directly — no XML parsing needed."""
    items = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)
        params = None  # nextLink already carries api-version/params
        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Key Vault request failed: {parse_error(message)}")
            raise typer.Exit(1)
        items.extend(result["value"])
        url = result.get("nextLink")
    return items


def _project_kv_item(item, thumbprint=False):
    attrs = item.get("attributes", {}) or {}
    projected = {
        "name":        _kv_item_name(item.get("id")),
        "enabled":     attrs.get("enabled"),
        "created":     attrs.get("created"),
        "updated":     attrs.get("updated"),
        "expires":     attrs.get("exp"),
        "tags":        item.get("tags"),
    }
    if thumbprint:
        projected["thumbprint"] = item.get("x5t")
    else:
        projected["contentType"] = item.get("contentType")
    return projected


@enum_app.command("keyvaults")
@handle_cli_errors
def enum_keyvaults(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    sub: str = typer.Option(None, "-s", "--sub-id", help="Subscription Id"),
    check_access: bool = typer.Option(True, "-a/-A", "--check-access/--no-check-access",
        help="Also live-probe whether the current identity can list secrets on each vault "
             "(one keyvault data-plane call per vault) — --no-check-access skips it on large subscriptions"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Enumerate Key Vaults in a subscription and their settings (requires a management token)"""
    if not sub:
        console.print(f"[bold red][-][/] Please provide a subscription Id explicitly")
        raise typer.Exit(1)

    tenant, headers = prepare_session(tenant, client_id, "management")

    url = f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.KeyVault/vaults"
    params = {"api-version": API_VERSIONS["management"]}

    vaults = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Management request failed: {parse_error(message)}")
            raise typer.Exit(1)

        vaults.extend(result["value"])
        url = result.get("nextLink")
        params = None

    vaults = [_project_vault(v) for v in vaults]
    if check_access:
        _, kv_headers = prepare_session(tenant, client_id, "keyvault")
        vaults = [_annotate_vault_access(kv_headers, v)
                  for v in iter_with_progress(vaults, "Checking access", key=lambda v: v["name"])]
    vprint(f"{len(vaults)} vaults retreived")
    render(console, f"Key Vaults in {tenant}", columns.VAULT, vaults,
           output=output, xml_root_tag="vaults", xml_item_tag="vault")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(vaults)}[/] key vaults total")


@enum_app.command("secrets")
@handle_cli_errors
def enum_secrets(
    vault: str = typer.Option(..., "-v", "--vault", help="Key Vault name (without .vault.azure.net)"),
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    output: OutputFormat = output_option(),
):
    """List secret names/metadata in a vault (requires a keyvault token)"""
    tenant, headers = prepare_session(tenant, client_id, "keyvault")
    url = f"https://{vault}.vault.azure.net/secrets"
    params = {"api-version": API_VERSIONS["keyvault"]}

    secrets = [_project_kv_item(s) for s in _kv_collect(url, headers, params)]
    vprint(f"{len(secrets)} secrets retreived")
    render(console, f"Secrets in {vault}", columns.SECRET, secrets,
           output=output, xml_root_tag="secrets", xml_item_tag="secret")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(secrets)}[/] secrets total")


@enum_app.command("keys")
@handle_cli_errors
def enum_keys(
    vault: str = typer.Option(..., "-v", "--vault", help="Key Vault name (without .vault.azure.net)"),
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    output: OutputFormat = output_option(),
):
    """List key names/metadata in a vault. (requires a keyvault token)"""
    tenant, headers = prepare_session(tenant, client_id, "keyvault")
    url = f"https://{vault}.vault.azure.net/keys"
    params = {"api-version": API_VERSIONS["keyvault"]}

    keys = [_project_kv_item(k) for k in _kv_collect(url, headers, params)]
    vprint(f"{len(keys)} keys retreived")
    render(console, f"Keys in {vault}", columns.KEY, keys,
           output=output, xml_root_tag="keys", xml_item_tag="key")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(keys)}[/] keys total")


@enum_app.command("certificates")
@handle_cli_errors
def enum_certificates(
    vault: str = typer.Option(..., "-v", "--vault", help="Key Vault name (without .vault.azure.net)"),
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    output: OutputFormat = output_option(),
):
    """List certificate names/metadata in a vault. (requires a keyvault token)"""
    tenant, headers = prepare_session(tenant, client_id, "keyvault")
    url = f"https://{vault}.vault.azure.net/certificates"
    params = {"api-version": API_VERSIONS["keyvault"]}

    certs = [_project_kv_item(c, thumbprint=True) for c in _kv_collect(url, headers, params)]
    render(console, f"Certificates in {vault}", columns.CERTIFICATE, certs,
           output=output, xml_root_tag="certificates", xml_item_tag="certificate")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(certs)}[/] certificates total")
