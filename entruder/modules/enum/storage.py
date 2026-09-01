import typer
import httpx
import fnmatch
import xml.etree.ElementTree as etree
from urllib.parse import parse_qsl

from entruder.static import API_VERSIONS, HTTP_TIMEOUT
from entruder.utils import (
    parse_error,
    parse_xml_tag,
    request_json,
    vprint,
    iter_with_progress,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
    get_tenant_cache,
    get_session,
)

from ._shared import enum_app, console, columns, prepare_session, resource_group_from_id


def _project_storage(acct):

    props = acct.get("properties", {}) or {}
    acls = props.get("networkAcls", {}) or {}
    endpoints = props.get("primaryEndpoints", {}) or {}
    sku = acct.get("sku", {}) or {}
    return {
        "id":              acct.get("id"),
        "name":            acct.get("name"),
        "resource_group":  resource_group_from_id(acct.get("id")),
        "location":        acct.get("location"),
        "kind":            acct.get("kind"),
        "sku":             sku.get("name"),
        "shared_key":      props.get("allowSharedKeyAccess"),
        "public_access":   props.get("allowBlobPublicAccess"),
        "public_network":  props.get("publicNetworkAccess"),
        "network_default": acls.get("defaultAction"),
        "https_only":      props.get("supportsHttpsTrafficOnly"),
        "min_tls":         props.get("minimumTlsVersion"),
        "oauth_default":   props.get("defaultToOAuthAuthentication"),
        "blob_endpoint":   endpoints.get("blob"),
        "created":         props.get("creationTime"),
    }



STORAGE_KEYS_ACTION = "Microsoft.Storage/storageAccounts/listKeys/action"


def _permission_allows(permissions, wanted, data_action=False):
 
    allow_key = "dataActions" if data_action else "actions"
    deny_key = "notDataActions" if data_action else "notActions"
    wanted = wanted.lower()
    for entry in permissions or []:
        allowed = any(fnmatch.fnmatch(wanted, p.lower()) for p in entry.get(allow_key) or [])
        denied = any(fnmatch.fnmatch(wanted, p.lower()) for p in entry.get(deny_key) or [])
        if allowed and not denied:
            return True
    return False


def _rbac_permissions(headers, resource_id):
   
    url = f"https://management.azure.com{resource_id}/providers/Microsoft.Authorization/permissions"
    params = {"api-version": API_VERSIONS["authorization"]}
    permissions = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)
        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            vprint(f"permissions check failed for {resource_id}: {parse_error(message)}")
            return None
        permissions.extend(result["value"])
        url = result.get("nextLink")
        params = None
    return permissions


def _check_container_listing(blob_endpoint, storage_headers):
  
    if not blob_endpoint:
        return "unknown"
    try:
        response = httpx.get(blob_endpoint, headers=storage_headers,
                              params={"comp": "list", "maxresults": "1"}, timeout=HTTP_TIMEOUT)
    except httpx.HTTPError as e:
        vprint(f"container-listing probe failed for {blob_endpoint}: {e}")
        return "unknown"
    vprint(f"GET {blob_endpoint})")
    return response.status_code == 200


def _annotate_storage_access(management_headers, storage_headers, acct):
   
    permissions = _rbac_permissions(management_headers, acct["id"])
    acct["can_list_keys"] = "unknown" if permissions is None else _permission_allows(permissions, STORAGE_KEYS_ACTION)
    acct["can_list_containers"] = _check_container_listing(acct.get("blob_endpoint"), storage_headers)
    return acct


def _list_storage_keys(headers, account_id):
    """POST the account's listKeys action to retrieve its actual shared keys —
    the live material behind `can_list_keys`, not just a permission check.
    Returns [] (not raises) on failure, most commonly Reader-but-not-listKeys
    on this account, a normal negative result rather than a tool error."""
    url = f"https://management.azure.com{account_id}/listKeys"
    params = {"api-version": API_VERSIONS["storage"]}
    vprint(f"POST {url}")
    result = request_json("POST", url, headers=headers, params=params)
    if "keys" not in result:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        vprint(f"listKeys failed for {account_id}: {parse_error(message)}")
        return []
    return result["keys"]


def _parse_sas(sas):
    """Split a SAS token into its query params so they can be merged into a
    data-plane request. Accepts the token with or without a leading '?'.
    Returns {} for an empty/None token."""
    if not sas:
        return {}
    return dict(parse_qsl(sas.lstrip("?"), keep_blank_values=True))


def _storage_headers(tenant, client_id, sas=None):

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
        vprint("No storage session found/provided — trying anonymous access")
    return headers


def _blob_xml_request(url, headers, params):
    """GET against the Azure Blob Storage data-plane REST API. Responses are
    XML (not JSON), so request_json can't be reused here. Returns the parsed
    XML root, or exits with a clear message on failure."""
    vprint(f"GET {url}")
    response = httpx.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    vprint(f"  -> HTTP {response.status_code} ({len(response.content)} bytes)")

    if response.status_code == 200:
        return etree.fromstring(response.text)

    if response.status_code == 404:
        console.print("[bold red][-][/] Not found (account or container doesn't exist, or DNS didn't resolve)")
        raise typer.Exit(1)
    if response.status_code in (401, 403):
        console.print("[bold red][-][/] Access denied: not publicly listable, and no valid storage token was used",
                      "for containers, listing always needs an authenticated storage token. "
                      "For blobs, anonymous listing only works if the container's public access "
                      "level is set to \"Container\" (full public read)")
        raise typer.Exit(1)

    try:
        root = etree.fromstring(response.text)
        code = parse_xml_tag(root, "Code")
        message = parse_xml_tag(root, "Message")
        console.print(f"[bold red][-][/] Request failed: HTTP {response.status_code} {code} - {message}")
    except etree.ParseError:
        console.print(f"[bold red][-][/] Request failed: HTTP {response.status_code}: {response.text[:200]}")
    raise typer.Exit(1)


def _xml_element_to_dict(element):
    """Flatten an XML element's children into a dict. Container/Blob entries
    nest their fields under <Properties>/<Metadata>; merging those children in
    rather than keeping them nested lets the flat CONTAINER/BLOB columns work
    directly against the result."""
    result = {}
    for child in element:
        if len(child):
            result.update(_xml_element_to_dict(child))
        else:
            result[child.tag] = child.text
    return result


@enum_app.command("storage-accounts")
@handle_cli_errors
def enum_storage_accounts(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    sub: str = typer.Option(None, "-s", "--sub-id", help="Subscription Id of the target (Mandatory)"),
    check_access: bool = typer.Option(True, "-a/-A", "--check-access/--no-check-access",
        help="Also check what the current identity can do on each account (Optional)"),
    list_keys: bool = typer.Option(False, "-l", "--list-keys",
        help="Retrieve the actual shared access keys (listKeys/action) for every account (Optional, can be slow and may require elevated permissions)"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Enumerate storage accounts in a subscription and their exposure-relevant settings. (requires a management token)"""
    # explicitly ask for subid
    if not sub:
         console.print(f"[bold red][-][/] Please provide a subscription Id explicitly")
         raise typer.Exit(1)

    tenant, headers = prepare_session(tenant, client_id, "management")

    url = f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Storage/storageAccounts"
    params = {"api-version": API_VERSIONS["storage"]}

    accounts = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Management request failed: {parse_error(message)}")
            raise typer.Exit(1)

        accounts.extend(result["value"])
        url = result.get("nextLink")
        params = None

    accounts = [_project_storage(a) for a in accounts]
    vprint(f"{len(accounts)} storage account(s) found") 
    if check_access:
        storage_headers = _storage_headers(tenant, client_id)
        accounts = [_annotate_storage_access(headers, storage_headers, a)
                    for a in iter_with_progress(accounts, "Checking access", key=lambda a: a["name"])]
    if list_keys:
        for a in iter_with_progress(accounts, "Listing keys", key=lambda a: a["name"]):
            a["keys"] = _list_storage_keys(headers, a["id"])
    render(console, f"Storage Accounts in {tenant}", columns.STORAGE, accounts,
           output=output, xml_root_tag="StorageAccounts", xml_item_tag="Account")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(accounts)}[/] storage accounts total")


@enum_app.command("containers")
@handle_cli_errors
def enum_containers(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID  (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    account: str = typer.Option(..., "-a", "--account", help="Storage account name (without .blob.core.windows.net) (Mandatory)"),
    sas: str = typer.Option(None, "-s", "--sas", help="Account SAS token to authenticate with instead of a session token (Optional) (needs service resource type + list permission)"),
    output: OutputFormat = output_option(),
):
    """
    List containers in a storage account via the Blob Service List Containers operation. (requires a storage token)
    """
    headers = _storage_headers(tenant, client_id, sas)
    sas_params = _parse_sas(sas)
    endpoint = f"https://{account}.blob.core.windows.net"

    containers = []
    marker = None
    while True:
        params = {"comp": "list", "maxresults": "5000", **sas_params}
        if marker:
            params["marker"] = marker
        root = _blob_xml_request(f"{endpoint}/", headers, params)
        containers.extend(_xml_element_to_dict(c) for c in root.findall("./Containers/Container"))
        marker = parse_xml_tag(root, "NextMarker")
        if marker in (None, "N/A", ""):
            break

    render(console, f"Containers in {account}", columns.CONTAINER, containers,
           output=output, xml_root_tag="containers", xml_item_tag="container")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(containers)}[/] containers total")


@enum_app.command("blobs")
@handle_cli_errors
def enum_blobs(
    account: str = typer.Option(..., "-a", "--account", help="Storage account name (without .blob.core.windows.net)"),
    container: str = typer.Option(..., "-n", "--container", help="Container name"),
    prefix: str = typer.Option(None, "-p", "--prefix", help="Only list blobs whose name starts with this prefix"),
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (optional — used to attach a cached storage token) (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (optional — used to attach a cached storage token) (will be cached upon explicit use)"),
    sas: str = typer.Option(None, "-s", "--sas", help="Account or service SAS token to authenticate with instead of a session token (needs container list permission)"),
    output: OutputFormat = output_option(),
):
    """List blobs in a container via the Blob Service List Blobs operation (requires a storage token). Run with no --tenant/--client-id and user session to test anonymous/public exposure directly"""
    headers = _storage_headers(tenant, client_id, sas)
    sas_params = _parse_sas(sas)
    endpoint = f"https://{account}.blob.core.windows.net"

    blobs = []
    marker = None
    while True:
        params = {"restype": "container", "comp": "list", "maxresults": "5000", **sas_params}
        if prefix:
            params["prefix"] = prefix
        if marker:
            params["marker"] = marker
        root = _blob_xml_request(f"{endpoint}/{container}", headers, params)
        blobs.extend(_xml_element_to_dict(b) for b in root.findall("./Blobs/Blob"))
        marker = parse_xml_tag(root, "NextMarker")
        if marker in (None, "N/A", ""):
            break

    render(console, f"Blobs in {account}/{container}", columns.BLOB, blobs,
           output=output, xml_root_tag="blobs", xml_item_tag="blob")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(blobs)}[/] blobs total")
