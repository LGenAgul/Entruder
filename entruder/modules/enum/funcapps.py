import typer

from entruder.static import API_VERSIONS
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


def _project_funcapp(site):
    props = site.get("properties", {}) or {}
    return {
        "id":               site.get("id"),
        "name":             site.get("name"),
        "resource_group":   resource_group_from_id(site.get("id")),
        "location":         site.get("location"),
        "kind":             site.get("kind"),
        "state":            props.get("state"),
        "default_hostname": props.get("defaultHostName"),
        "https_only":       props.get("httpsOnly"),
        "public_network":   props.get("publicNetworkAccess"),
        "identity":         site.get("identity") or {},
    }


def _fetch_site_config(headers, site_id):
   
    url = f"https://management.azure.com{site_id}/config/web"
    params = {"api-version": API_VERSIONS["web"]}
    vprint(f"GET {url}")
    result = request_json("GET", url, headers=headers, params=params)
    if "properties" not in result:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        vprint(f"site config fetch failed for {site_id}: {parse_error(message)}")
        return {}
    return result["properties"]


def _list_functions(headers, site_id):
    
    url = f"https://management.azure.com{site_id}/functions"
    params = {"api-version": API_VERSIONS["web"]}
    vprint(f"GET {url}")
    result = request_json("GET", url, headers=headers, params=params)
    if "value" not in result:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        vprint(f"function listing failed for {site_id}: {parse_error(message)}")
        return []
    return result["value"]


def _project_function(func):
    props = func.get("properties", {}) or {}
    bindings = (props.get("config", {}) or {}).get("bindings", []) or []
    triggers = [b.get("type") for b in bindings if str(b.get("type", "")).lower().endswith("trigger")]
    name = (func.get("name") or "").rsplit("/", 1)[-1]
    return f"{name} ({', '.join(triggers) or 'unknown trigger'})"


def _list_host_keys(headers, site_id):
    
    url = f"https://management.azure.com{site_id}/host/default/listkeys"
    params = {"api-version": API_VERSIONS["web"]}
    vprint(f"POST {url}")
    result = request_json("POST", url, headers=headers, params=params)
    if not any(k in result for k in ("masterKey", "functionKeys", "systemKeys")):
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        vprint(f"listkeys failed for {site_id}: {parse_error(message)}")
        return {}
    return result


def _list_publishing_credentials(headers, site_id):
    
    url = f"https://management.azure.com{site_id}/config/publishingcredentials/list"
    params = {"api-version": API_VERSIONS["web"]}
    vprint(f"POST {url}")
    result = request_json("POST", url, headers=headers, params=params)
    props = result.get("properties", {}) or {}
    if not props:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        vprint(f"listPublishingCredentials failed for {site_id}: {parse_error(message)}")
        return {}
    scm_uri = props.get("scmUri")
    return {
        "publishingUserName": props.get("publishingUserName"),
        "publishingPassword": props.get("publishingPassword"),
        "scmUri":             scm_uri,
        "kuduRce":            f"{scm_uri}/api/command (RCE) | {scm_uri}/api/zipdeploy (webshell)" if scm_uri else None,
    }


def _list_app_settings(headers, site_id):

    url = f"https://management.azure.com{site_id}/config/appsettings/list"
    params = {"api-version": API_VERSIONS["web"]}
    vprint(f"POST {url}")
    result = request_json("POST", url, headers=headers, params=params)
    if "properties" not in result:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        vprint(f"listAppSettings failed for {site_id}: {parse_error(message)}")
        return {}
    return result["properties"]


def _list_connection_strings(headers, site_id):

    url = f"https://management.azure.com{site_id}/config/connectionstrings/list"
    params = {"api-version": API_VERSIONS["web"]}
    vprint(f"POST {url}")
    result = request_json("POST", url, headers=headers, params=params)
    if "properties" not in result:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        vprint(f"listConnectionStrings failed for {site_id}: {parse_error(message)}")
        return {}
    return {name: entry.get("value") for name, entry in result["properties"].items()}


@enum_app.command("funcapps")
@handle_cli_errors
def enum_funcapps(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    sub: str = typer.Option(None, "-s", "--sub-id", help="Subscription ID of the target subscription (Mandatory)"),
    check_config: bool = typer.Option(True, "-h/-H", "--check-config/--no-check-config",
        help="Also fetch the app's runtime configuration and its individual functions (Optional, can be slow)"),
    list_secrets: bool = typer.Option(False, "-l", "--list-secrets",
        help="Also retreive each app's host and secret keys (Optional, can be slow and may require elevated permissions)"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Enumerate all function apps in a given subscription. (requires a management token)"""
    if not sub:
        console.print(f"[bold red][-][/] Please provide a subscription Id explicitly")
        raise typer.Exit(1)

    tenant, headers = prepare_session(tenant, client_id, "management")

    url = f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Web/sites"
    params = {"api-version": API_VERSIONS["web"]}

    sites = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Management request failed: {parse_error(message)}")
            raise typer.Exit(1)

        sites.extend(result["value"])
        url = result.get("nextLink")
        params = None

    sites = [s for s in sites if "functionapp" in (s.get("kind") or "").lower()]
    vprint(f"{len(sites)} function app(s) identified")
    funcapps = [_project_funcapp(s) for s in sites]

    if check_config:
        for f in iter_with_progress(funcapps, "Fetching config", key=lambda f: f["name"]):
            cfg = _fetch_site_config(headers, f["id"])
            f["runtime"] = cfg.get("linuxFxVersion") or cfg.get("windowsFxVersion") or None
            f["functions"] = [_project_function(fn) for fn in _list_functions(headers, f["id"])]

    if list_secrets:
        for f in iter_with_progress(funcapps, "Listing secrets", key=lambda f: f["name"]):
            f["host_keys"]              = _list_host_keys(headers, f["id"])
            f["publishing_credentials"] = _list_publishing_credentials(headers, f["id"])
            f["app_settings"]           = _list_app_settings(headers, f["id"])
            f["connection_strings"]     = _list_connection_strings(headers, f["id"])

    render(console, f"Function Apps in {tenant}", columns.FUNCAPP, funcapps,
           output=output, xml_root_tag="funcapps", xml_item_tag="funcapp")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(funcapps)}[/] function apps total")
