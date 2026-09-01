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


def _project_webapp(site):
    props = site.get("properties", {}) or {}
    return {
        "id":                  site.get("id"),
        "name":                site.get("name"),
        "resource_group":      resource_group_from_id(site.get("id")),
        "location":            site.get("location"),
        "kind":                site.get("kind"),
        "state":               props.get("state"),
        "default_hostname":    props.get("defaultHostName"),
        "https_only":          props.get("httpsOnly"),
        "client_cert_enabled": props.get("clientCertEnabled"),
        "public_network":      props.get("publicNetworkAccess"),
        "identity":            site.get("identity") or {},
    }


def _fetch_site_config(headers, site_id):
    """GET the site's actual web config for the settings the base listing doesn't reliably populate. """
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


def _list_publishing_credentials(headers, site_id):
    """ Sends a POST request to the publishingcredentials endpoint to extract any user credentials for their Kudu/Scm Host """
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
    """POST the site's appsettings/list action — app settings are Azure's
    equivalent of environment variables and routinely hold connection
    strings/API keys/secrets, not just config toggles."""
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
    """POST the site's connectionstrings/list action."""
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


def _list_slots(headers, site_id):
    """GET the site's deployment slots. Each slot is a full site in its own right (own identity/config/secrets) """
    url = f"https://management.azure.com{site_id}/slots"
    params = {"api-version": API_VERSIONS["web"]}
    vprint(f"GET {url}")
    result = request_json("GET", url, headers=headers, params=params)
    if "value" not in result:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        vprint(f"slot listing failed for {site_id}: {parse_error(message)}")
        return []
    return result["value"]


@enum_app.command("webapps")
@handle_cli_errors
def enum_webapps(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    sub: str = typer.Option(None, "-s", "--sub-id", help="Subscription Id"),
    check_config: bool = typer.Option(True, "-h/-H", "--check-config/--no-check-config",
        help="Also fetch each site's actual config (TLS version, FTPS state, remote debugging, "
             "always-on) and its deployment slot names — two extra ARM calls per site, so "
             "--no-check-config skips both on large subscriptions"),
    list_secrets: bool = typer.Option(False, "-l", "--list-secrets",
        help="Retrieve each site's actual publishing credentials, app settings, and connection "
             "strings — opt-in since this materializes live secret values (three extra ARM calls per site)"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Enumerate Azure App Service web apps in a subscription and their exposure-relevant settings. (requires a management token)"""
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

    sites = [_project_webapp(s) for s in sites]

    if check_config:
        for s in iter_with_progress(sites, "Fetching config", key=lambda s: s["name"]):
            cfg = _fetch_site_config(headers, s["id"])
            s["min_tls"]          = cfg.get("minTlsVersion")
            s["ftps_state"]       = cfg.get("ftpsState")
            s["remote_debugging"] = cfg.get("remoteDebuggingEnabled")
            s["always_on"]        = cfg.get("alwaysOn")
            s["slots"] = [slot.get("name", "").rsplit("/", 1)[-1] for slot in _list_slots(headers, s["id"])]

    if list_secrets:
        for s in iter_with_progress(sites, "Listing secrets", key=lambda s: s["name"]):
            s["publishing_credentials"] = _list_publishing_credentials(headers, s["id"])
            s["app_settings"]           = _list_app_settings(headers, s["id"])
            s["connection_strings"]     = _list_connection_strings(headers, s["id"])

    render(console, f"Web Apps in {tenant}", columns.WEBAPP, sites,
           output=output, xml_root_tag="webapps", xml_item_tag="webapp")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(sites)}[/] web apps total")


@enum_app.command("webapp-slots")
@handle_cli_errors
def enum_webapp(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    sub: str = typer.Option(None, "-s", "--sub-id", help="Subscription Id for the target(Mandatory)"),
    rg: str = typer.Option(..., "-r", "--rg", help="Resource group the web app lives in (Mandatory)"),
    webapp: str = typer.Option(..., "-w", "--webapp", help="Web app (site) name (Mandatory)"),
    check_config: bool = typer.Option(True, "-h/-H", "--check-config/--no-check-config",
        help="Also fetch each slot's actual config (TLS version, FTPS state, remote debugging, always-on) (Optional)"),
    list_secrets: bool = typer.Option(False, "-l", "--list-secrets",
        help="Retrieve each slot's actual publishing credentials, app settings, and connection strings (Optional)"),
    output: OutputFormat = output_option(OutputFormat.json), 
):
    """GET the site's deployment slots. Each slot is a full site in its own right (requires a management token)"""
    if not sub:
        console.print(f"[bold red][-][/] Please provide a subscription Id explicitly")
        raise typer.Exit(1)

    tenant, headers = prepare_session(tenant, client_id, "management")

    site_id = f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{webapp}"
    slots = [_project_webapp(s) for s in _list_slots(headers, site_id)]
    if check_config:
        for s in iter_with_progress(slots, "Fetching config", key=lambda s: s["name"]):
            cfg = _fetch_site_config(headers, s["id"])
            s["min_tls"]          = cfg.get("minTlsVersion")
            s["ftps_state"]       = cfg.get("ftpsState")
            s["remote_debugging"] = cfg.get("remoteDebuggingEnabled")
            s["always_on"]        = cfg.get("alwaysOn")

    if list_secrets:
        for s in iter_with_progress(slots, "Listing secrets", key=lambda s: s["name"]):
            s["publishing_credentials"] = _list_publishing_credentials(headers, s["id"])
            s["app_settings"]           = _list_app_settings(headers, s["id"])
            s["connection_strings"]     = _list_connection_strings(headers, s["id"])

    render(console, f"Slots for {webapp} in {tenant}", columns.WEBAPP, slots,
           output=output, xml_root_tag="slots", xml_item_tag="slot")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(slots)}[/] slots total")
