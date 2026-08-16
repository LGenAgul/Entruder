import typer
from rich.console import Console
from entruder.globals import API_VERSIONS, HTTP_TIMEOUT
import xml.etree.ElementTree as etree
import httpx
from entruder.utils import (
    parse_error,
    parse_xml_tag,
    report_error,
    request_json,
    vprint,
    handle_cli_errors,
    require_session,
    render,
    OutputFormat,
    save_domain_mapping,
    require_tenant
    )

enum_app = typer.Typer(help="Enumeration", no_args_is_help=True)
console = Console()

USER_COLUMNS = [
    ("Display Name", "displayName"),
    ("UPN", "userPrincipalName"),
    ("Enabled", "accountEnabled"),
    ("Job Title", "jobTitle"),
    ("Department", "department"),
]

TENANT_COLUMNS = [
    ("Domain", "domain"),
    ("Tenant ID", "tenant_id"),
    ("Token Endpoint", "token_endpoint"),
    ("Tenant Region", "tenant_region"),
    ("MsGraph Host", "msgraph_host"),
    ("Namespace", "namespace"),
    ("Brand Name", "brand_name"),
    ("Cloud", "cloud"),
    ("Auth URL", "auth_url"),
    ("DSSO Enabled", "dsso_enabled"),
    ("Federated", "federated"),
]

@enum_app.command("tenant")
@handle_cli_errors
def enum_tenant(
    domain: str = typer.Option(..., "-domain", help="Domain Name"),
    output: OutputFormat = typer.Option(OutputFormat.table, "-output", help="Output format"),
):
    try:
        tenant_info = {}
        openid_json = request_json(
            "GET",
            f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
        )
        # a valid tenant returns an issuer; its absence means the domain isn't an Entra tenant
        if not openid_json.get("issuer"):
            console.print(f"[bold red][-][/] Not a valid Entra tenant domain: {domain} "
                          f"({parse_error(openid_json.get('error_description', 'no issuer returned'))})")
            raise typer.Exit(1)

        tenant_id = openid_json["issuer"].split("/")[-2]
        if tenant_id:
            save_domain_mapping(domain,tenant_id)

        tenant_region_scope = openid_json.get("tenant_region_scope", "N/A")
        msgraph_host = openid_json.get("msgraph_host", "N/A")
        token_endpoint = openid_json.get("token_endpoint", "N/A")

        vprint(f"GET getuserrealm.srf for {domain}")
        userrealm_xml = httpx.get(
            "https://login.microsoftonline.com/getuserrealm.srf",
            params={"login":domain,"xml":"1"},
            timeout=HTTP_TIMEOUT)
        userrealm_xml.raise_for_status()
        vprint(f"  -> HTTP {userrealm_xml.status_code} ({len(userrealm_xml.content)} bytes)")
        root = etree.fromstring(userrealm_xml.text)
        tenant_info["domain"] = domain
        tenant_info["tenant_id"] = tenant_id
        tenant_info["token_endpoint"] = token_endpoint
        tenant_info["tenant_region"] = tenant_region_scope
        tenant_info["msgraph_host"] = msgraph_host
        tenant_info["namespace"] = parse_xml_tag(root, 'NameSpaceType')
        tenant_info["brand_name"] = parse_xml_tag(root, 'FederationBrandName')
        tenant_info["cloud"] = parse_xml_tag(root, 'CloudInstanceName')
        tenant_info["auth_url"] = parse_xml_tag(root, 'AuthURL')
        tenant_info["dsso_enabled"] = parse_xml_tag(root, 'IsDssoEnabled')
        tenant_info["federated"] = parse_xml_tag(root, 'NameSpaceType') == 'Federated'

        
        
        render(console, f"Tenant info for {domain}", TENANT_COLUMNS, [tenant_info], output=output, xml_item_tag="tenant")
    except typer.Exit:
        raise  # let our own explicit exits (with their specific message) through
    except Exception as e:
        console.print(f"[bold red][-][/] Could not reach tenant for domain: {domain}")
        report_error(e, console)
        raise typer.Exit(1)


@enum_app.command("users")
@handle_cli_errors
def enum_users(
    tenant: str = typer.Option(..., "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(..., "-clientid", help="Client ID"),
    output: OutputFormat = typer.Option(OutputFormat.table, "-output", help="Output format"),
):
    """Enumerate directory users via Microsoft Graph, using a saved graph session"""
    resolved_tenant = require_tenant(tenant,console)

    token = require_session(resolved_tenant, client_id, "graph", console)
    headers = {"Authorization": f"Bearer {token}"}

    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/users"
    params = {"$select": "id,displayName,userPrincipalName,accountEnabled,jobTitle,department"}
    
    users = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)
        params = None  # already baked into @odata.nextLink for subsequent pages

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Graph request failed: {parse_error(message)}")
            raise typer.Exit(1)

        users.extend(result["value"])
        url = result.get("@odata.nextLink")

    render(console, f"Users in {resolved_tenant}", USER_COLUMNS, users, output=output, xml_item_tag="user")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(users)}[/] users total")

@enum_app.command("userinfo")
@handle_cli_errors
def enum_user_detail(

):
    pass