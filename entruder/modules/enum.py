import typer
from rich.console import Console
from entruder.globals import (
    API_VERSIONS,
    HTTP_TIMEOUT,
    BASIC_FIELDS,
    BASIC_PARAMS,
    TRANSITIVE_PARAMS,
    GROUP_PARAMS,
    SP_PARAMS,
    FULL_METADATA_ACCEPT,
    GROUP_FIELDS,
    ROLE_FIELDS,
)
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
    output_option,
    pluck,
    require_tenant,
    require_tenant_cache,
    initialize_tenant_cache,
    save_domain_mapping,
    format_mfa,
    format_groups,
    format_credentials,
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

GROUP_COLUMNS = [
    ("Group Id",    "id"),
    ("Display Name",    "displayName"),
    ("Description",     "description"),
    ("Security",        "securityEnabled"),
    ("Role-Assignable", "isAssignableToRole"),
    ("Mail Enabled",    "mailEnabled"),
    ("Types",           "groupTypes"),
]

SP_COLUMNS = [
    ("Display Name",         "displayName"),
    ("App Id",               "appId"),
    ("Type",                 "servicePrincipalType"),
    ("Enabled",              "accountEnabled"),
    ("Assignment Required",  "appRoleAssignmentRequired"),
    ("Owner Org",            "appOwnerOrganizationId"),
    ("Publisher",            "publisherName"),
    ("Homepage",             "homepage"),
    ("Cert Creds",           "keyCredentials", format_credentials),
    ("Secret Creds",         "passwordCredentials", format_credentials),
    ("Tags",                 "tags"),
]




USERINFO_COLUMNS = [
    ("Display Name", "displayName"),
    ("UPN", "userPrincipalName"),
    ("Enabled", "accountEnabled"),
    ("Job Title", "jobTitle"),
    ("Department", "department"),
    ("Groups", "groups", format_groups),
    ("Roles", "roles", pluck("displayName")),
    ("MFA", "mfa", format_mfa),
    ("Owned", "owned", pluck("displayName")),
    ("App Roles", "app_roles", pluck("resourceDisplayName")),
    ("MFA Exclusion Groups", "mfa_exclusion_groups"),
]


TENANT_COLUMNS = [
    ("Domain",          "domain"),
    ("Tenant ID",       "tenant_id"),
    ("Token Endpoint",  "token_endpoint"),
    ("Tenant Region",   "tenant_region"),
    ("MsGraph Host",    "msgraph_host"),
    ("Namespace",       "namespace"),
    ("Brand Name",      "brand_name"),
    ("Cloud",           "cloud"),
    ("Auth URL",        "auth_url"),
    ("DSSO Enabled",    "dsso_enabled"),
    ("Federated",       "federated"),
]
 
@enum_app.command("tenant")
@handle_cli_errors
def enum_tenant(
    domain: str = typer.Option(..., "-domain", help="Domain Name"),
    output: OutputFormat = output_option(),
):
    try: 
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
            save_domain_mapping(domain, tenant_id)
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

        result = {
            "domain":         domain,
            "tenant_id":      tenant_id,
            "token_endpoint": token_endpoint,
            "tenant_region":  tenant_region_scope,
            "msgraph_host":   msgraph_host,
            "namespace":      parse_xml_tag(root, "NameSpaceType"),
            "brand_name":     parse_xml_tag(root, "FederationBrandName"),
            "cloud":          parse_xml_tag(root, "CloudInstanceName"),
            "auth_url":       parse_xml_tag(root, "AuthURL"),
            "dsso_enabled":   parse_xml_tag(root, "IsDssoEnabled"),
            "federated":      parse_xml_tag(root, "NameSpaceType") == "Federated",
        }
        
        render(console, f"Tenant:{domain}", TENANT_COLUMNS, result, output=output, xml_item_tag="tenant")

    except typer.Exit:
        raise  # let our own explicit exits (with their specific message) through
    except Exception as e:
        console.print(f"[bold red][-][/] Could not reach tenant for domain: {domain}")
        report_error(e, console)
        raise typer.Exit(1)

@enum_app.command("groups")
@handle_cli_errors
def enum_groups(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    output: OutputFormat = output_option(),
    ):
    """Enumerate directory groups via Microsoft Graph, using a saved graph session"""
    explicit_args = bool(tenant or client_id)
    tenant, client_id = require_tenant_cache(tenant, client_id, console)
    tenant =  require_tenant(tenant,console)
    if explicit_args:
        initialize_tenant_cache(tenant, client_id)
    token = require_session(tenant, client_id, "graph", console)
    headers = {"Authorization": f"Bearer {token}"}

    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/groups"
    params = GROUP_PARAMS

    groups = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)
        params = None  # nextLink already carries $select; don't re-send it

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Graph request failed: {parse_error(message)}")
            raise typer.Exit(1)

        groups.extend(result["value"])
        url = result.get("@odata.nextLink")
    render(console, f"Groups in {tenant}", GROUP_COLUMNS, groups, output=output, xml_root_tag="groups", xml_item_tag="group")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(groups)}[/] groups total")


@enum_app.command("serviceprincipals")
@handle_cli_errors
def enum_serviceprincipals(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    owned: bool = typer.Option(False, "-owned",
        help="Only show service principals owned by the current signed-in user "
             "(requires a delegated session, ropc/device/authcode, not app-only secret/cert/foci/kerberos)"),
    output: OutputFormat = output_option(),
    ):
    """Enumerate service principals via Microsoft Graph, using a saved graph session"""
    explicit_args = bool(tenant or client_id)
    tenant, client_id = require_tenant_cache(tenant, client_id, console)
    tenant = require_tenant(tenant, console)

    if explicit_args:
        initialize_tenant_cache(tenant, client_id)
        
    token = require_session(tenant, client_id, "graph", console)
    headers = {"Authorization": f"Bearer {token}"}

    if owned:
        url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/me/ownedObjects"
        params = SP_PARAMS
    else:
        url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/servicePrincipals"
        params = SP_PARAMS

    service_principals = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)
        params = None  # nextLink already carries $select; don't re-send it

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Graph request failed: {parse_error(message)}")
            if owned:
                console.print("[dim]-owned requires a delegated (user) session — log in via ropc/device/authcode, not secret/cert/foci/kerberos[/dim]")
            raise typer.Exit(1)

        batch = result["value"]
        if owned:
            # /me/ownedObjects is polymorphic (apps, groups, service principals, ...)
            batch = [obj for obj in batch if obj.get("@odata.type") == "#microsoft.graph.servicePrincipal"]
        service_principals.extend(batch)
        url = result.get("@odata.nextLink")

    title = f"Service Principals in {tenant}" + (" (owned by current user)" if owned else "")
    render(console, title, SP_COLUMNS, service_principals, output=output,
           xml_root_tag="serviceprincipals", xml_item_tag="serviceprincipal")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(service_principals)}[/] service principals total")


@enum_app.command("users")
@handle_cli_errors
def enum_users(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    output: OutputFormat = output_option(),
):
    """Enumerate directory users via Microsoft Graph, using a saved graph session"""
    explicit_args = bool(tenant or client_id)
    tenant, client_id = require_tenant_cache(tenant, client_id, console)
    tenant =  require_tenant(tenant,console)
    if explicit_args:
        initialize_tenant_cache(tenant, client_id)
    token = require_session(tenant, client_id, "graph", console)
    headers = {"Authorization": f"Bearer {token}"}

    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/users"
    params = BASIC_PARAMS
    
    users = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)
        params = None 

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Graph request failed: {parse_error(message)}")
            raise typer.Exit(1)

        users.extend(result["value"])
        url = result.get("@odata.nextLink")
    render(console, f"Users in {tenant}", USER_COLUMNS, users, output=output, xml_root_tag="users", xml_item_tag="user")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(users)}[/] users total")



@enum_app.command("userinfo")
@handle_cli_errors
def enum_userinfo(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    username: str = typer.Option(...,"-upn",help="userPrincipalName/email of the target user"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    from entruder.globals import MFA_EXCLUSION_PATTERNS
    explicit_args = bool(tenant or client_id)
    tenant, client_id = require_tenant_cache(tenant, client_id, console)
    tenant =  require_tenant(tenant,console)
    if explicit_args:
        initialize_tenant_cache(tenant, client_id)
    token = require_session(tenant, client_id, "graph", console)
    headers = {"Authorization": f"Bearer {token}"}
     
    base = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/users/{username}"
    
    result = {}
    basic_info = request_json("GET", base, headers=headers, params=BASIC_PARAMS)
    #member_of = request_json("GET", f"{base}/memberOf", headers=headers)
    transitive = request_json(
        "GET",
        f"{base}/transitiveMemberOf",
        headers={**headers, "Accept": FULL_METADATA_ACCEPT},
        params=TRANSITIVE_PARAMS,
    )
    mfa = request_json("GET", f"{base}/authentication/methods", headers=headers)
    owned = request_json("GET", f"{base}/ownedObjects", headers=headers)
    app_roles = request_json("GET", f"{base}/appRoleAssignments", headers=headers)

    transitive_value = transitive.get("value", [])

    # parse from basic info
    result = {
        **{field: basic_info.get(field) for field in BASIC_FIELDS},
        "groups":    [ {k: v for k, v in m.items() if k in GROUP_FIELDS} for m in transitive_value if m.get("@odata.type") == "#microsoft.graph.group" ],
        "roles":     [ {k: v for k, v in m.items() if k in ROLE_FIELDS} for m in  transitive_value if m.get("@odata.type") == "#microsoft.graph.directoryRole" ],
        "mfa":       mfa.get("value", mfa),  
        "owned":     owned.get("value", []),
        "app_roles": app_roles.get("value", []),
    }

    result["mfa_exclusion_groups"] = [
        g.get("displayName") for g in result["groups"]
        if any(p in g.get("displayName", "").lower() 
               for p in MFA_EXCLUSION_PATTERNS)
    ]

    render(console, f"Information for {username}", USERINFO_COLUMNS, result, output=output, xml_item_tag="user")