import typer

from entruder.static import (
    API_VERSIONS,
    BASIC_FIELDS,
    BASIC_PARAMS,
    TRANSITIVE_PARAMS,
    FULL_METADATA_ACCEPT,
    GROUP_FIELDS,
    ROLE_FIELDS,
)
from entruder.utils import (
    request_json,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
    parse_error,
)

from ._shared import info_app, console, columns, prepare_session, resolve_app_roles


@info_app.command("users")
@handle_cli_errors
def enum_users(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    output: OutputFormat = output_option(),
):
    """Enumerate directory users via Microsoft Graph, using a saved graph session"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

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
    render(console, f"Users in {tenant}", columns.USER, users, output=output, xml_root_tag="users", xml_item_tag="user")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(users)}[/] users total")


@info_app.command("user")
@handle_cli_errors
def enum_userinfo(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    username: str = typer.Option(...,"-upn",help="userPrincipalName/email of the target user"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Query a specific user's information, provides more details than the users command"""
    from entruder.static import MFA_EXCLUSION_PATTERNS
    tenant, headers = prepare_session(tenant, client_id, "graph")

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
    app_roles_value = resolve_app_roles(
        headers, f"https://graph.microsoft.com/{API_VERSIONS['graph']}", app_roles.get("value", [])
    )

    transitive_value = transitive.get("value", [])

    # parse from basic info
    result = {
        **{field: basic_info.get(field) for field in BASIC_FIELDS},
        "groups":    [ {k: v for k, v in m.items() if k in GROUP_FIELDS} for m in transitive_value if m.get("@odata.type") == "#microsoft.graph.group" ],
        "roles":     [ {k: v for k, v in m.items() if k in ROLE_FIELDS} for m in  transitive_value if m.get("@odata.type") == "#microsoft.graph.directoryRole" ],
        "mfa":       mfa.get("value", mfa),
        "owned":     owned.get("value", []),
        "app_roles": app_roles_value,
    }

    result["mfa_exclusion_groups"] = [
        g.get("displayName") for g in result["groups"]
        if any(p in g.get("displayName", "").lower()
               for p in MFA_EXCLUSION_PATTERNS)
    ]

    render(console, f"Information for {username}", columns.USERINFO, result, output=output, xml_item_tag="user")


