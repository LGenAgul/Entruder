import typer

from entruder.static import API_VERSIONS, DIRECTORY_ROLES
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

from ._shared import enum_app, console, columns, prepare_session, resolve_app_roles, resolve_principal_names


def _role_definition_names(headers, role_definition_ids):
    definitions = {}
    ids = set(filter(None, role_definition_ids))
    for role_definition_id in iter_with_progress(ids, "Resolving role names", key=lambda rid: rid.rsplit("/", 1)[-1]):
        vprint(f"GET {role_definition_id}")
        result = request_json(
            "GET",
            f"https://management.azure.com{role_definition_id}",
            headers=headers,
            params={"api-version": API_VERSIONS["authorization"]},
        )
        props = result.get("properties", {}) or {}
        definitions[role_definition_id] = {
            "roleName":    props.get("roleName", "unknown"),
            "description": props.get("description", "unknown"),
        }
    return definitions


def _directory_role_definition_names(headers, graph_url_base, role_definition_ids):
    ids = set(filter(None, role_definition_ids))
    definitions = {}
    for role_id in iter_with_progress(ids, "Resolving role names", key=lambda rid: rid):
        builtin = DIRECTORY_ROLES.get(role_id)
        if builtin:
            definitions[role_id] = {"roleName": builtin["name"], "tier": builtin["tier"]}
            continue
        vprint(f"GET {graph_url_base}/roleManagement/directory/roleDefinitions/{role_id}")
        result = request_json(
            "GET",
            f"{graph_url_base}/roleManagement/directory/roleDefinitions/{role_id}",
            headers=headers,
        )
        definitions[role_id] = {"roleName": result.get("displayName", "unknown"), "tier": "custom"}
    return definitions


def _graph_pim_eligibility(headers, graph_url_base):
    url = f"{graph_url_base}/roleManagement/directory/roleEligibilityScheduleInstances/filterByCurrentUser(on='principal')"
    vprint(f"GET {url}")
    result = request_json("GET", url, headers=headers)
    if "value" not in result:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        console.print(f"[dim][-] Entra PIM eligibility check skipped: {parse_error(message)}[/dim]")
        return []
    return result["value"]


def _arm_pim_eligibility(headers, arm_url_base):
    url = f"{arm_url_base}/Microsoft.Authorization/roleEligibilityScheduleInstances"
    params = {"api-version": API_VERSIONS["authorization_pim"], "$filter": "asTarget()"}
    vprint(f"GET {url}")
    result = request_json("GET", url, headers=headers, params=params)
    if "value" not in result:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        console.print(f"[dim][-] Azure PIM eligibility check skipped: {parse_error(message)}[/dim]")
        return []
    return [{**a.get("properties", {}), "id": a.get("id")} for a in result["value"]]


@enum_app.command("privs")
@handle_cli_errors
def enum_priv(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    sub: str = typer.Option(None, "-s", "--sub-id", help="Subscription Id of the target (Mandatory)"),
    output: OutputFormat = output_option()
    ):
    """Enumerate Your Users Privileges (requires a graph AND management token)"""
    if not sub:
        console.print(f"[bold red][-][/] Please provide a subscription Id explicitly")
        raise typer.Exit(1)

    tenant, arm_headers = prepare_session(tenant, client_id, "management")
    _, graph_headers = prepare_session(tenant, client_id, "graph")

    graph_url_base = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"
    arm_url_base = f"https://management.azure.com/subscriptions/{sub}/providers"

    # start with the graph plane
    vprint(f"GET {graph_url_base}/me")
    me = request_json("GET",f"{graph_url_base}/me", headers=graph_headers)
    if not me.get("id"):
        error = me.get("error", {})
        message = error.get("message") if isinstance(error, dict) else me.get("error_description", "Unknown error")
        console.print(f"[bold red][-][/] Graph request failed: {parse_error(message)}")
        console.print("[dim]this needs a delegated (user) session log in via "
                      "ropc/device/authcode, not secret/cert/foci/kerberos[/dim]")
        raise typer.Exit(1)

    vprint(f"GET {graph_url_base}/me/transitive/MemberOf")
    transitive_member_of = request_json("GET",f"{graph_url_base}/me/transitiveMemberOf", headers=graph_headers)
    vprint(f"GET {graph_url_base}/me/memberOf/microsoft.graph.administrativeUnit")
    administrative_unit_membership = request_json("GET",f"{graph_url_base}/me/memberOf/microsoft.graph.administrativeUnit", headers=graph_headers)
    vprint(f"GET {graph_url_base}/me/ownedObjects")
    owned = request_json("GET",f"{graph_url_base}/me/ownedObjects", headers=graph_headers)
    vprint(f"GET {graph_url_base}/me/appRoleAssignments")
    app_role_assignments = request_json("GET",f"{graph_url_base}/me/appRoleAssignments", headers=graph_headers)

    # setting up a filter for assignments on my user
    params = {"$filter":f"principalId eq '{me['id']}'",
              "api-version":"2022-04-01"}
    # now the management plane
    vprint(f"GET {arm_url_base}/Microsoft.Authorization/roleAssignments)")
    assignments = request_json("GET",f"{arm_url_base}/Microsoft.Authorization/roleAssignments",headers=arm_headers,params=params)

    # PIM roles
    eligible_directory_roles = _graph_pim_eligibility(graph_headers, graph_url_base)
    eligible_azure_role_assignments = _arm_pim_eligibility(arm_headers, arm_url_base)

    app_role_assignments_value = resolve_app_roles(
        graph_headers, graph_url_base, app_role_assignments.get("value", [])
    )

    transitive_value = transitive_member_of.get("value", [])
    azure_role_assignments = [
        {**a.get("properties", {}), "roleAssignmentId": a.get("id")}
        for a in assignments.get("value", [])
    ]
    role_definitions = _role_definition_names(
        arm_headers, [a.get("roleDefinitionId") for a in azure_role_assignments]
    )
    for a in azure_role_assignments:
        a.update(role_definitions.get(a.get("roleDefinitionId"), {"roleName": "unknown", "description": "unknown"}))

    principal_names = resolve_principal_names(
        graph_headers, graph_url_base,
        [a.get("createdBy") for a in azure_role_assignments] +
        [a.get("updatedBy") for a in azure_role_assignments],
    )
    for a in azure_role_assignments:
        a["createdByUpn"] = principal_names.get(a.get("createdBy"), a.get("createdBy"))
        a["updatedByUpn"] = principal_names.get(a.get("updatedBy"), a.get("updatedBy"))

    eligible_directory_role_defs = _directory_role_definition_names(
        graph_headers, graph_url_base, [e.get("roleDefinitionId") for e in eligible_directory_roles]
    )
    for e in eligible_directory_roles:
        e.update(eligible_directory_role_defs.get(e.get("roleDefinitionId"), {"roleName": "unknown", "tier": "unknown"}))

    eligible_azure_role_defs = _role_definition_names(
        arm_headers, [e.get("roleDefinitionId") for e in eligible_azure_role_assignments]
    )
    for e in eligible_azure_role_assignments:
        e.update(eligible_azure_role_defs.get(e.get("roleDefinitionId"), {"roleName": "unknown", "description": "unknown"}))

    result = {
        "displayName":             me.get("displayName"),
        "userPrincipalName":       me.get("userPrincipalName"),
        "id":                      me.get("id"),
        "groups":                  [m for m in transitive_value if m.get("@odata.type") == "#microsoft.graph.group"],
        "directory_roles":         [m for m in transitive_value if m.get("@odata.type") == "#microsoft.graph.directoryRole"],
        "eligible_directory_roles": eligible_directory_roles,
        "administrative_units":    administrative_unit_membership.get("value", []),
        "owned":                   owned.get("value", []),
        "app_role_assignments":    app_role_assignments_value,
        "azure_role_assignments":  azure_role_assignments,
        "eligible_azure_role_assignments": eligible_azure_role_assignments,
    }

    render(console, f"Privileges for {tenant}", columns.PRIV, result, output=output, xml_item_tag="privileges")
