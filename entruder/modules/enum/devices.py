import typer

from entruder.static import API_VERSIONS
from entruder.utils import (
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
    vprint
)

from ._shared import enum_app, console, columns, prepare_session, graph_collect


def _owner_role_names(headers, graph_url_base):
    """Maps principalId -> sorted directory role display names, so devices can
    be filtered/labelled by the roles held by their registered owners — e.g.
    surfacing endpoints belonging to a Global Administrator."""
    assignments = graph_collect(
        f"{graph_url_base}/roleManagement/directory/roleAssignments",
        headers, params={"$expand": "roleDefinition"},
    )
    roles_by_principal = {}
    for a in assignments:
        role_definition = a.get("roleDefinition") or {}
        role_name = role_definition.get("displayName")
        principal_id = a.get("principalId")
        if not role_name or not principal_id:
            continue
        roles_by_principal.setdefault(principal_id, set()).add(role_name)
    return roles_by_principal


@enum_app.command("devices")
@handle_cli_errors
def enum_devices(
    tenant:    str = typer.Option(None, "-t", "--tenant"),
    client_id: str = typer.Option(None, "-c", "--client-id"),
    role:      str = typer.Option(None, "-r", "--role",
        help="Filter by the directory role name of a registered owner e.g. 'Global Administrator' (Optional)"),
    upn:       str = typer.Option(None, "-u", "--upn",
        help="Filter by registered owner UPN (Optional)"),
    output:    OutputFormat = output_option(),
):
    """Enumerate tenant wide registered devices (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")
    graph = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"
    devices = graph_collect(
        f"{graph}/devices",
        headers,
        params={"$expand": "registeredOwners($select=id,displayName,userPrincipalName)"},
    )
    vprint(f"{len(devices)} devices collected")

    owner_roles = _owner_role_names(headers, graph)
    vprint(f"{len(owner_roles)} owner roles collected")
    rows = []
    for d in devices:
        owners = d.get("registeredOwners") or []
        owner_role_names = sorted({
            role_name
            for owner in owners
            for role_name in owner_roles.get(owner.get("id"), set())
        })

        row = {
            "displayName":                   d.get("displayName"),
            "deviceId":                      d.get("deviceId"),
            "operatingSystem":               d.get("operatingSystem"),
            "operatingSystemVersion":        d.get("operatingSystemVersion"),
            "trustType":                     d.get("trustType"),
            "deviceOwnership":               d.get("deviceOwnership"),
            "accountEnabled":                d.get("accountEnabled"),
            "isCompliant":                   d.get("isCompliant"),
            "isManaged":                     d.get("isManaged"),
            "mdmAppId":                      d.get("mdmAppId"),
            "registrationDateTime":          d.get("registrationDateTime"),
            "approximateLastSignInDateTime": d.get("approximateLastSignInDateTime"),
            "registeredOwners":              owners,
            "ownerRoles":                    owner_role_names,
        }

        if upn and not any(upn.lower() in (o.get("userPrincipalName") or "").lower() for o in owners):
            continue
        if role and not any(role.lower() in r.lower() for r in owner_role_names):
            continue
        rows.append(row)

    render(console, f"Registered devices in {tenant}", columns.DEVICE, rows,
           output=output, xml_root_tag="devices", xml_item_tag="device")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(rows)}[/] devices total")
