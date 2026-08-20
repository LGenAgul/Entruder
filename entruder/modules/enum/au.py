import typer

from entruder.static import API_VERSIONS, DIRECTORY_ROLES
from entruder.utils import (
    iter_with_progress,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import enum_app, console, columns, prepare_session, graph_collect


@enum_app.command("au")
@handle_cli_errors
def enum_au(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    members: bool = typer.Option(False, "-members", help="Also enumerate members of each administrative unit"),
    scoped_roles: bool = typer.Option(False, "-scoped-roles",
        help="Also enumerate scoped role assignments (restricted management AU delegation) on each administrative unit"),
    output: OutputFormat = output_option(),
):
    """Enumerate Entra administrative units tenant-wide — delegation boundaries used to scope directory role assignments to a subset of users/groups/devices."""
    tenant, headers = prepare_session(tenant, client_id, "graph")
    graph_url_base = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"

    url = f"{graph_url_base}/directory/administrativeUnits"
    params = {"$select": "id,displayName,description,visibility,membershipType,membershipRule"}

    aus = graph_collect(url, headers, params=params)

    if members or scoped_roles:
        for au in iter_with_progress(aus, "Enriching administrative units", key=lambda a: a.get("displayName")):
            au_id = au["id"]
            if members:
                au["members"] = graph_collect(f"{url}/{au_id}/members", headers)
            if scoped_roles:
                scoped = graph_collect(f"{url}/{au_id}/scopedRoleMembers", headers)
                au["scoped_role_members"] = [
                    f"{DIRECTORY_ROLES.get(s.get('roleId'), {}).get('name', s.get('roleId'))}: "
                    f"{(s.get('roleMemberInfo') or {}).get('displayName') or (s.get('roleMemberInfo') or {}).get('id')}"
                    for s in scoped
                ]

    render(console, f"Administrative Units in {tenant}", columns.ADMIN_UNIT, aus,
           output=output, xml_root_tag="administrativeUnits", xml_item_tag="administrativeUnit")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(aus)}[/] administrative unit(s) total")
