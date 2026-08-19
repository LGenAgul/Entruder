import typer

from entruder.globals import API_VERSIONS
from entruder.utils import (
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import enum_app, console, columns, prepare_session, graph_collect, resolve_principal_names


@enum_app.command("roles")
@handle_cli_errors
def enum_roles(
    tenant:    str = typer.Option(None, "-tenant"),
    client_id: str = typer.Option(None, "-clientid"),
    role:      str = typer.Option(None, "-role",
        help="Filter by role name e.g. 'Global Administrator' (Optional)"),
    upn:       str = typer.Option(None, "-upn",
        help="Filter by user UPN (Optional)"),
    output:    OutputFormat = output_option(),
):
    """Enumerate tenant wide Entra directory role assignments, who has what role"""
    tenant, headers = prepare_session(tenant, client_id, "graph")
    graph = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"

    assignments = graph_collect(
        f"{graph}/roleManagement/directory/roleAssignments",
        headers, params={"$expand": "roleDefinition"},
    )

    principal_names = resolve_principal_names(
        headers, graph, [a.get("principalId") for a in assignments]
    )

    rows = []
    for a in assignments:
        role_definition = a.get("roleDefinition") or {}
        row = {
            "roleName":         role_definition.get("displayName", "unknown"),
            "principalId":      a.get("principalId"),
            "principalName":    principal_names.get(a.get("principalId"), a.get("principalId")),
            "directoryScopeId": a.get("directoryScopeId"),
            "appScopeId":       a.get("appScopeId"),
        }
        if role and role.lower() not in (row["roleName"] or "").lower():
            continue
        if upn and upn.lower() not in (row["principalName"] or "").lower():
            continue
        rows.append(row)

    render(console, f"Directory role assignments in {tenant}", columns.ROLE, rows,
           output=output, xml_root_tag="roles", xml_item_tag="assignment")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(rows)}[/] role assignments total")
