import typer

from entruder.static import API_VERSIONS
from entruder.utils import (
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
    vprint
)

from ._shared import enum_app, console, columns, prepare_session, graph_collect, resolve_principal_names


@enum_app.command("consents")
@handle_cli_errors
def enum_consents(
    tenant:    str = typer.Option(None, "-t", "--tenant"),
    client_id: str = typer.Option(None, "-c", "--client-id"),
    client:    str = typer.Option(None, "-l", "--client",
        help="Filter by client app name e.g. 'My Risky App' (Optional)"),
    admin_consented: bool = typer.Option(False, "-a", "--admin-consented",
        help="Only show org-wide grants (consentType 'AllPrincipals') — scopes every "
             "user in the tenant is implicitly consenting to just by using the app"),
    output:    OutputFormat = output_option(),
):
    """Enumerate OAuth2 delegated permission grants, which apps hold what delegated scopes on whose behalf. (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")
    graph = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"
    vprint(f"GET {graph}/oauth2PermissionGrants")
    
    grants = graph_collect(f"{graph}/oauth2PermissionGrants", headers)
    vprint(f"{len(grants)} grants retrieved, resolving principal names...")
    principal_names = resolve_principal_names(
        headers, graph,
        [g.get("clientId") for g in grants] +
        [g.get("resourceId") for g in grants] +
        [g.get("principalId") for g in grants],
    )
    vprint(f"{len(principal_names)} resolved, retreiving grants...")
    rows = []
    for g in grants:
        row = {
            "clientAppName":   principal_names.get(g.get("clientId"), g.get("clientId")),
            "clientId":        g.get("clientId"),
            "resourceAppName": principal_names.get(g.get("resourceId"), g.get("resourceId")),
            "resourceId":      g.get("resourceId"),
            "consentType":     g.get("consentType"),
            "principalName":   principal_names.get(g.get("principalId"), "All Users (org-wide)"),
            "scopes":          (g.get("scope") or "").split(),
        }
        if client and client.lower() not in (row["clientAppName"] or "").lower():
            continue
        if admin_consented and row["consentType"] != "AllPrincipals":
            continue
        rows.append(row)

    render(console, f"OAuth2 delegated permission grants in {tenant}", columns.CONSENT, rows,
           output=output, xml_root_tag="consents", xml_item_tag="grant")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(rows)}[/] delegated permission grants total")
