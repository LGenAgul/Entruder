import typer

from entruder.static import API_VERSIONS, SP_PARAMS, MS_FIRST_PARTY_TENANT_ID
from entruder.utils import (
    parse_error,
    request_json,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import enum_app, console, columns, prepare_session


@enum_app.command("sp")
@handle_cli_errors
def enum_serviceprincipals(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    owned: bool = typer.Option(False, "-w", "--owned",
        help="Only show service principals owned by the current signed-in user (Optional) (requires a delegated session, ropc/device/authcode)"
             "(requires a delegated session, ropc/device/authcode, not app-only secret/cert/foci/kerberos)"),
    non_default: bool = typer.Option(False, "-n", "--non-default",
        help="Hide Microsoft first-party service principals (Graph, Exchange Online, Teams, etc.) (Optional) "),
    output: OutputFormat = output_option(),
    ):
    """Enumerate service principals via Microsoft Graph (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

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
                console.print("[dim]--owned requires a delegated (user) session log in via ropc/device/authcode, not secret/cert/foci/kerberos[/dim]")
            raise typer.Exit(1)

        batch = result["value"]
        if owned:
            # /me/ownedObjects is polymorphic (apps, groups, service principals, ...)
            batch = [obj for obj in batch if obj.get("@odata.type") == "#microsoft.graph.servicePrincipal"]
        service_principals.extend(batch)
        url = result.get("@odata.nextLink")

    if non_default:
        service_principals = [
            sp for sp in service_principals
            if sp.get("appOwnerOrganizationId") != MS_FIRST_PARTY_TENANT_ID
        ]

    title = f"Service Principals in {tenant}" + (" (owned by current user)" if owned else "")
    if non_default:
        title += " (non-default)"
    render(console, title, columns.SP, service_principals, output=output,
           xml_root_tag="serviceprincipals", xml_item_tag="serviceprincipal")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(service_principals)}[/] service principals total")
