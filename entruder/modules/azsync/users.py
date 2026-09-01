from ._shared import azsync_app, console, columns
from entruder.globals import prepare_session, graph_collect, typer
from entruder.static import API_VERSIONS
from entruder.utils import handle_cli_errors, render, OutputFormat, output_option


AZSYNC_USER_SELECT = (
    "id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,"
    "onPremisesDomainName,onPremisesSamAccountName,onPremisesDistinguishedName,"
    "onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesProvisioningErrors"
)


@azsync_app.command("users")
@handle_cli_errors
def azsync_users(
        tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
        client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
        output: OutputFormat = output_option(),
):
    """Enumerate directory users that are synced from on-prem AD via AD Sync/Entra Connect (requires a graph token)"""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/users"
    params = {
        "$select": AZSYNC_USER_SELECT,
        "$filter": "onPremisesSyncEnabled eq true",
        "$count": "true",
    }
    headers = {**headers, "ConsistencyLevel": "eventual"}

    users = graph_collect(url, headers, params=params)

    render(console, f"AD Sync synced users in {tenant}", columns.AZSYNC_USER, users,
           output=output, xml_root_tag="users", xml_item_tag="user")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(users)}[/] synced users total")
