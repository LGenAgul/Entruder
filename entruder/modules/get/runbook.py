import typer
import httpx

from entruder.static import API_VERSIONS, HTTP_TIMEOUT
from entruder.utils import (
    parse_error,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import get_app, console, columns, prepare_session


@get_app.command("runbook-content")
@handle_cli_errors
def get_runbook_content(
    runbook: str = typer.Option(..., "-b", "--runbook", help="Runbook name (see `enum runbooks`)"),
    account: str = typer.Option(..., "-a", "--account", help="Automation Account name"),
    rg: str = typer.Option(..., "-r", "--rg", help="Resource group the account lives in"),
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    sub: str = typer.Option(None, "-s", "--sub-id", help="Subscription Id"),
    output: OutputFormat = output_option(),
):
    """Retrieve a runbook's actual script content, which potentially hides credentials (requires a management token)"""
    if not sub:
        console.print(f"[bold red][-][/] Please provide a subscription Id explicitly")
        raise typer.Exit(1)

    tenant, headers = prepare_session(tenant, client_id, "management")

    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
           f"/providers/Microsoft.Automation/automationAccounts/{account}/runbooks/{runbook}/content")
    params = {"api-version": API_VERSIONS["automation"]}

    vprint(f"GET {url}")
    response = httpx.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    vprint(f"  -> HTTP {response.status_code} ({len(response.content)} bytes)")
    if response.status_code != 200:
        try:
            error = response.json().get("error", {})
            message = error.get("message", "Unknown error")
        except Exception:
            message = response.text[:200]
        console.print(f"[bold red][-][/] Management request failed: HTTP {response.status_code} {parse_error(message)}")
        raise typer.Exit(1)

    row = {"name": runbook, "content": response.text}
    render(console, f"{account}/{runbook}", columns.RUNBOOK_CONTENT, row, output=output, xml_item_tag="runbook")
