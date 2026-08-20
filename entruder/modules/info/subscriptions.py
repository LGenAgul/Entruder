import typer

from entruder.static import API_VERSIONS
from entruder.utils import (
    parse_error,
    request_json,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import info_app, console, columns, prepare_session


@info_app.command("subs")
@handle_cli_errors
def enum_subscriptions(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Enumerate subscriptions associated to this tenant"""

    tenant, headers = prepare_session(tenant, client_id, "management")

    url = f"https://management.azure.com/subscriptions"
    params = {"api-version": API_VERSIONS["management"]}
    subscriptions = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Management request failed: {parse_error(message)}")
            raise typer.Exit(1)

        subscriptions.extend(result["value"])
        url = result.get("nextLink")  # ARM uses nextLink, not @odata.nextLink
        params = None  # nextLink already carries api-version

    render(console, f"Subscriptions in {tenant}", columns.SUBSCRIPTION, subscriptions,
           output=output, xml_root_tag="subscriptions", xml_item_tag="subscription")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(subscriptions)}[/] subscriptions total")
