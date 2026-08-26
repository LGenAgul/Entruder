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

from ._shared import enum_app, console, columns, prepare_session


@enum_app.command("subs")
@handle_cli_errors
def enum_subscriptions(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
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


@enum_app.command("resources")
@handle_cli_errors
def enum_resources(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    sub: str = typer.Option(None, "-s", "--sub-id", help="Subscription Id"),
    type: str = typer.Option(None, "-y", "--type", help="Resource Type"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Enumerate resources within a subscription"""
    # explicitly ask for subid
    if not sub:
         console.print(f"[bold red][-][/] Please provide a subscription Id explicitly")
         raise typer.Exit(1)

    tenant, headers = prepare_session(tenant, client_id, "management")

    url = f"https://management.azure.com/subscriptions/{sub}/resources"
    params = {"api-version": API_VERSIONS["management"]}

    if type:
        params["$filter"] = f"resourceType eq '{type}'"

    resources = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Management request failed: {parse_error(message)}")
            raise typer.Exit(1)

        resources.extend(result["value"])
        url = result.get("nextLink")
        params = None

    render(console, f"Resources in {tenant}", columns.RESOURCE, resources,
           output=output, xml_root_tag="resources", xml_item_tag="resource")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(resources)}[/] resources total")
