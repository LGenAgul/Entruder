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

from ._shared import get_app, console, prepare_session, object_columns


def _find_vault_id(headers, sub, vault_name):
    """Key Vault names are globally unique across Azure, like storage account
    names, so at most one vault in a subscription can match. Listing and
    matching by name means the caller doesn't need to already know the
    resource group."""
    url = f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.KeyVault/vaults"
    params = {"api-version": API_VERSIONS["management"]}
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)
        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Management request failed: {parse_error(message)}")
            raise typer.Exit(1)
        for vault in result["value"]:
            if vault.get("name", "").lower() == vault_name.lower():
                return vault["id"]
        url = result.get("nextLink")
        params = None
    return None


@get_app.command("keyvault")
@handle_cli_errors
def get_keyvault(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    vault: str = typer.Option(..., "-v", "--vault", help="Key Vault name (without .vault.azure.net)"),
    sub: str = typer.Option(None, "-s", "--sub-id", help="Subscription Id of the target (Mandatory)"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Fetch a single Key Vault's ARM properties by name. (requires a management token)"""
    if not sub:
        console.print(f"[bold red][-][/] Please provide a subscription Id explicitly")
        raise typer.Exit(1)

    tenant, headers = prepare_session(tenant, client_id, "management")

    vault_id = _find_vault_id(headers, sub, vault)
    if not vault_id:
        console.print(f"[bold red][-][/] No key vault named '{vault}' found in subscription {sub}")
        raise typer.Exit(1)

    vprint(f"GET https://management.azure.com{vault_id}")
    result = request_json("GET", f"https://management.azure.com{vault_id}", headers=headers,
                           params={"api-version": API_VERSIONS["management"]})
    if "error" in result:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        console.print(f"[bold red][-][/] Management request failed: {parse_error(message)}")
        raise typer.Exit(1)

    render(console, f"Key Vault {vault}", object_columns(result), result, output=output, xml_item_tag="vault")
