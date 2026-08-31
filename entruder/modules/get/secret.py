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

from ._shared import get_app, console, columns, prepare_session


def _kv_item_name(item_id):
    """Key Vault responses only give the full item id
    (https://vault.vault.azure.net/{kind}/{name}); the name is the last path
    segment."""
    return (item_id or "").rstrip("/").rsplit("/", 1)[-1]


@get_app.command("secret-value")
@handle_cli_errors
def get_secret_value(
    vault: str = typer.Option(..., "-v", "--vault", help="Key Vault name (without .vault.azure.net)"),
    secret: str = typer.Option(..., "-s", "--secret", help="Secret name"),
    version: str = typer.Option(None, "-e", "--version", help="Specific version (defaults to the current version)"),
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    output: OutputFormat = output_option(),
):
    """Retrieve one secret's actual value. (requires a keyvault token)"""
    tenant, headers = prepare_session(tenant, client_id, "keyvault")
    url = f"https://{vault}.vault.azure.net/secrets/{secret}"
    if version:
        url += f"/{version}"
    params = {"api-version": API_VERSIONS["keyvault"]}

    vprint(f"GET {url}")
    result = request_json("GET", url, headers=headers, params=params)
    if "value" not in result:
        error = result.get("error", {})
        message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
        console.print(f"[bold red][-][/] Key Vault request failed: {parse_error(message)}")
        raise typer.Exit(1)

    # a resolved secret's id is always .../secrets/{name}/{version}, even when
    # --version wasn't passed, so the version comes from the id, not the input
    attrs = result.get("attributes", {}) or {}
    row = {
        "name":        secret,
        "value":       result.get("value"),
        "contentType": result.get("contentType"),
        "version":     _kv_item_name(result.get("id")),
        "enabled":     attrs.get("enabled"),
        "expires":     attrs.get("exp"),
    }
    render(console, f"{vault}/{secret}", columns.SECRETVALUE, row, output=output, xml_item_tag="secret")
