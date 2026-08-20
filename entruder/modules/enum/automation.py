import json

import typer
import httpx

from entruder.static import API_VERSIONS, HTTP_TIMEOUT
from entruder.utils import (
    parse_error,
    request_json,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import enum_app, console, columns, prepare_session, resource_group_from_id


def _project_automation_account(acct):
    """Flatten a raw ARM Automation Account resource into the exposure-relevant
    shape the AUTOMATION_ACCOUNT columns expect, mirroring _project_storage /
    _project_vault. Managed identity is the headline field here — an
    over-privileged system/user-assigned identity on an Automation Account is
    a classic priv-esc target since runbooks execute as that identity."""
    props = acct.get("properties", {}) or {}
    identity = acct.get("identity") or {}
    return {
        "id":                     acct.get("id"),
        "name":                   acct.get("name"),
        "resource_group":         resource_group_from_id(acct.get("id")),
        "location":               acct.get("location"),
        "state":                  props.get("state"),
        "sku":                    (props.get("sku") or {}).get("name"),
        "public_network":         props.get("publicNetworkAccess"),
        "disable_local_auth":     props.get("disableLocalAuth"),
        "identity_type":          identity.get("type"),
        "identity_principal_id":  identity.get("principalId"),
        "created":                props.get("creationTime"),
    }


def _project_runbook(rb):
    props = rb.get("properties", {}) or {}
    return {
        "name":          rb.get("name"),
        "runbook_type":  props.get("runbookType"),
        "state":         props.get("state"),
        "log_verbose":   props.get("logVerbose"),
        "log_progress":  props.get("logProgress"),
        "description":   props.get("description"),
        "created":       props.get("creationTime"),
        "last_modified": props.get("lastModifiedTime"),
    }


def _project_variable(var):
    """Automation variable values come back JSON-encoded (a plain string value
    is literally `"foo"`, quotes included) — unwrap that so the cell shows the
    real value. Encrypted variables never return a value over the API at all,
    regardless of caller privilege; `encrypted` tells you which is which."""
    props = var.get("properties", {}) or {}
    raw_value = props.get("value")
    if raw_value is not None:
        try:
            raw_value = json.loads(raw_value)
        except (TypeError, ValueError):
            pass
    return {
        "name":          var.get("name"),
        "encrypted":     props.get("isEncrypted"),
        "value":         raw_value,
        "description":   props.get("description"),
        "created":       props.get("creationTime"),
        "last_modified": props.get("lastModifiedTime"),
    }


@enum_app.command("automation-accounts")
@handle_cli_errors
def enum_automation_accounts(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    sub: str = typer.Option(None, "-subid", help="Subscription Id"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Enumerate Automation Accounts in a subscription."""
    if not sub:
        console.print(f"[bold red][-][/] Please provide a subscription Id explicitly")
        raise typer.Exit(1)

    tenant, headers = prepare_session(tenant, client_id, "management")

    url = f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Automation/automationAccounts"
    params = {"api-version": API_VERSIONS["automation"]}

    accounts = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Management request failed: {parse_error(message)}")
            raise typer.Exit(1)

        accounts.extend(result["value"])
        url = result.get("nextLink")
        params = None

    accounts = [_project_automation_account(a) for a in accounts]
    render(console, f"Automation Accounts in {tenant}", columns.AUTOMATION_ACCOUNT, accounts,
           output=output, xml_root_tag="automationAccounts", xml_item_tag="account")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(accounts)}[/] automation accounts total")


@enum_app.command("runbooks")
@handle_cli_errors
def enum_runbooks(
    account: str = typer.Option(..., "-account", help="Automation Account name (see `enum automation-accounts`)"),
    rg: str = typer.Option(..., "-rg", help="Resource group the account lives in"),
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    sub: str = typer.Option(None, "-subid", help="Subscription Id"),
    output: OutputFormat = output_option(),
):
    """List runbooks in an Automation Account."""
    if not sub:
        console.print(f"[bold red][-][/] Please provide a subscription Id explicitly")
        raise typer.Exit(1)

    tenant, headers = prepare_session(tenant, client_id, "management")

    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
           f"/providers/Microsoft.Automation/automationAccounts/{account}/runbooks")
    params = {"api-version": API_VERSIONS["automation"]}

    runbooks = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Management request failed: {parse_error(message)}")
            raise typer.Exit(1)

        runbooks.extend(result["value"])
        url = result.get("nextLink")
        params = None

    runbooks = [_project_runbook(r) for r in runbooks]
    render(console, f"Runbooks in {account}", columns.RUNBOOK, runbooks,
           output=output, xml_root_tag="runbooks", xml_item_tag="runbook")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(runbooks)}[/] runbooks total")


@enum_app.command("runbook-content")
@handle_cli_errors
def enum_runbook_content(
    runbook: str = typer.Option(..., "-runbook", help="Runbook name (see `enum runbooks`)"),
    account: str = typer.Option(..., "-account", help="Automation Account name"),
    rg: str = typer.Option(..., "-rg", help="Resource group the account lives in"),
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    sub: str = typer.Option(None, "-subid", help="Subscription Id"),
    output: OutputFormat = output_option(),
):
    """Retrieve a runbook's actual script content, which potentially hides credentials"""
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


@enum_app.command("automation-variables")
@handle_cli_errors
def enum_automation_variables(
    account: str = typer.Option(..., "-account", help="Automation Account name (see `enum automation-accounts`)"),
    rg: str = typer.Option(..., "-rg", help="Resource group the account lives in"),
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    sub: str = typer.Option(None, "-subid", help="Subscription Id"),
    output: OutputFormat = output_option(),
):
    """List variables in an Automation Account."""
    if not sub:
        console.print(f"[bold red][-][/] Please provide a subscription Id explicitly")
        raise typer.Exit(1)

    tenant, headers = prepare_session(tenant, client_id, "management")

    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
           f"/providers/Microsoft.Automation/automationAccounts/{account}/variables")
    params = {"api-version": API_VERSIONS["automation"]}

    variables = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Management request failed: {parse_error(message)}")
            raise typer.Exit(1)

        variables.extend(result["value"])
        url = result.get("nextLink")
        params = None

    variables = [_project_variable(v) for v in variables]
    render(console, f"Variables in {account}", columns.AUTOMATION_VARIABLE, variables,
           output=output, xml_root_tag="variables", xml_item_tag="variable")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(variables)}[/] variables total")
