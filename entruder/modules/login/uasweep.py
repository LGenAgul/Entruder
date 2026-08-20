import typer

from entruder.static import MFA_SWEEP_RESOURCES, USER_AGENT_SWEEP
from entruder.utils import (
    handle_cli_errors,
    parse_token,
    request_json,
    vprint,
    require_tenant,
    save_session,
)

from ._shared import login_app, console, classify_ropc_result


@login_app.command("uasweep")
@handle_cli_errors
def login_uasweep(
    tenant:      str = typer.Option(None, "-tenant", help="Tenant ID"),
    username:    str = typer.Option(..., "-upn", help="Username"),
    password:    str = typer.Option(..., "-password", help="Password"),
    client_id:   str = typer.Option(..., "-clientid", help="Client ID to authenticate with"),
    resource:    str = typer.Option("graph", "-resource", help="Target resource for the sweep (Optional, default: graph)"),
    user_agent:  str = typer.Option(None, "-useragent", help="Test a single custom User-Agent instead of sweeping the built-in list"),
    unsafe:      bool = typer.Option(False, "-unsafe", help="Continue past an account-locked response instead of stopping immediately (Optional, risks worsening the lockout)"),
):
    """
    Authenticates to a resource using a  range of User-Agent strings to check whether Conditional Access fails to enforce MFA 
    """
    tenant = require_tenant(tenant, console)
    resource_url = MFA_SWEEP_RESOURCES.get(resource, resource)

    user_agents = {"custom": user_agent} if user_agent else USER_AGENT_SWEEP
    total = len(user_agents)

    console.print(f"[bold]Sweeping {total} User-Agent(s) against {resource} for {username}[/]\n")

    gaps = []
   
    for ua_name, ua_value in user_agents.items():
        vprint(f"Trying User-Agent: {ua_name}")
        headers = {"User-Agent": ua_value} if ua_value is not None else None
        result = request_json(
            "POST",
            f"https://login.microsoftonline.com/{tenant}/oauth2/token",
            data={
                "grant_type": "password",
                "client_id":  client_id,
                "username":   username,
                "password":   password,
                "resource":   resource_url,
            },
            headers=headers,
        )

        status, message = classify_ropc_result(result)

        if status == "gap_no_mfa":
            gaps.append((ua_name, message))
            console.print(f"[bold red][!][/] MFA GAP: {ua_name}. No MFA challenge")
            console.print(f"[bold] User-Agent:[/] {ua_value}")
            continue

        if status == "gap_unenrolled":
            gaps.append((ua_name, message))
            console.print(f"[bold red][!][/] MFA GAP: {ua_name}. MFA required but not enrolled")
            continue

        if status == "expected_mfa":
            console.print(f"[dim][-] {ua_name}: MFA required (expected)[/dim]")
            continue

        if status == "expected_ca":
            console.print(f"[dim][-] {ua_name}: blocked by Conditional Access (expected)[/dim]")
            continue

        if status == "fatal_wrong_password":
            console.print(f"[bold red][-][/] {message}: stopping sweep, password is wrong for every remaining User-Agent")
            raise typer.Exit(1)

        if status == "fatal_account_missing":
            console.print(f"[bold red][-][/] {message}: stopping sweep")
            raise typer.Exit(1)

        if status == "locked":
            console.print(f"[bold red][-][/] {message}")
            if not unsafe:
                console.print("[dim]Stopping to avoid worsening the lockout. Pass -unsafe to continue anyway.[/dim]")
                raise typer.Exit(1)
            console.print("[dim]-unsafe set, continuing despite lockout[/dim]")
            continue

        # anything else: log and keep going rather than assuming it's fatal
        console.print(f"[dim][-] {ua_name} : {message}[/dim]")

    if not gaps:
        console.print(f"\r\n[bold green]No User-Agent MFA gaps found for {username} across {total} User-Agent(s)[/]")
