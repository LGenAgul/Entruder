import typer

from entruder.static import MFA_SWEEP_RESOURCES, FOCI_CLIENTS
from entruder.utils import (
    handle_cli_errors,
    parse_token,
    request_json,
    vprint,
    require_tenant,
    save_session,
)

from ._shared import login_app, console, classify_ropc_result


@login_app.command("mfasweep")
@handle_cli_errors
def login_mfasweep(
    tenant:   str = typer.Option(None, "-tenant", help="Tenant ID"),
    username: str = typer.Option(..., "-upn", help="Username"),
    password: str = typer.Option(..., "-password", help="Password"),
    resource: str = typer.Option(None, "-resource", help="Limit the sweep to one resource (Optional, default: sweep all known resources)"),
    client_id: str = typer.Option(None, "-clientid", help="Limit the sweep to one client ID (Optional, default: sweep all FOCI client IDs)"),
    unsafe: bool = typer.Option(False, "-unsafe", help="Continue past an account-locked response instead of stopping immediately (Optional, risks worsening the lockout)"),
    user_agent: str = typer.Option(None, "-useragent", help="Hold the User-Agent header fixed to this value across the whole sweep (Optional; to sweep the User-Agent itself, use `login uasweep`)"),
):
    """
    Authenticates against numerous planes to check for a lack of MFA enforcment (Shoutouts to https://github.com/absolomb/FindMeAccess)
    """
    tenant = require_tenant(tenant, console)

    resources = {resource: MFA_SWEEP_RESOURCES.get(resource, resource)} if resource else MFA_SWEEP_RESOURCES
    clients = {"custom": client_id} if client_id else FOCI_CLIENTS
    headers = {"User-Agent": user_agent} if user_agent else None
    total = len(resources) * len(clients)

    console.print(f"[bold]Sweeping {len(resources)} resource(s) x {len(clients)} client ID(s) "
                  f"({total} combinations) for {username}[/]\n")

    gaps = []
    for res_name, resource_url in resources.items():
        for client_name, sweep_client_id in clients.items():
            vprint(f"Trying {res_name} / {client_name}")
            result = request_json(
                "POST",
                f"https://login.microsoftonline.com/{tenant}/oauth2/token",
                data={
                    "grant_type": "password",
                    "client_id":  sweep_client_id,
                    "username":   username,
                    "password":   password,
                    "resource":   resource_url,
                },
                headers=headers,
            )

            status, message = classify_ropc_result(result)

            if status == "gap_no_mfa":
                gaps.append((res_name, client_name, message))
                console.print(f"[bold red][!][/] MFA GAP: {res_name} / {client_name} — no MFA challenge")
                save_session(tenant, sweep_client_id, {res_name: parse_token(result)})
                continue

            if status == "gap_unenrolled":
                gaps.append((res_name, client_name, message))
                console.print(f"[bold red][!][/] MFA GAP: {res_name} / {client_name} — MFA required but not enrolled")
                continue

            if status == "expected_mfa":
                console.print(f"[dim][-] {res_name} / {client_name} — MFA required (expected)[/dim]")
                continue

            if status == "expected_ca":
                console.print(f"[dim][-] {res_name} / {client_name} — blocked by Conditional Access (expected)[/dim]")
                continue

            if status == "fatal_wrong_password":
                console.print(f"[bold red][-][/] {message} — stopping sweep, password is wrong for every remaining combination")
                raise typer.Exit(1)

            if status == "fatal_account_missing":
                console.print(f"[bold red][-][/] {message} — stopping sweep")
                raise typer.Exit(1)

            if status == "locked":
                console.print(f"[bold red][-][/] {message}")
                if not unsafe:
                    console.print("[dim]Stopping to avoid worsening the lockout. Pass -unsafe to continue anyway.[/dim]")
                    raise typer.Exit(1)
                console.print("[dim]-unsafe set, continuing despite lockout[/dim]")
                continue

            # anything else: log and keep going rather than assuming it's fatal
            console.print(f"[dim][-] {res_name} / {client_name} — {message}[/dim]")

    console.print()
    if gaps:
        console.print(f"[bold red]{len(gaps)} MFA gap(s) found for {username}:[/]")
        for res_name, client_name, reason in gaps:
            console.print(f"  - {res_name} / {client_name}: {reason}")
        console.print("[dim]Gap sessions were saved — pick them up with `entruder enum ...`[/dim]")
    else:
        console.print(f"[bold green]No MFA gaps found for {username} across {total} combination(s)[/]")
