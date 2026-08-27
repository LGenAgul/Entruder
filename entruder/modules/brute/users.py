from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import typer

from entruder.utils import (
    handle_cli_errors,
    iter_futures_with_progress,
    vprint,
    render,
    OutputFormat,
    output_option,
)

from ._shared import brute_app, console, columns


def _read_userlist(path_str: str) -> list:
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(path_str)
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def _check_username(username: str, timeout: int) -> dict:
    """Query Microsoft's unauthenticated GetCredentialType endpoint — no
    token, tenant, or client_id needed, since it's the same check the login
    page itself makes as you type an email in. IfExistsResult == 0 means the
    username maps to a real account somewhere in Entra ID; 1 means it
    doesn't. Same technique o365creeper/MSOLSpray use for pre-spray user
    enumeration."""
    try:
        response = httpx.post(
            "https://login.microsoftonline.com/common/GetCredentialType",
            params={"mkt": "en-US"},
            json={"Username": username},
            timeout=timeout,
        )
        data = response.json()
    except (httpx.HTTPError, ValueError):
        return {"username": username, "exists": None, "throttled": False, "federated": False}

    return {
        "username":  username,
        "exists":    data.get("IfExistsResult") == 0,
        "throttled": bool(data.get("ThrottleStatus")),
        "federated": bool(data.get("FederationRedirectUrl")),
    }


@brute_app.command("users")
@handle_cli_errors
def brute_users(
    userlist: str = typer.Option(..., "-l", "--userlist", help="Path to a file of candidate usernames/emails to check (one per line)"),
    domain: str = typer.Option(None, "-d", "--domain", help="Append this domain to any bare (no @) entries in the list (Optional)"),
    threads: int = typer.Option(5, "-t", "--threads", help="Concurrent requests (Optional, default: 5 — this endpoint throttles aggressively)"),
    timeout: int = typer.Option(10, "-i", "--timeout", help="Per-request timeout in seconds (Optional, default: 10)"),
    output: OutputFormat = output_option(),
):
    """
    Discover which candidate usernames correspond to real Entra ID accounts, via Microsoft's
    unauthenticated GetCredentialType endpoint. No login/tenant/client-id required — useful for
    building a validated username list ahead of `brute mfasweep`/`login ropc`/a password spray.
    """
    try:
        candidates = _read_userlist(userlist)
    except FileNotFoundError as e:
        console.print(f"[bold red][-][/] Userlist not found: {e}")
        raise typer.Exit(1)

    if domain:
        candidates = [c if "@" in c else f"{c}@{domain}" for c in candidates]
    candidates = list(dict.fromkeys(candidates))

    if not candidates:
        console.print("[bold red][-][/] Userlist is empty")
        raise typer.Exit(1)

    console.print(f"[bold]Checking {len(candidates)} candidate username(s)[/]\n")

    found = []
    throttled_count = 0
    failed_count = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_check_username, u, timeout): u for u in candidates}
        for future, username in iter_futures_with_progress(futures, "Checking usernames", label=lambda v: v):
            result = future.result()

            if result["exists"] is None:
                failed_count += 1
                vprint(f"{username}: request failed")
                continue

            if result["throttled"]:
                throttled_count += 1

            if result["exists"]:
                found.append(result)
                flag = " [dim](federated)[/dim]" if result["federated"] else ""
                console.print(f"[bold green][+][/] {username} exists{flag}")

    if throttled_count:
        console.print(f"\n[bold yellow][!][/] {throttled_count} request(s) were throttled by Microsoft — "
                       f"results may be incomplete. Lower --threads or retry later.")
    if failed_count:
        console.print(f"[dim][-] {failed_count} request(s) failed outright and were skipped[/dim]")

    render(console, "Discovered usernames", columns.BRUTE_USERS, found, output=output,
           xml_root_tag="users", xml_item_tag="user")

    if output == OutputFormat.table:
        console.print(f"\n[bold]{len(found)}[/] of {len(candidates)} candidate(s) confirmed to exist")
