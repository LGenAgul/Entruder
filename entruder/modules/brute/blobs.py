import re
import xml.etree.ElementTree as etree
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List

import httpx
import typer

from entruder.static import STORAGE_CONTAINER_GUESSES
from entruder.utils import (
    handle_cli_errors,
    iter_futures_with_progress,
    parse_xml_tag,
    render,
    OutputFormat,
    output_option,
    vprint
)

from ._shared import brute_app, console, columns


def _normalize_account(value: str) -> str:
    # accepts a bare account name or a full <name>.blob.core.windows.net —
    # strip the suffix first so pasting either form works the same way
    value = value.strip().lower().split(".blob.core.windows.net")[0]
    return re.sub(r"[^a-z0-9]", "", value)


def _read_wordlist(path_str: str) -> list:
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(path_str)
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def _probe_container(account: str, container: str, timeout: int) -> dict:

    url = f"https://{account}.blob.core.windows.net/{container}"
    blobs = []
    marker = None
    vprint(f"GET {url}")
    while True:
        params = {"restype": "container", "comp": "list", "maxresults": "5000"}
        if marker:
            params["marker"] = marker
        try:
            response = httpx.get(url, params=params, timeout=timeout)
        except httpx.HTTPError:
            return {"exists": False, "public": False, "blobs": []}

        if response.status_code != 200:
            return {"exists": response.status_code != 404, "public": False, "blobs": []}

        root = etree.fromstring(response.text)
        blobs.extend(parse_xml_tag(b, "Name") for b in root.findall("./Blobs/Blob"))
        marker = parse_xml_tag(root, "NextMarker")
        if marker in (None, "N/A", ""):
            break

    return {"exists": True, "public": True, "blobs": blobs}


@brute_app.command("blobs")
@handle_cli_errors
def brute_blobs(
    account: List[str] = typer.Option(..., "-a", "--account",
        help="Storage account to brute-force containers on — repeatable. Accepts either just the "
             "account name or the full <name>.blob.core.windows.net"),
    container_wordlist: str = typer.Option(None, "-c", "--container-wordlist",
        help="Path to a file of container names (one per line) to try, added on top of the built-in"),
    threads: int = typer.Option(10, "-t", "--threads", help="Concurrent requests (Optional, default: 10)"),
    timeout: int = typer.Option(10, "-i", "--timeout", help="Per-request timeout in seconds (Optional, default: 10)"),
    output: OutputFormat = output_option(),
):
    """
    Brute-force container names against a known storage account and check for anonymous public listing.
    """
    accounts = sorted({a for a in (_normalize_account(a) for a in account) if a})
    if not accounts:
        console.print("[bold red][-][/] --account didn't normalize to a valid storage account name")
        raise typer.Exit(1)
    vprint(f"Accounts: {accounts}")
    try:
        vprint(f"Using wordlist {container_wordlist}")
        container_names = list(dict.fromkeys(STORAGE_CONTAINER_GUESSES + _read_wordlist(container_wordlist))) \
            if container_wordlist else STORAGE_CONTAINER_GUESSES
    except FileNotFoundError as e:
        console.print(f"[bold red][-][/] Wordlist not found: {e}")
        raise typer.Exit(1)

    console.print(f"[bold]Trying {len(container_names)} container name(s) against {len(accounts)} account(s)[/]\n")
    vprint(f"Containers: {container_names[:10]}{'...' if len(container_names) > 10 else ''}")

    results = {a: [] for a in accounts}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_probe_container, acct, container, timeout): (acct, container)
            for acct in accounts for container in container_names
        }
        for future, (acct, container) in iter_futures_with_progress(
                futures, "Probing containers", label=lambda v: f"{v[0]}/{v[1]}"):
            result = future.result()
            if not result["exists"]:
                continue
            results[acct].append({
                "name": container,
                "public": result["public"],
                "blobs": result["blobs"],
            })
            if result["public"]:
                base_url = f"https://{acct}.blob.core.windows.net/{container}"
                console.print(f"[bold red][!][/] Public container: {base_url} ({len(result['blobs'])} blob(s))")
                for blob_name in result["blobs"]:
                    console.print(f"    {base_url}/{blob_name}")

    found = [{"account": a, "containers": c} for a, c in results.items()]
    render(console, "Container brute-force results", columns.BRUTE_BLOB, found,
           output=output, xml_root_tag="accounts", xml_item_tag="account")

    if output == OutputFormat.table:
        public_hits = sum(1 for f in found for c in f["containers"] if c["public"])
        total_hits = sum(len(f["containers"]) for f in found)
        console.print(f"\n[bold]{total_hits}[/] container(s) found, [bold red]{public_hits}[/] publicly-listable")
