import time

import msal
import typer
from rich.console import Console

from entruder.globals import RESOURCE_SHORTCUTS
from .http import request_json
from .logging import vprint
from .parser import csv_to_list, parse_error

console = Console()


def build_cert_credential(cert_path: str, key_path: str, passphrase: str = None) -> dict:
    """
    Build the MSAL client_credential dict for certificate-based auth.
    """
    from pathlib import Path
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives import hashes

    cert_pem = Path(cert_path).read_bytes()
    private_key = Path(key_path).read_text()

    thumbprint = load_pem_x509_certificate(cert_pem).fingerprint(hashes.SHA1()).hex()
    vprint(f"Loaded certificate (SHA-1 thumbprint {thumbprint})")

    credential = {
        "private_key": private_key,
        "thumbprint": thumbprint,
        "public_certificate": cert_pem.decode(),
    }
    if passphrase:
        credential["passphrase"] = passphrase
    return credential


def device_login_v1(resource, tenant, client_id) -> dict:
    """
    Authenticate using device code flow for v1 endpoint, done directly via raw http requests.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/103.0.0.0 Safari/537.36"
    }
    resource_url = RESOURCE_SHORTCUTS.get(resource, resource)
    # Initialize device code flow to receive the user code
    initial_response = request_json(
            "POST",
            f"https://login.microsoftonline.com/{tenant}/oauth2/devicecode",
            params={"api-version": "1.0"},
            data={
                "client_id": client_id,
                "resource": resource_url
            },
            headers=headers
        )

    if "user_code" not in initial_response:
        console.print(f"[bold red][-][/] Failed to initiate device code flow: {parse_error(initial_response.get('error_description', 'Unknown error'))}")
        raise typer.Exit(1)

    interval = int(initial_response.get("interval", 5))
    device_code = initial_response["device_code"]
    # the device code is only valid for a limited window, stop polling once it expires
    deadline = time.monotonic() + int(initial_response.get("expires_in", 900))

    console.print(f"{initial_response['message']}")
    vprint(f"Polling every {interval}s for up to {int(deadline - time.monotonic())}s")

    # wait for the user to authenticate and poll for the access token
    result = None
    while time.monotonic() < deadline:
        time.sleep(interval)
        result = request_json(
            "POST",
            f"https://login.microsoftonline.com/{tenant}/oauth2/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "resource": resource_url,
                "code": device_code
            },
            headers=headers
        )

        if "access_token" in result:
            return result

        if "error" in result:
            error = result["error"]
            if error == "authorization_pending":
                vprint("authorization_pending — user has not completed sign-in yet")
                continue
            elif error == "slow_down":
                # AAD is telling us to back off, increase the interval as required
                interval += 5
                vprint(f"slow_down — backing off, interval now {interval}s")
                continue
            else:
                console.print(f"[bold red][-][/] Error during token acquisition: {parse_error(result.get('error_description', 'Unknown error'))}")
                raise typer.Exit(1)

    console.print("[bold red][-][/] Device code expired before authentication completed.")
    raise typer.Exit(1)


def device_login_v2(tenant, client_id, scopes) -> dict:
    """
    Authenticate using device code flow for v2 endpoint, using MSAL library for handling the flow.
    """
    app = msal.PublicClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant}")

    vprint(f"Initiating v2 device flow (scopes={csv_to_list(scopes)})")
    flow = app.initiate_device_flow(scopes=csv_to_list(scopes))
    if "user_code" not in flow:
        console.print(f"[bold red][-][/] Failed to initiate device code flow: {parse_error(flow.get('error_description', 'Unknown error'))}")
        raise typer.Exit(1)

    console.print(f"\n[bold yellow][*][/] {flow['message']}\n")

    result = app.acquire_token_by_device_flow(flow)

    if "access_token" not in result:
        console.print(f"[bold red][-][/] Error during token acquisition: {parse_error(result.get('error_description', 'Unknown error'))}")
        raise typer.Exit(1)

    return result


