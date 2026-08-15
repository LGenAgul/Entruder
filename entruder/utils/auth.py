import base64
import hashlib
import secrets
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import msal
import typer
from rich.console import Console

from entruder.globals import RESOURCE_SHORTCUTS
from .http import request_json
from .logging import vprint
from .parser import csv_to_list, parse_error, parse_token, resolve_plane_from_resource

console = Console()


def acquire_for_resources(resources: list, acquire, console, output_tokens=False, label=None) -> dict:
    tokens = {}
    prefix = f"{label} " if label else ""
    for res in resources:
        plane = resolve_plane_from_resource(res)
        result = acquire(plane, res)

        if "access_token" not in result:
            msg = f"{prefix}{plane.capitalize()} token failed to acquire: {parse_error(result.get('error_description', result.get('error', 'Unknown error')))}"
            console.print(f"[bold red][-][/] {msg}")
            continue

        parsed = parse_token(result)
        tokens[plane] = parsed
        vprint(f"{plane} token expires at {parsed['expires_at']}")
        console.print(f"[bold green][+][/] {prefix}{plane.capitalize()} Token acquired successfully!")
        if output_tokens:
            console.print(f"[bold]{prefix}{plane.capitalize()} Access Token:[/]\n{parsed['value']}\n")

    return tokens


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


def _catch_redirect(redirect_uri: str, timeout: int = 300) -> dict:
    """
    Bind a short-lived local HTTP listener on redirect_uri's host/port, wait for AAD's browser redirect to land on it, and return the callback's query params. Only used by the interactive flow with an out-of-band code never touches this.
    """
    parsed = urlparse(redirect_uri)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    callback_path = parsed.path or "/"

    captured = {}

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if urlparse(self.path).path == callback_path:
                captured.update(parse_qs(urlparse(self.path).query))
                body = b"<html><body>Login captured &mdash; you can close this tab.</body></html>"
                self.send_response(200)
            else:
                body = b""
                self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass 

    server = HTTPServer((host, port), _Handler)
    vprint(f"Listening for the redirect on {host}:{port}{callback_path}")

    deadline = time.monotonic() + timeout
    while not captured and time.monotonic() < deadline:
        server.timeout = max(1, deadline - time.monotonic())
        server.handle_request()
    server.server_close()

    if not captured:
        console.print("[bold red][-][/] Timed out waiting for the authorization redirect.")
        raise typer.Exit(1)

    # parse_qs always returns lists; flatten to single values
    return {k: v[0] for k, v in captured.items()}


def _interactive_auth_code(tenant, client_id, scope_param, redirect_uri, pkce, open_browser) -> tuple:
    """
    Build the /authorize URL (with PKCE by default), drive the user to it, and catch the resulting redirect. Returns (code, verifier) for the token exchange.
    """
    state = secrets.token_urlsafe(16)
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": scope_param,
        "state": state,
    }

    verifier = None
    if pkce:
        verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        params["code_challenge"] = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        params["code_challenge_method"] = "S256"

    auth_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{urlencode(params)}"
    console.print(f"\n[bold yellow][*][/] Open this URL to sign in:\n{auth_url}\n")
    if open_browser:
        webbrowser.open(auth_url)

    auth_response = _catch_redirect(redirect_uri)

    if auth_response.get("state") != state:
        console.print("[bold red][-][/] State mismatch on redirect — possible CSRF, aborting.")
        raise typer.Exit(1)

    if "code" not in auth_response:
        console.print(f"[bold red][-][/] Authorization failed: {parse_error(auth_response.get('error_description', 'No code in redirect'))}")
        raise typer.Exit(1)

    return auth_response["code"], verifier


def auth_code_login(
    tenant, client_id, scopes, redirect_uri,
    client_secret=None, code=None, verifier=None, pkce=True, open_browser=True,
) -> dict:
    scope_list = csv_to_list(scopes)
    if any(s.endswith("/.default") or s == ".default" for s in scope_list):
        # .default (app-only, "whatever's statically configured") can't be mixed
        # with other scopes in the same request — AAD rejects it. Send it as-is.
        vprint(".default scope requested — skipping the openid/profile/offline_access auto-append, AAD rejects that combination")
    else:
        for extra in ("openid", "profile", "offline_access"):
            if extra not in scope_list:
                scope_list.append(extra)
    scope_param = " ".join(scope_list)

    if code is None:
        code, verifier = _interactive_auth_code(tenant, client_id, scope_param, redirect_uri, pkce, open_browser)

    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "scope": scope_param,
    }
    if verifier:
        data["code_verifier"] = verifier
    if client_secret:
        data["client_secret"] = client_secret

    vprint(f"Redeeming authorization code for {client_id} (scope={scope_param})")
    result = request_json(
        "POST",
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data=data,
    )

    if "access_token" not in result:
        console.print(f"[bold red][-][/] Error during token acquisition: {parse_error(result.get('error_description', 'Unknown error'))}")
        raise typer.Exit(1)

    return result


