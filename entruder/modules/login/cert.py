import typer
import msal

from entruder.static import PLANES, RESOURCE_SHORTCUTS
from entruder.utils import (
    acquire_for_resources,
    build_cert_credential,
    build_msal_http_client,
    handle_cli_errors,
    save_session,
    vprint,
    require_tenant,
    resolve_client_id,
    initialize_tenant_cache,
)

from ._shared import login_app, console


@login_app.command("cert")
@handle_cli_errors
def login_cert(
    tenant:    str = typer.Option(...,  "-t", "--tenant",   help="Tenant ID"),
    client_id: str = typer.Option(...,  "-c", "--client-id", help="Client ID"),
    cert:      str = typer.Option(...,  "-e", "--cert",     help="Path to certificate file (.pem/.crt)"),
    key:       str = typer.Option(...,  "-k", "--key",      help="Path to private key file (.pem)"),
    keypass:   str = typer.Option(None, "-p", "--key-pass",  help="Passphrase for an encrypted private key (Optional)"),
    resource:  str = typer.Option(None, "-r", "--resource", help="Target resource (Optional, default: all planes)"),
    output_tokens: bool = typer.Option(False, "-o", "--output", help="Output tokens to console (Optional)"),
    user_agent: str = typer.Option(None, "-u", "--user-agent", help="Override the User-Agent header sent during authentication (Optional)"),
):
    """
    Authenticate with a Service Principal's client certificate (certificate-based auth)
    """
    tenant =  require_tenant(tenant,console)
    client_id = resolve_client_id(client_id)
    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())

    # certificate credentials swap in for a secret; everything else mirrors `login secret`
    authority = f"https://login.microsoftonline.com/{tenant}"
    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=build_cert_credential(cert, key, keypass),
        authority=authority,
        http_client=build_msal_http_client(user_agent),
    )

    def acquire(plane, res):
        scope = PLANES.get(plane)
        vprint(f"Acquiring {plane} token (scope={scope})")
        return app.acquire_token_for_client(scopes=[scope])

    tokens = acquire_for_resources(resources, acquire, console, output_tokens=output_tokens)

    # if the tokens dictionary is not empty, save the session
    if tokens:
        save_session(tenant, client_id, tokens)
        initialize_tenant_cache(tenant, client_id)
        console.print(f"[bold green][+][/] Session saved for tenant: {tenant}")
