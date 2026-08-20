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
    initialize_tenant_cache,
)

from ._shared import login_app, console


@login_app.command("cert")
@handle_cli_errors
def login_cert(
    tenant:    str = typer.Option(...,  "-tenant",   help="Tenant ID"),
    client_id: str = typer.Option(...,  "-clientid", help="Client ID"),
    cert:      str = typer.Option(...,  "-cert",     help="Path to certificate file (.pem/.crt)"),
    key:       str = typer.Option(...,  "-key",      help="Path to private key file (.pem)"),
    keypass:   str = typer.Option(None, "-keypass",  help="Passphrase for an encrypted private key (Optional)"),
    resource:  str = typer.Option(None, "-resource", help="Target resource (Optional, default: all planes)"),
    output_tokens: bool = typer.Option(False, "-output", help="Output tokens to console (Optional)"),
    user_agent: str = typer.Option(None, "-useragent", help="Override the User-Agent header sent during authentication (Optional)"),
):
    """
    Authenticate with a Service Principal's client certificate (certificate-based auth)
    """
    tenant =  require_tenant(tenant,console)
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
