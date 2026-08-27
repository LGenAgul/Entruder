import typer
import msal

from entruder.static import PLANES, RESOURCE_SHORTCUTS
from entruder.utils import (
    acquire_for_resources,
    build_msal_http_client,
    handle_cli_errors,
    resolve_client_id,
    save_session,
    vprint,
    initialize_tenant_cache,
)

from ._shared import login_app, console


@login_app.command("secret")
@handle_cli_errors
def login_secret(
    tenant: str = typer.Option(..., "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(..., "-c", "--client-id", help="Client ID"),
    client_secret: str = typer.Option(..., "-s", "--secret", help="Client Secret"),
    output_tokens: bool = typer.Option(False, "-o", "--output", help="Output tokens to console"),
    resource: str = typer.Option(None, "-r", "--resource", help="Target resource for the token"),
    user_agent: str = typer.Option(None, "-u", "--user-agent", help="Override the User-Agent header sent during authentication (Optional)"),
):
    """
    Authenticate with a Service Principal's client credentials, via a client ID and a secret
    """
    client_id = resolve_client_id(client_id)
    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())

    # initialize the MSAL confidential client application auth flow
    authority = f"https://login.microsoftonline.com/{tenant}"
    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
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
