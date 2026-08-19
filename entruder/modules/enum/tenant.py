import typer
import httpx
import xml.etree.ElementTree as etree

from entruder.globals import HTTP_TIMEOUT
from entruder.utils import (
    parse_error,
    parse_xml_tag,
    report_error,
    request_json,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
    save_domain_mapping,
)

from ._shared import enum_app, console, columns


@enum_app.command("tenant")
@handle_cli_errors
def enum_tenant(
    domain: str = typer.Option(..., "-domain", help="Domain Name"),
    output: OutputFormat = output_option(),
):
    try:
        openid_json = request_json(
            "GET",
            f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
        )
        # a valid tenant returns an issuer; its absence means the domain isn't an Entra tenant
        if not openid_json.get("issuer"):
            console.print(f"[bold red][-][/] Not a valid Entra tenant domain: {domain} "
                          f"({parse_error(openid_json.get('error_description', 'no issuer returned'))})")
            raise typer.Exit(1)

        tenant_id = openid_json["issuer"].split("/")[-2]
        if tenant_id:
            save_domain_mapping(domain, tenant_id)
        tenant_region_scope = openid_json.get("tenant_region_scope", "N/A")
        msgraph_host = openid_json.get("msgraph_host", "N/A")
        token_endpoint = openid_json.get("token_endpoint", "N/A")

        vprint(f"GET getuserrealm.srf for {domain}")
        userrealm_xml = httpx.get(
            "https://login.microsoftonline.com/getuserrealm.srf",
            params={"login":domain,"xml":"1"},
            timeout=HTTP_TIMEOUT)
        userrealm_xml.raise_for_status()
        vprint(f"  -> HTTP {userrealm_xml.status_code} ({len(userrealm_xml.content)} bytes)")
        root = etree.fromstring(userrealm_xml.text)

        result = {
            "domain":         domain,
            "tenant_id":      tenant_id,
            "token_endpoint": token_endpoint,
            "tenant_region":  tenant_region_scope,
            "msgraph_host":   msgraph_host,
            "namespace":      parse_xml_tag(root, "NameSpaceType"),
            "brand_name":     parse_xml_tag(root, "FederationBrandName"),
            "cloud":          parse_xml_tag(root, "CloudInstanceName"),
            "auth_url":       parse_xml_tag(root, "AuthURL"),
            "dsso_enabled":   parse_xml_tag(root, "IsDssoEnabled"),
            "federated":      parse_xml_tag(root, "NameSpaceType") == "Federated",
        }

        render(console, f"Tenant:{domain}", columns.TENANT, result, output=output, xml_item_tag="tenant")

    except typer.Exit:
        raise  # let our own explicit exits (with their specific message) through
    except Exception as e:
        console.print(f"[bold red][-][/] Could not reach tenant for domain: {domain}")
        report_error(e, console)
        raise typer.Exit(1)
