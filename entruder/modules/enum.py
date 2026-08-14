import typer
from rich.console import Console
from entruder.utils import parse_error, parse_xml_tag, report_error, request_json, vprint
from entruder.globals import HTTP_TIMEOUT
import xml.etree.ElementTree as etree
import httpx

enum_app = typer.Typer(help="Enumeration", no_args_is_help=True)
console = Console()

@enum_app.command("tenant")
def enum_tenant(
    domain: str = typer.Option(..., "-domain", help="Domain Name")
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

        # printing the userrealm information
        console.print(f"[bold]Domain:[/]         {domain}")
        console.print(f"[bold]Tenant ID:[/]      {tenant_id}")
        console.print(f"[bold]Token Endpoint:[/] {token_endpoint}")
        console.print(f"[bold]Tenant Region:[/]  {tenant_region_scope}")
        console.print(f"[bold]MsGraph Host:[/]   {msgraph_host}")
        console.print(f"[bold]Namespace:[/]      {parse_xml_tag(root,'NameSpaceType')}")
        console.print(f"[bold]Brand Name:[/]     {parse_xml_tag(root,'FederationBrandName')}")
        console.print(f"[bold]Cloud:[/]          {parse_xml_tag(root,'CloudInstanceName')}")
        console.print(f"[bold]Auth URL:[/]       {parse_xml_tag(root,'AuthURL')}")
        console.print(f"[bold]DSSO Enabled:[/]   {parse_xml_tag(root,'IsDssoEnabled')}")
        console.print(f"[bold]Federated:[/]      {parse_xml_tag(root,'NameSpaceType') == 'Federated'}")
    except typer.Exit:
        raise  # let our own explicit exits (with their specific message) through
    except Exception as e:
        console.print(f"[bold red][-][/] Could not reach tenant for domain: {domain}")
        report_error(e, console)
        raise typer.Exit(1)