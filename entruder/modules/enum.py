import typer
from rich.console import Console
from entruder.helpers import parse_xml_tag
import xml.etree.ElementTree as etree
import httpx

enum_app = typer.Typer(help="Enumeration", no_args_is_help=True)
console = Console()

@enum_app.command("tenant")
def enum_tenant(
    domain: str = typer.Option(..., "-domain", help="Domain Name")
):  
    try: 
        console.print(f"[bold green][+][/] The domain is valid! acquiring information\n")

        openid_json =  httpx.get(
            f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
            ).json()
        tenant_id = openid_json.get("issuer").split("/")[-2]
        tenant_region_scope = openid_json.get("tenant_region_scope", "N/A")
        msgraph_host = openid_json.get("msgraph_host", "N/A")
        token_endpoint = openid_json.get("token_endpoint", "N/A")

        userrealm_xml = httpx.get(
            "https://login.microsoftonline.com/getuserrealm.srf",
            params={"login":domain,"xml":"1"})
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
    except Exception:
        console.print(f"[bold red][-][/] Could not reach tenant for domain: {domain}")
        raise typer.Exit(1)