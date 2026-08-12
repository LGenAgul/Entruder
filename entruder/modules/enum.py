import typer
from rich.console import Console
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
        def get(tag):
            el = root.find(tag)
            return el.text if el is not None else "N/A"
        
        console.print(f"[bold]Domain:[/]         {domain}")
        console.print(f"[bold]Tenant ID:[/]      {tenant_id}")
        console.print(f"[bold]Token Endpoint:[/] {token_endpoint}")
        console.print(f"[bold]Tenant Region:[/]  {tenant_region_scope}")
        console.print(f"[bold]MsGraph Host:[/]   {msgraph_host}")
        console.print(f"[bold]Namespace:[/]      {get('NameSpaceType')}")
        console.print(f"[bold]Brand Name:[/]     {get('FederationBrandName')}")
        console.print(f"[bold]Cloud:[/]          {get('CloudInstanceName')}")
        console.print(f"[bold]Auth URL:[/]       {get('AuthURL')}")
        console.print(f"[bold]DSSO Enabled:[/]   {get('IsDssoEnabled')}")
        console.print(f"[bold]Federated:[/]      {get('NameSpaceType') == 'Federated'}")
    except Exception:
        console.print(f"[bold red][-][/] Could not reach tenant for domain: {domain}")
        raise typer.Exit(1)