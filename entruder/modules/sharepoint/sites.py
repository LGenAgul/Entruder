import typer

from entruder.static import API_VERSIONS
from entruder.utils import (
    parse_error,
    request_json,
    vprint,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import sharepoint_app, console, columns, prepare_session


@sharepoint_app.command("sites")
@handle_cli_errors
def sharepoint_sites(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    batch_size: int = typer.Option(200, "--batch-size", help="Search API page size (capped at 1000) (Optional, default: 200)"),
    max_sites: int = typer.Option(0, "--max-sites", help="Stop after this many unique sites (Optional, default: 0 = no limit)"),
    output: OutputFormat = output_option(),
    ):
    """Enumerate SharePoint sites visible to the current session via the Microsoft Search API (requires a graph token)."""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    
    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/search/query"
    batch_size = min(batch_size, 1000)

    seen_site_ids = set()
    sites = []
    offset = 0
    more_results = True

    while more_results:
        vprint(f"POST {url} (from={offset}, size={batch_size})")
        body = {
            "requests": [{
                "entityTypes": ["drive"],
                "query": {"queryString": "*"},
                "from": offset,
                "size": batch_size,
                "fields": ["parentReference", "webUrl"],
            }]
        }
        result = request_json("POST", url, headers=headers, json=body)

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Graph request failed: {parse_error(message)}")
            raise typer.Exit(1)

        hits_container = (result["value"][0] if result["value"] else {}).get("hitsContainers", [{}])[0]

        for hit in hits_container.get("hits", []) or []:
            resource = hit.get("resource", {}) or {}
            site_id = (resource.get("parentReference") or {}).get("siteId")
            if not site_id or site_id in seen_site_ids:
                continue
            seen_site_ids.add(site_id)
            sites.append({"siteId": site_id, "webUrl": resource.get("webUrl")})
            if max_sites and len(sites) >= max_sites:
                more_results = False
                break

        if more_results:
            more_results = bool(hits_container.get("moreResultsAvailable"))
            offset += batch_size

    sites.sort(key=lambda s: s.get("webUrl") or "")

    render(console, "All SharePoint Sites", columns.SHAREPOINT_SITES, sites, output=output,
           xml_root_tag="SharePointSites", xml_item_tag="Site")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(sites)}[/] sites total")
