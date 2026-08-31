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


@sharepoint_app.command("files")
@handle_cli_errors
def sharepoint_files(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    query: str = typer.Option(..., "-q", "--query", help="Search term or KQL query, e.g. 'password filetype:xlsx', 'confidential'"),
    batch_size: int = typer.Option(25, "--batch-size", help="Search API page size (capped at 1000)"),
    max_results: int = typer.Option(0, "--max-results", help="Stop after this many results (0 = no limit)"),
    output: OutputFormat = output_option(),
    ):
    """Search file names/content across every SharePoint site and OneDrive drive visible to the
    current session, via the Microsoft Search API (entityTypes: driveItem) — matches GraphRunner's
    Invoke-SearchSharePointAndOneDrive. Accepts KQL (filetype:, filename:, etc). Each hit's Drive
    Item ID (driveId:itemId) is the handle needed to fetch that file's content directly."""
    tenant, headers = prepare_session(tenant, client_id, "graph")

    url = f"https://graph.microsoft.com/{API_VERSIONS['graph']}/search/query"
    batch_size = min(batch_size, 1000)

    results = []
    offset = 0
    more_results = True

    while more_results:
        vprint(f"POST {url} (query={query!r}, from={offset}, size={batch_size})")
        body = {
            "requests": [{
                "entityTypes": ["driveItem"],
                "query": {"queryString": query},
                "from": offset,
                "size": batch_size,
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
            parent = resource.get("parentReference", {}) or {}
            drive_id, item_id = parent.get("driveId"), resource.get("id")
            results.append({
                "file_name":     resource.get("name"),
                "size":          resource.get("size"),
                "location":      resource.get("webUrl"),
                "drive_item_id": f"{drive_id}:{item_id}" if drive_id and item_id else None,
                "preview":       hit.get("summary"),
                "last_modified": resource.get("lastModifiedDateTime"),
            })
            if max_results and len(results) >= max_results:
                more_results = False
                break

        if more_results:
            more_results = bool(hits_container.get("moreResultsAvailable"))
            offset += batch_size

    render(console, f"Search results for {query!r}", columns.SEARCH_FILES, results, output=output,
           xml_root_tag="SearchResults", xml_item_tag="File")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(results)}[/] file(s) matched")
