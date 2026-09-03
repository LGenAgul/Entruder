import typer

from entruder.static import API_VERSIONS
from entruder.utils import (
    parse_error,
    request_json,
    vprint,
    iter_with_progress,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import enum_app, console, columns, prepare_session, resolve_principal_names


def _role_definition_names(headers, role_definition_ids):
    """Resolve ARM role definition ids (full resource paths) to their display
    roleName via one GET per distinct definition, deduped across every
    assignment being enumerated."""
    definitions = {}
    ids = set(filter(None, role_definition_ids))
    for role_definition_id in iter_with_progress(ids, "Resolving role names", key=lambda rid: rid.rsplit("/", 1)[-1]):
        vprint(f"GET {role_definition_id}")
        result = request_json(
            "GET",
            f"https://management.azure.com{role_definition_id}",
            headers=headers,
            params={"api-version": API_VERSIONS["authorization"]},
        )
        props = result.get("properties", {}) or {}
        definitions[role_definition_id] = props.get("roleName", "unknown")
    return definitions


@enum_app.command("rbac")
@handle_cli_errors
def enum_resource_role_assignments(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (will be cached upon explicit use)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (will be cached upon explicit use)"),
    resource_id: str = typer.Option(None, "-i", "--resource-id", help="Full ARM resource id to inspect, e.g. the 'id' from 'enum resources'. Overrides --sub/--resource-group/--resource"),
    sub: str = typer.Option(None, "--sub", "-s", help="Subscription ID"),
    rg: str = typer.Option(None, "--resource-group", "-rg", help="Resource group (optional, omit for subscription scope)"),
    resource: str = typer.Option(None, "--resource", "-res", help="Resource path relative to the resource group, e.g. 'Microsoft.Storage/storageAccounts/mystorageacct' (requires --resource-group)"),
    inherited: bool = typer.Option(True, "--inherited/--direct", help="Include assignments inherited from the resource group and subscription (default), or only those set directly at the target scope"),
    output: OutputFormat = output_option(),
):
    """Enumerate the Azure RBAC role assignments on a resource, resource group, or subscription scope, resolving each principal and role name (requires a management AND graph token)."""
    # Build the scope from a full resource id, or from the sub/rg/resource parts
    # the same way `set arm-role` does so the two commands compose.
    if resource_id:
        scope = resource_id if resource_id.startswith("/") else f"/{resource_id}"
        # A valid ARM scope is a subscription/rg/resource path or a
        # management-group / tenant-level provider path. A bare name like
        # "funcapp" would otherwise sail through and only fail later with an
        # opaque ARM error, so reject it up front with a usable hint.
        if not (scope.startswith("/subscriptions/") or scope.startswith("/providers/")):
            console.print(f"[bold red][-][/] --resource-id must be a full ARM resource id, got '{resource_id}'")
            console.print("[dim]e.g. /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Web/sites/<name>. "
                          "To build it from parts use --sub/--resource-group/--resource instead[/dim]")
            raise typer.Exit(1)
    else:
        if not sub:
            console.print("[bold red][-][/] Provide either --resource-id or --sub")
            raise typer.Exit(1)
        if resource and not rg:
            console.print("[bold red][-][/] --resource requires --resource-group")
            raise typer.Exit(1)
        if resource and resource.count("/") < 2:
            console.print(f"[bold red][-][/] --resource must be a provider path 'Namespace/type/name', got '{resource}'")
            console.print("[dim]e.g. Microsoft.Web/sites/myfuncapp or Microsoft.Storage/storageAccounts/myacct[/dim]")
            raise typer.Exit(1)
        scope = f"/subscriptions/{sub}"
        if rg:
            scope += f"/resourceGroups/{rg}"
        if resource:
            scope += f"/providers/{resource}"

    tenant, arm_headers = prepare_session(tenant, client_id, "management")
    _, graph_headers = prepare_session(tenant, client_id, "graph")
    graph_url_base = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"

    url = f"https://management.azure.com{scope}/providers/Microsoft.Authorization/roleAssignments"
    # atScope() returns assignments set directly at the scope plus those
    # inherited from every ancestor scope (rg, subscription, management group),
    # which is the effective who-has-what on the resource. Without it ARM also
    # returns assignments from child scopes, which we don't want here.
    params = {"api-version": API_VERSIONS["authorization"]}
    if inherited:
        params["$filter"] = "atScope()"

    assignments = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=arm_headers, params=params)

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            console.print(f"[bold red][-][/] Management request failed: {parse_error(message)}")
            raise typer.Exit(1)

        assignments.extend(result["value"])
        url = result.get("nextLink")  # ARM uses nextLink, not @odata.nextLink
        params = None  # nextLink already carries api-version and the filter

    projected = [
        {**a.get("properties", {}), "roleAssignmentId": a.get("id")}
        for a in assignments
    ]

    role_definitions = _role_definition_names(
        arm_headers, [a.get("roleDefinitionId") for a in projected]
    )
    principal_names = resolve_principal_names(
        graph_headers, graph_url_base, [a.get("principalId") for a in projected]
    )
    for a in projected:
        a["roleName"] = role_definitions.get(a.get("roleDefinitionId"), "unknown")
        a["principalName"] = principal_names.get(a.get("principalId"), a.get("principalId"))

    render(console, f"Role assignments on {scope}", columns.RESOURCE_RA, projected,
           output=output, xml_root_tag="roleAssignments", xml_item_tag="roleAssignment")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(projected)}[/] role assignments total")
