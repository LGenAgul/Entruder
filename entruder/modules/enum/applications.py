import typer

from entruder.static import API_VERSIONS, APP_PARAMS
from entruder.utils import (
    request_json,
    vprint,
    iter_with_progress,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import enum_app, console, columns, prepare_session, graph_collect


def _resolve_required_resource_access(headers, graph_url_base, apps):
    """Resolve each app's requiredResourceAccess (the API permissions it's
    statically declared it wants — distinct from what's actually been
    granted, which is what `enum privs`/appRoleAssignments shows) from
    opaque {resourceAppId, resourceAccess:[{id,type}]} blobs into readable
    "Resource: permission (Scope/Role)" lines. One servicePrincipals lookup
    per distinct resource app (Microsoft Graph, etc.), deduped across every
    app being enumerated."""
    resource_app_ids = {
        rra["resourceAppId"]
        for app in apps
        for rra in app.get("requiredResourceAccess", []) or []
        if rra.get("resourceAppId")
    }

    resource_maps = {}
    for app_id in iter_with_progress(resource_app_ids, "Resolving permissions", key=lambda app_id: app_id):
        vprint(f"GET /servicePrincipals?$filter=appId eq '{app_id}'")
        result = request_json(
            "GET", f"{graph_url_base}/servicePrincipals",
            headers=headers,
            params={"$filter": f"appId eq '{app_id}'",
                    "$select": "appId,displayName,appRoles,oauth2PermissionScopes"},
        )
        sp = (result.get("value") or [{}])[0]
        resource_maps[app_id] = {
            "displayName": sp.get("displayName", app_id),
            "roles":  {r["id"]: r.get("value", "unknown") for r in sp.get("appRoles", []) or []},
            "scopes": {s["id"]: s.get("value", "unknown") for s in sp.get("oauth2PermissionScopes", []) or []},
        }

    for app in apps:
        lines = []
        for rra in app.get("requiredResourceAccess", []) or []:
            res = resource_maps.get(rra.get("resourceAppId"), {})
            resource_name = res.get("displayName", rra.get("resourceAppId"))
            for access in rra.get("resourceAccess", []) or []:
                kind = "roles" if access.get("type") == "Role" else "scopes"
                perm = res.get(kind, {}).get(access.get("id"), access.get("id"))
                lines.append(f"{resource_name}: {perm} ({access.get('type')})")
        app["_required_resource_access"] = lines
    return apps


def _project_application(app):
    """Flatten redirect URIs from web/spa/publicClient into one list, and
    flag whether the app can run without a client secret at all (public
    client / device-code-friendly, notably foci-adjacent risk)."""
    web = app.get("web", {}) or {}
    spa = app.get("spa", {}) or {}
    public_client = app.get("publicClient", {}) or {}
    app["_redirect_uris"] = (
        list(web.get("redirectUris") or []) +
        list(spa.get("redirectUris") or []) +
        list(public_client.get("redirectUris") or [])
    )
    app["_public_client"] = bool(public_client.get("redirectUris")) or bool(app.get("isFallbackPublicClient"))
    return app


@enum_app.command("apps")
@handle_cli_errors
def enum_applications(
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID"),
    owned: bool = typer.Option(False, "-w", "--owned",
        help="Only show app registrations owned by the current signed-in user "
             "(requires a delegated session, ropc/device/authcode, not app-only secret/cert/foci/kerberos)"),
    output: OutputFormat = output_option(),
    ):
    """Enumerate Entra app registrations, requested API permissions, redirect URIs, and credentials on the app registration itself."""
    tenant, headers = prepare_session(tenant, client_id, "graph")
    graph_url_base = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"
    if owned:
        url = f"{graph_url_base}/me/ownedObjects"
    else:
        url = f"{graph_url_base}/applications"

    apps = graph_collect(url, headers, params=APP_PARAMS, delegated=owned)
    if owned:
        # /me/ownedObjects is polymorphic (apps, groups, service principals, ...)
        vprint("Showcasing owned resources:")
        apps = [a for a in apps if a.get("@odata.type") == "#microsoft.graph.application"]

    apps = _resolve_required_resource_access(headers, graph_url_base, apps)
    apps = [_project_application(a) for a in apps]
    
    title = f"Applications in {tenant}" + (" (owned by current user)" if owned else "")
    render(console, title, columns.APPLICATION, apps, output=output,
           xml_root_tag="applications", xml_item_tag="application")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(apps)}[/] applications total")
