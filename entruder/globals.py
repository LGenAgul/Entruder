"""Shared cross-module Graph/ARM helpers — generic plumbing (session setup,
paginated collection, id->name resolution) needed by every module group
(enum, exploit, whatever comes next), so it lives here once instead of being
copy-pasted into each group's _shared.py. Plain constant/dict data (API
versions, static id maps, etc.) lives in entruder.static instead.

entruder.utils imports are done lazily inside each function since some
entruder.utils modules import entruder.static at load time — keeping the
import local here avoids depending on module import order.
"""

import typer
from rich.console import Console

_console = Console()


def resource_group_from_id(resource_id):
    """Pull the resource group out of an ARM resource id (…/resourceGroups/<rg>/…)."""
    parts = (resource_id or "").split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def prepare_session(tenant, client_id, service):
    """ When either the tenant_id or client_id is not provided explicitly, the tool will check the cache for their excistence and will use them accordingly and vice-versa. """
    from entruder.utils import require_session, require_tenant, require_tenant_cache, initialize_tenant_cache

    explicit_args = bool(tenant or client_id)
    tenant, client_id = require_tenant_cache(tenant, client_id, _console)
    tenant = require_tenant(tenant, _console)
    if explicit_args:
        initialize_tenant_cache(tenant, client_id)
    token = require_session(tenant, client_id, service, _console)
    return tenant, {"Authorization": f"Bearer {token}"}


def graph_collect(url, headers, params=None, delegated=False):
    """ Follows the @odata.nextLink pagination link and returns the final merged list. """
    from entruder.utils import parse_error, request_json, vprint

    items = []
    while url:
        vprint(f"GET {url}")
        result = request_json("GET", url, headers=headers, params=params)
        params = None  # nextLink already carries $select; don't re-send it

        if "value" not in result:
            error = result.get("error", {})
            message = error.get("message") if isinstance(error, dict) else result.get("error_description", "Unknown error")
            _console.print(f"[bold red][-][/] Graph request failed: {parse_error(message)}")
            if delegated:
                _console.print("[dim]this needs a delegated (user) session — log in via "
                                "ropc/device/authcode, not secret/cert/foci/kerberos[/dim]")
            raise typer.Exit(1)

        items.extend(result["value"])
        url = result.get("@odata.nextLink")
    return items


def resolve_principal_names(headers, graph_url_base, object_ids):
    """ Resolves associated ID's to userPrincipalNames in a tenant """
    from entruder.utils import request_json, vprint

    ids = sorted(set(filter(None, object_ids)))
    if not ids:
        return {}
    vprint(f"POST {graph_url_base}/directoryObjects/getByIds")
    result = request_json(
        "POST",
        f"{graph_url_base}/directoryObjects/getByIds",
        headers=headers,
        json={"ids": ids},
    )
    return {
        obj["id"]: obj.get("userPrincipalName") or obj.get("displayName") or obj["id"]
        for obj in result.get("value", []) or []
    }


# Entra's well-known "default access" app role — assigned when a principal is
# just enabled/SSO'd into an app that declares no real app roles, not a real
# permission grant. Worth naming explicitly instead of a failed lookup.
DEFAULT_APP_ROLE = "00000000-0000-0000-0000-000000000000"


def resolve_app_roles(headers, graph_url_base, assignments):
    """ Reolves an app role I'd to it's displayName """
    from entruder.utils import request_json, vprint, iter_with_progress

    resource_ids = set(filter(None, (a.get("resourceId") for a in assignments)))
    app_roles_by_resource = {}
    for resource_id in iter_with_progress(resource_ids, "Resolving app roles", key=lambda rid: rid):
        vprint(f"GET /servicePrincipals/{resource_id}")
        result = request_json(
            "GET",
            f"{graph_url_base}/servicePrincipals/{resource_id}",
            headers=headers,
            params={"$select": "id,appRoles"},
        )
        app_roles_by_resource[resource_id] = {
            role["id"]: role for role in result.get("appRoles", []) or []
        }

    for a in assignments:
        role_id = a.get("appRoleId")
        if role_id == DEFAULT_APP_ROLE:
            a["appRolePermission"] = "Default Access. No explicit app role"
            continue
        role = app_roles_by_resource.get(a.get("resourceId"), {}).get(role_id)
        a["appRolePermission"] = (role.get("value") or role.get("displayName")) if role else "unknown"
    return assignments
