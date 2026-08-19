import re
import typer

from entruder.globals import API_VERSIONS, DIRECTORY_ROLES
from entruder.utils import (
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
)

from ._shared import enum_app, console, columns, prepare_session, graph_collect, resolve_principal_names

# includeUsers/excludeUsers/includeGroups/excludeGroups mix real object ids
# with sentinels ("All", "GuestsOrExternalUsers", "None") — only the former
# are worth a directoryObjects/getByIds round trip.
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _resolvable_ids(*id_lists):
    return {i for lst in id_lists for i in (lst or []) if _GUID_RE.match(i or "")}


def _resolve_role_names(role_ids):
    return [DIRECTORY_ROLES.get(r, {}).get("name", r) for r in role_ids or []]


def _project_ca_policy(policy, names):
    """Flatten a raw CA policy into the grouped shape the CAPOLICY columns
    expect: who it applies to (resolved to display names/UPNs where the id is
    a real object, not a sentinel), what it applies to, under what
    conditions, and what it requires."""
    conditions = policy.get("conditions", {}) or {}
    users = conditions.get("users", {}) or {}
    apps = conditions.get("applications", {}) or {}
    platforms = conditions.get("platforms", {}) or {}
    locations = conditions.get("locations", {}) or {}
    grant = policy.get("grantControls", {}) or {}

    def resolve(ids):
        return [names.get(i, i) for i in (ids or [])]

    return {
        "id":               policy.get("id"),
        "displayName":      policy.get("displayName"),
        "state":            policy.get("state"),
        "modifiedDateTime": policy.get("modifiedDateTime"),
        "users": {
            "includeUsers":  resolve(users.get("includeUsers")),
            "excludeUsers":  resolve(users.get("excludeUsers")),
            "includeGroups": resolve(users.get("includeGroups")),
            "excludeGroups": resolve(users.get("excludeGroups")),
            "includeRoles":  _resolve_role_names(users.get("includeRoles")),
            "excludeRoles":  _resolve_role_names(users.get("excludeRoles")),
            "includeGuestsOrExternalUsers": (users.get("includeGuestsOrExternalUsers") or {}).get("guestOrExternalUserTypes"),
            "excludeGuestsOrExternalUsers": (users.get("excludeGuestsOrExternalUsers") or {}).get("guestOrExternalUserTypes"),
        },
        "applications": {
            "includeApplications": apps.get("includeApplications"),
            "excludeApplications": apps.get("excludeApplications"),
            "includeUserActions":  apps.get("includeUserActions"),
            "includeAuthenticationContextClassReferences": apps.get("includeAuthenticationContextClassReferences"),
        },
        "conditions_extra": {
            "clientAppTypes":   conditions.get("clientAppTypes"),
            "signInRiskLevels": conditions.get("signInRiskLevels"),
            "userRiskLevels":   conditions.get("userRiskLevels"),
            "includePlatforms": platforms.get("includePlatforms"),
            "excludePlatforms": platforms.get("excludePlatforms"),
            "includeLocations": locations.get("includeLocations"),
            "excludeLocations": locations.get("excludeLocations"),
        },
        "grant_controls": {
            "operator":                    grant.get("operator"),
            "builtInControls":             grant.get("builtInControls"),
            "customAuthenticationFactors": grant.get("customAuthenticationFactors"),
            "termsOfUse":                  grant.get("termsOfUse"),
        },
        "session_controls": policy.get("sessionControls") or {},
    }


@enum_app.command("cap")
@handle_cli_errors
def enum_ca_policies(
    tenant: str = typer.Option(None, "-tenant", help="Tenant ID"),
    client_id: str = typer.Option(None, "-clientid", help="Client ID"),
    output: OutputFormat = output_option(OutputFormat.json),
):
    """Enumerate Conditional Access policies via Microsoft Graph"""
    tenant, headers = prepare_session(tenant, client_id, "graph")
    graph = f"https://graph.microsoft.com/{API_VERSIONS['graph']}"

    policies = graph_collect(f"{graph}/identity/conditionalAccess/policies", headers)

    user_group_ids = set()
    for p in policies:
        users = (p.get("conditions", {}) or {}).get("users", {}) or {}
        user_group_ids |= _resolvable_ids(
            users.get("includeUsers"), users.get("excludeUsers"),
            users.get("includeGroups"), users.get("excludeGroups"),
        )
    names = resolve_principal_names(headers, graph, user_group_ids)

    projected = [_project_ca_policy(p, names) for p in policies]
    render(console, f"Conditional Access Policies in {tenant}", columns.CAPOLICY, projected,
           output=output, xml_root_tag="policies", xml_item_tag="policy")
    if output == OutputFormat.table:
        enabled = sum(1 for p in projected if p["state"] == "enabled")
        console.print(f"[bold]{len(projected)}[/] policies total "
                      f"([bold]{enabled}[/] enforced, [bold yellow]{len(projected) - enabled}[/] disabled/report-only)")
