import typer
from datetime import datetime, timezone
from entruder.static import FOCI_CLIENTS, KNOWN_CLIENT_IDS, CLIENT_ID_ALIASES, DIRECTORY_ROLES, DIRECTORY_ROLE_TIER_ORDER
from entruder.utils import (
    decode_jwt,
    decode_jwt_header,
    handle_cli_errors,
    render,
    OutputFormat,
    output_option,
    get_session,
    require_tenant_cache,
)
from entruder.columns import Columns
from entruder.console import CONSOLE as console

info_app = typer.Typer(help="Local, offline lookups — token decoding and well-known ID maps", no_args_is_help=True)
columns = Columns()


def _fmt_epoch(ts):
    if not ts:
        return None
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _directory_roles(wids):
    """Map wids (role template IDs) to name/tier via DIRECTORY_ROLES. An
    unrecognized wid is still surfaced (not silently dropped) since an
    unmapped role is still evidence of *some* privileged assignment, just one
    outside our curated list."""
    roles = []
    for wid in wids or []:
        info = DIRECTORY_ROLES.get(wid)
        roles.append(f"{info['name']} ({info['tier']})" if info else f"unrecognized role ({wid})")
    return roles


def _highest_tier(wids):
    tiers_present = {DIRECTORY_ROLES[w]["tier"] for w in (wids or []) if w in DIRECTORY_ROLES}
    for tier in DIRECTORY_ROLE_TIER_ORDER:
        if tier in tiers_present:
            return tier
    return "none"


def _identity_type(claims):
    """idtyp is only emitted on v2 tokens and only for app-only ones — its
    absence doesn't prove a delegated token, so this stays honest about that
    rather than guessing confidently from a missing claim."""
    if claims.get("idtyp") == "app":
        return "application (app-only)"
    if claims.get("upn") or claims.get("unique_name"):
        return "user (delegated)"
    return "unknown (no idtyp/upn claim — check aud/appid manually)"


def _analyze_claims(token: str) -> dict:
    claims = decode_jwt(token)
    if not claims:
        return {"error": "Could not decode token — not a valid JWT"}

    header = decode_jwt_header(token)
    now = int(datetime.now(tz=timezone.utc).timestamp())
    exp = claims.get("exp")
    wids = claims.get("wids", []) or []
    app_id = claims.get("appid") or claims.get("azp")
    is_foci = app_id in FOCI_CLIENTS.values()
    amr = claims.get("amr") or []
    scp = claims.get("scp")

    return {
        "identity_type":     _identity_type(claims),
        "upn":               claims.get("upn") or claims.get("unique_name"),
        "name":              claims.get("name"),
        "object_id":         claims.get("oid"),
        "app_id":            app_id,
        # app_displayname isn't always issued (depends on optional-claims config,
        # token version, etc.) — fall back to the well-known client id map, same
        # pattern as _directory_roles() resolving a wid via DIRECTORY_ROLES.
        "app_display_name":  claims.get("app_displayname") or KNOWN_CLIENT_IDS.get(app_id),
        "tenant_id":         claims.get("tid"),
        "audience":          claims.get("aud"),
        "issuer":            claims.get("iss"),
        "directory_roles":   _directory_roles(wids),
        "highest_role_tier": _highest_tier(wids),
        "delegated_scopes":  scp.split() if isinstance(scp, str) else scp,
        "app_permissions":   claims.get("roles"),
        "mfa_performed":     "mfa" in amr,
        "auth_methods":      amr,
        "is_foci_client":    is_foci,
        "foci_hint":         ("FOCI family member — if a refresh_token is available, `login foci` can "
                               "redeem it against every other family member without re-authenticating") if is_foci else None,
        "issued_at":         _fmt_epoch(claims.get("iat")),
        "not_before":        _fmt_epoch(claims.get("nbf")),
        "expires_at":        _fmt_epoch(exp),
        "expired":           bool(exp and exp <= now),
        "token_version":     claims.get("ver"),
        "signing_alg":       header.get("alg"),
        "key_id":            header.get("kid"),
    }


@info_app.command("token")
@handle_cli_errors
def info_token(
    token: str = typer.Option(None, "-k", "--token",
        help="Raw JWT to analyze directly (e.g. a token captured out-of-band). "
             "Skips the session cache entirely — no auth needed for this, it's a local decode."),
    tenant: str = typer.Option(None, "-t", "--tenant", help="Tenant ID (optional — selects a specific cached session instead of the active one)"),
    client_id: str = typer.Option(None, "-c", "--client-id", help="Client ID (optional — selects a specific cached session instead of the active one)"),
    plane: str = typer.Option(None, "-p", "--plane", help="Only analyze this plane's cached token (graph/management/storage/keyvault). Default: every plane present in the session."),
    output: OutputFormat = output_option(),
):
    """Decode and analyze a JWT: identity type (delegated vs app-only),
    directory roles held (via wids, flagged by privilege tier), MFA (amr),
    FOCI-family membership, and expiry. With no --token, analyzes every plane
    in the active (or --tenant/--client-id) cached session."""
    if token:
        result = _analyze_claims(token)
        if "error" in result:
            console.print(f"[bold red][-][/] {result['error']}")
            raise typer.Exit(1)
        render(console, "Token analysis", columns.TOKEN, result, output=output, xml_item_tag="token")
        return

    resolved_tenant, resolved_client_id = require_tenant_cache(tenant, client_id, console)
    session = get_session(resolved_tenant, resolved_client_id)
    if not session:
        console.print(f"[bold red][-][/] No cached session for {resolved_tenant} / {resolved_client_id}")
        raise typer.Exit(1)

    tokens = session.get("tokens", {})
    planes = [plane] if plane else list(tokens.keys())

    results = []
    for p in planes:
        entry = tokens.get(p)
        if not entry or not entry.get("value"):
            console.print(f"[dim][-] No {p} token in this session, skipping[/dim]")
            continue
        analysis = _analyze_claims(entry["value"])
        if "error" in analysis:
            console.print(f"[dim][-] {p}: {analysis['error']}, skipping[/dim]")
            continue
        analysis["plane"] = p
        results.append(analysis)

    if not results:
        console.print("[bold red][-][/] No tokens to analyze in this session")
        raise typer.Exit(1)

    render(console, f"Token analysis for {resolved_tenant} / {resolved_client_id}", columns.TOKEN,
           results, output=output, xml_root_tag="tokens", xml_item_tag="token")


@info_app.command("clients")
@handle_cli_errors
def info_clients(
    output: OutputFormat = output_option(),
):
    """List well-known Microsoft first-party client IDs this tool recognizes (KNOWN_CLIENT_IDS).
    Entries with a value in "Resolve As" can be passed to any --client-id option by that name
    instead of the raw GUID (e.g. --client-id office)."""
    aliases_by_id = {}
    for name, cid in {**CLIENT_ID_ALIASES, **FOCI_CLIENTS}.items():
        aliases_by_id.setdefault(cid, []).append(name)

    records = [
        {"client_id": cid, "app_name": name, "resolve_as": ", ".join(sorted(aliases_by_id.get(cid, [])))}
        for cid, name in sorted(KNOWN_CLIENT_IDS.items(), key=lambda kv: kv[1])
    ]

    render(console, "Known Client IDs", columns.CLIENT_IDS, records, output=output,
           xml_root_tag="clients", xml_item_tag="client")
    if output == OutputFormat.table:
        console.print(f"[bold]{len(records)}[/] known client IDs, {len(aliases_by_id)} resolvable via --client-id shortcut")
