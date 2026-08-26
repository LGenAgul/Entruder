
from .logging import vprint
from .auth import refresh_access_token
from .parser import parse_token, parse_error
from entruder.static import SESSIONS_DIR, EXPIRY_BUFFER, ACTIVE_FILE, RESOURCE_SHORTCUTS
import json
import time

SESSION_SCHEMA = {
    "type": "object",
    "required": ["tenant", "client_id", "tokens"],
    "properties": {
        "tenant": {
            "type": "string",
            # every login command accepts --tenant as a GUID, a domain name
            # (contoso.onmicrosoft.com), or one of AAD's multi-tenant aliases —
            # a GUID-only pattern here rejects perfectly valid sessions
            "pattern": "^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|common|organizations|consumers|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)$"
        },
        "client_id": {
            "type": "string",
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        },
        "upn": {
            "type": ["string", "null"]
        },
        "refresh_token": {
            "type": ["string", "null"]
        },
        "tokens": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "required": ["value", "expires_at"],
                "properties": {
                    "value": {"type": "string"},
                    "expires_at": {"type": ["integer", "null"]},
                    "wids": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "upn": {"type": ["string", "null"]}
                }
            }
        }
    }
}

def initialize_tenant_cache(tenant: str, client_id: str) -> None:
    from entruder.static import CACHE_DIR
    CACHE_DIR.mkdir(mode=0o700, exist_ok=True)
    body = {"tenant": tenant, "client_id": client_id}
    ACTIVE_FILE.write_text(json.dumps(body, indent=2))
    ACTIVE_FILE.chmod(0o600)
    vprint(f"[dim]Tenant cache saved: tenant={tenant}, client_id={client_id}[/dim]")


def get_tenant_cache(tenant: str = None, client_id: str = None) -> tuple:
    """
    Resolve tenant/client_id independently: whatever the caller explicitly
    passed is used as-is, and the cached active session only fills in whichever
    value is missing — it never overrides an explicitly-provided value. Always
    returns a safely-unpackable 2-tuple; unresolved values come back as None
    rather than the whole call returning a bare None.
    """
    cached_tenant, cached_client_id = None, None
    if not (tenant and client_id) and ACTIVE_FILE.exists():
        body = json.loads(ACTIVE_FILE.read_text())
        cached_tenant, cached_client_id = body.get("tenant"), body.get("client_id")

    return tenant or cached_tenant, client_id or cached_client_id


def require_tenant_cache(tenant: str, client_id: str, console) -> tuple:
    """
    Like get_tenant_cache, but hard-exits with a clear message if either
    value is still missing after checking the cache — mirrors require_session's
    "get_X returns best-effort, require_X gates it" pattern.
    """
    import typer

    resolved_tenant, resolved_client_id = get_tenant_cache(tenant, client_id)
    missing = [flag for flag, value in (("--tenant", resolved_tenant), ("--client-id", resolved_client_id)) if not value]
    if missing:
        console.print(f"[bold red][-][/] Missing {' and '.join(missing)}, and no active tenant information found")
        console.print("[dim] Pass them explicitly, or run a login command first to set an active session[/dim]")
        raise typer.Exit(1)

    return resolved_tenant, resolved_client_id


def save_session(tenant: str, client_id: str, tokens: dict, refresh_token: str=None) -> None:
    """
    The write operation for session files, labeled with ~/entruder/<TENANT_ID>+<CLIENT_ID>.json
    """
    safe_client = "".join(c if c.isalnum() or c in "-_" else "_" for c in client_id)
    session_file = SESSIONS_DIR / f"{tenant}_{safe_client}.json"

    # load existing
    existing = {}
    if session_file.exists():
        existing = json.loads(session_file.read_text())
    
    existing_tokens = existing.get("tokens", {})
    existing_tokens.update(tokens)

    if refresh_token is None:
        refresh_token = next(
            (t.get("refresh_token") for t in tokens.values() if t.get("refresh_token")),
            None,
        )

    existing.update({
        "tenant": tenant,
        "client_id": client_id,
        "tokens": existing_tokens,
        "refresh_token": refresh_token or existing.get("refresh_token")
    })

    session_file.write_text(json.dumps(existing, indent=2))
    session_file.chmod(0o600)
    vprint(f"Session written to {session_file} (planes: {', '.join(existing_tokens)})")


def get_session(tenant: str, client_id: str) -> dict:
    """ Return the session file as json """
    safe_client = "".join(c if c.isalnum() or c in "-_" else "_" for c in client_id)
    session_file = SESSIONS_DIR / f"{tenant}_{safe_client}.json"
    if not session_file.exists():
        return {}
    
    with open(session_file,"r") as session:
        return json.loads(session.read())

def require_session(tenant: str, client_id: str, plane: str, console) -> str:
    import typer

    session = get_session(tenant, client_id)
    if not session:
        console.print(f"[bold red][-][/] No valid session found for {tenant} / {client_id}")
        console.print(f"[dim] To receive a session run: entruder login <method> --tenant {tenant} --client-id {client_id} ... [/dim]")
        raise typer.Exit(1)

    if not validate_json(session):
        console.print(f"[bold red][-][/] Session file corrupted/malformed, or contains incorrect data for {tenant} / {client_id}")
        console.print(f"[dim] Invoke a new Auth Flow via: entruder login <method> --tenant {tenant} --client-id {client_id} ... [/dim]")
        raise typer.Exit(1)

    plane_missing = not session.get("tokens", {}).get(plane, {}).get("value")
    if (check_expired(session, plane) or plane_missing) and session.get("refresh_token"):
        session = _refresh_plane(tenant, client_id, plane, session, console)

    if check_expired(session, plane):
        console.print(f"[bold red][-][/] Session Expired for {tenant} / {client_id} on {plane} plane")
        console.print(f"[dim] Invoke a new Auth Flow via: entruder login <method> --tenant {tenant} --client-id {client_id} ... [/dim]")
        raise typer.Exit(1)

    token = session.get("tokens", {}).get(plane, {}).get("value")
    if not token:
        console.print(f"[bold red][-][/] No {plane} token in session")
        console.print(f"[dim]    Run: entruder login <method> --tenant {tenant} --client-id {client_id} --resource {plane}[/dim]")
        raise typer.Exit(1)
    return token


def _refresh_plane(tenant: str, client_id: str, plane: str, session: dict, console) -> dict:
    """Silently reissue `plane`'s token from the session's stored
    refresh_token instead of immediately failing to "log in again" — covers
    both an expired token and a plane that was simply never acquired (a
    refresh token isn't tied to the resource it was originally issued for).
    Returns the session unchanged if the redemption fails (e.g. Conditional
    Access blocks it, or this is a client-credential session with no
    refresh_token at all), so the caller's existing expired/missing checks
    report the failure exactly as before."""
    resource = RESOURCE_SHORTCUTS.get(plane, plane)
    result = refresh_access_token(tenant, client_id, session["refresh_token"], resource)

    if "access_token" not in result:
        vprint(f"Silent refresh failed for {plane}: "
               f"{parse_error(result.get('error_description', result.get('error', 'Unknown error')))}")
        return session

    save_session(tenant, client_id, {plane: parse_token(result)})
    console.print(f"[dim][*] Silently refreshed {plane} token via cached refresh token[/dim]")
    return get_session(tenant, client_id)


def validate_json(session: dict) -> bool:
    from jsonschema import validate, ValidationError
    try:
        validate(instance=session, schema=SESSION_SCHEMA)
        return True
    except ValidationError as e:
        return False


def check_expired(session: dict, plane) -> bool:
    expires_at = session.get("tokens",{}).get(plane,{}).get("expires_at")
    now = int(time.time())
    if expires_at and expires_at <= (now + EXPIRY_BUFFER):
        return True
    return False

