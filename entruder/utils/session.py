
from .logging import vprint

def save_session(tenant: str, client_id: str, tokens: dict, refresh_token: str=None) -> None:
    from entruder.globals import SESSIONS_DIR
    import json

    session_file = SESSIONS_DIR / f"{tenant}.json"
    
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