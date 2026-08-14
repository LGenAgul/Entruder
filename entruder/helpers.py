
import base64,json

def parse_xml_tag(root, tag) -> str:
            el = root.find(tag)
            return el.text if el is not None else "N/A"

def decode_jwt(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(base64.b64decode(payload))
    except Exception:
        return {}

def parse_token(result: dict) -> dict:
     claims = decode_jwt(result['access_token'])
     return {
         "value": result['access_token'],
         "expires_at": claims.get("exp"),
         "wids": claims.get("wids", []),
         "upn": claims.get("upn") or claims.get("unique_name"),
     }

def csv_to_list(csv: str) -> list:
      return [item.strip() for item in csv.split(",") if item.strip()]

def resolve_resource(resource: str) -> str:
    from entruder.globals import PLANES
    return PLANES.get(resource, resource)

# temporary, probably will make a class of this later

def save_session(tenant: str, client_id: str, tokens: dict) -> None:
    from entruder.globals import SESSIONS_DIR
    import json

    session_file = SESSIONS_DIR / f"{tenant}.json"
    
    # load existing
    existing = {}
    if session_file.exists():
        existing = json.loads(session_file.read_text())
    
    # deep merge tokens
    existing_tokens = existing.get("tokens", {})
    existing_tokens.update(tokens)
    
    existing.update({
        "tenant": tenant,
        "client_id": client_id,
        "tokens": existing_tokens
    })
    
    session_file.write_text(json.dumps(existing, indent=2))
    session_file.chmod(0o600)

def resolve_plane_from_resource(resource: str) -> str:
    from entruder.globals import RESOURCE_SHORTCUTS
    
    if resource in RESOURCE_SHORTCUTS:
        return resource
    
    reverse = {v: k for k, v in RESOURCE_SHORTCUTS.items()}
    return reverse.get(resource, resource)