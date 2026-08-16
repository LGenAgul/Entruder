import re
import json
import base64



def parse_error(description: str) -> str:
     from entruder.globals import ERROR_CODES
     match = re.match(r"AADSTS\d+", description or "")
     identifier = match.group() if match else None
     return ERROR_CODES.get(identifier, description) if identifier else description



def parse_xml_tag(root, tag) -> str:
            el = root.find(tag)
            return el.text if el is not None else "N/A"

def decode_jwt(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
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
         "refresh_token": result.get("refresh_token")
     }

def csv_to_list(csv: str) -> list:
      return [item.strip() for item in csv.split(",") if item.strip()]

def resolve_resource(resource: str) -> str:
    from entruder.globals import PLANES
    return PLANES.get(resource, resource)

def resolve_plane_from_resource(resource: str) -> str:
    from entruder.globals import RESOURCE_SHORTCUTS

    if resource in RESOURCE_SHORTCUTS:
        return resource

    reverse = {v: k for k, v in RESOURCE_SHORTCUTS.items()}
    return reverse.get(resource, resource)

def resolve_plane_from_scope(scope: str) -> str:
    """
    Derive the plane a v2-endpoint scope belongs to, e.g.
    "https://graph.microsoft.com/.default" -> "graph". Falls back to the raw
    scope string when it isn't a resource-URI-shaped scope or matches nothing.
    """
    if not scope.startswith("http"):
        return scope
    origin = scope.rsplit("/", 1)[0] + "/"
    return resolve_plane_from_resource(origin)


def save_domain_mapping(domain: str, tenant: str) -> None:
    from entruder.globals import DOMAINS_FILE, CACHE_DIR   
    CACHE_DIR.mkdir(mode=0o700, exist_ok=True)
    domains = {}
    if DOMAINS_FILE.exists():
         domains = json.loads(DOMAINS_FILE.read_text())
    domains[domain] = tenant
    DOMAINS_FILE.write_text(json.dumps(domains, indent=2))
    DOMAINS_FILE.chmod(0o600)

def is_domain(value: str) -> bool:
    return bool(re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$').match(value))

def resolve_tenant_from_domain(tenant: str):
    # skip resolving if not a domain
    if not is_domain(tenant):
         return tenant
    
    from entruder.globals import DOMAINS_FILE
    if not DOMAINS_FILE.exists():
        return None

    domains = json.loads(DOMAINS_FILE.read_text())
    mapped_tenant=domains.get(tenant)
    if mapped_tenant:
         return mapped_tenant
    # domain not found thus we return nothing for the app to quit
    return None

def require_tenant(tenant: str, console):
     import typer
     resolved_tenant = resolve_tenant_from_domain(tenant)
     if not resolved_tenant:
        console.print(f"[bold red][-][/] Could not resolve {tenant} to a known tenant")
        console.print(f"[bold][-][/] To resolve a domain to a tenant and store it in cache do: entruder enum tenant -domain <DOMAIN>")
        raise typer.Exit(1)
     return resolved_tenant