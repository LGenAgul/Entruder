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

# temporary, probably will make a class of this later
def resolve_plane_from_resource(resource: str) -> str:
    from entruder.globals import RESOURCE_SHORTCUTS
    
    if resource in RESOURCE_SHORTCUTS:
        return resource
    
    reverse = {v: k for k, v in RESOURCE_SHORTCUTS.items()}
    return reverse.get(resource, resource)