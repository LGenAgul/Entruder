
import base64,json

def parse_xml_tag(root, tag):
            el = root.find(tag)
            return el.text if el is not None else "N/A"

def decode_jwt(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(base64.b64decode(payload))
    except Exception:
        return {}