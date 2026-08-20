from .logging import vprint
import httpx


def request_json(method: str, url: str, **kwargs) -> dict:

    from entruder.static import HTTP_TIMEOUT
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    vprint(f"{method} {url}")
    response = httpx.request(method, url, **kwargs)
    vprint(f"  -> HTTP {response.status_code} ({len(response.content)} bytes)")
    try:
        return response.json()
    except Exception:
        return {
            "error": "non_json_response",
            "error_description": f"HTTP {response.status_code}: {response.text[:200]}",
        }