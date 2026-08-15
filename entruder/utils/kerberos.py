import sys
from base64 import b64encode
# platform dependent import for the kerberos module



def get_kerberos_service_ticket(spn: str) -> str:
    """Request a Kerberos Service Ticket for the SSO service principal"""
    if sys.platform == "win32":
        return _get_ticket_windows(spn)
    return _get_ticket_unix(spn)
    


def _get_ticket_unix(spn: str) -> str:
    try:
        import gssapi
    except ImportError:
        raise ImportError("gssapi not installed. Run: pip install kerberos --user")
    name = gssapi.Name(spn, gssapi.NameType.kerberos_principal)
    ctx = gssapi.SecurityContext(name=name, usage="initiate")
    token = ctx.step()
    return b64encode(token).decode()

def _get_ticket_windows(spn: str) -> str:
    try:
        import winkerberos
    except ImportError:
        raise ImportError("winkerberos not installed. Run: pip install kerberos --user")

    status, ctx = winkerberos.authGSSClientInit(spn)
    if status != winkerberos.AUTH_GSS_COMPLETE:
        raise Exception(f"Failed to initialize Kerberos context: {status}")
    status = winkerberos.authGSSClientStep(ctx,"")   
    # alraedy returns base64 encoded ticket
    if status == winkerberos.AUTH_GSS_COMPLETE or status == winkerberos.AUTH_GSS_CONTINUE:
        token = winkerberos.authGSSClientResponse(ctx)
        return token
    raise Exception(f"Failed to get Kerberos token: {status}")