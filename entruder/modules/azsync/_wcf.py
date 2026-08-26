"""
Minimal .NET Binary XML (MC-NBFX / "application/soap+msbin1") codec plus the
MSOnline password-hash helpers, ported from AADInternals' AzureADConnectAPI.

The AzureAD Connect sync SOAP endpoint (adminwebservice.microsoftonline.com/
provisioningservice.svc) only speaks WCF binary XML, so we need to serialise the
request envelope to MC-NBFX and parse the binary response back.

Write path: we emit *literal* records only (no static-dictionary references).
That is fully valid msbin1 and a conformant WCF reader reconstructs the exact
same infoset, which keeps the encoder small and removes the guesswork around
dictionary-id parity. Read path: the server answers with heavy dictionary use,
so the reader below implements the WCF static string dictionary and the common
element/attribute/text records.
"""
import hashlib
import os
import struct


# ---------------------------------------------------------------------------
# MD4 (pure Python — OpenSSL 3 drops md4 from the default provider)
# ---------------------------------------------------------------------------
def md4(data: bytes) -> bytes:
    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    msg = bytearray(data)
    orig_len_bits = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len_bits)

    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d

        def F(x, y, z):
            return (x & y) | (~x & z)

        def G(x, y, z):
            return (x & y) | (x & z) | (y & z)

        def H(x, y, z):
            return x ^ y ^ z

        for i, s in zip(range(16), [3, 7, 11, 19] * 4):
            a = lrot((a + F(b, c, d) + X[i]) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        for i, s in zip([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15],
                        [3, 5, 9, 13] * 4):
            a = lrot((a + G(b, c, d) + X[i] + 0x5A827999) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        for i, s in zip([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15],
                        [3, 9, 11, 15] * 4):
            a = lrot((a + H(b, c, d) + X[i] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


def create_aad_hash(password: str, iterations: int = 1000) -> str:
    """Build the CredentialData blob AAD sync expects (Create-AADHash).

    v1;PPH1_MD4,<salt-hex>,<iterations>,<pbkdf2-hex>;
    """
    md4_hex = md4(password.encode("utf-16-le")).hex().upper()          # 32 chars
    md4_bytes = md4_hex.encode("utf-16-le")                            # 64 bytes
    salt = os.urandom(10)
    dk = hashlib.pbkdf2_hmac("sha256", md4_bytes, salt, iterations, dklen=32)
    return f"v1;PPH1_MD4,{salt.hex()},{iterations},{dk.hex()};"


# ---------------------------------------------------------------------------
# MC-NBFX writer (literal records only)
# ---------------------------------------------------------------------------
def _mbi31(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


class NbfxWriter:
    """Serialises an element tree to MC-NBFX using only literal records."""

    def __init__(self):
        self.buf = bytearray()

    def _string(self, s):
        b = s.encode("utf-8")
        self.buf += _mbi31(len(b))
        self.buf += b

    def _text(self, s):
        b = s.encode("utf-8")
        n = len(b)
        if n <= 0xFF:
            self.buf.append(0x98)            # Chars8Text
            self.buf.append(n)
        elif n <= 0xFFFF:
            self.buf.append(0x9A)            # Chars16Text
            self.buf += struct.pack("<H", n)
        else:
            self.buf.append(0x9C)            # Chars32Text
            self.buf += struct.pack("<i", n)
        self.buf += b

    def start_element(self, prefix, name):
        if prefix:
            self.buf.append(0x41)            # Element (prefix + name)
            self._string(prefix)
        else:
            self.buf.append(0x40)            # ShortElement
        self._string(name)

    def xmlns(self, prefix, ns):
        if prefix:
            self.buf.append(0x09)            # XmlnsAttribute
            self._string(prefix)
        else:
            self.buf.append(0x08)            # ShortXmlnsAttribute
        self._string(ns)

    def attribute(self, prefix, name, value):
        if prefix:
            self.buf.append(0x05)            # Attribute
            self._string(prefix)
        else:
            self.buf.append(0x04)            # ShortAttribute
        self._string(name)
        self._text(value)

    def text(self, value):
        self._text(value)

    def end_element(self):
        self.buf.append(0x01)


class Elem:
    """Tiny XML node. qname is 'prefix:local' or 'local'."""

    __slots__ = ("qname", "ns", "attrs", "text", "children")

    def __init__(self, qname, ns=None, attrs=None, text=None, children=None):
        self.qname = qname
        self.ns = ns or {}                   # {prefix_or_'': uri}
        self.attrs = attrs or []             # [(qname, value)]
        self.text = text
        self.children = children or []


def _split(qname):
    if ":" in qname:
        p, n = qname.split(":", 1)
        return p, n
    return "", qname


def encode_document(root: Elem) -> bytes:
    w = NbfxWriter()

    def walk(el):
        p, n = _split(el.qname)
        w.start_element(p, n)
        for prefix, uri in el.ns.items():
            w.xmlns(prefix, uri)
        for aq, av in el.attrs:
            ap, an = _split(aq)
            w.attribute(ap, an, av)
        if el.text is not None:
            w.text(el.text)
        for c in el.children:
            walk(c)
        w.end_element()

    walk(root)
    return bytes(w.buf)


# ---------------------------------------------------------------------------
# MC-NBFX reader (handles the dictionary records the server sends back)
# ---------------------------------------------------------------------------
class _Node:
    __slots__ = ("name", "text", "children")

    def __init__(self, name):
        self.name = name
        self.text = None
        self.children = []

    def find(self, localname):
        """Depth-first search for the first descendant with this local name."""
        for c in self.children:
            if c.name == localname:
                return c
            hit = c.find(localname)
            if hit:
                return hit
        return None

    def find_all(self, localname):
        out = []
        for c in self.children:
            if c.name == localname:
                out.append(c)
            out.extend(c.find_all(localname))
        return out


class NbfxReader:
    def __init__(self, data: bytes):
        self.d = data
        self.p = 0

    def _byte(self):
        b = self.d[self.p]
        self.p += 1
        return b

    def _mbi31(self):
        val = 0
        shift = 0
        while True:
            b = self._byte()
            val |= (b & 0x7F) << shift
            if not (b & 0x80):
                return val
            shift += 7

    def _string(self):
        n = self._mbi31()
        s = self.d[self.p:self.p + n].decode("utf-8", "replace")
        self.p += n
        return s

    def _dict_string(self):
        idx = self._mbi31()
        # static dictionary strings are even (id >> 1); session strings are odd
        # (msbin1 carries no session, so treat both leniently)
        key = idx >> 1
        return WCF_DICTIONARY[key] if 0 <= key < len(WCF_DICTIONARY) else f"?{idx}"

    def _text_value(self, code):
        base = code & 0xFE
        if base == 0x80:
            return "0"
        if base == 0x82:
            return "1"
        if base == 0x84:
            return "false"
        if base == 0x86:
            return "true"
        if base == 0x88:
            v = self.d[self.p]; self.p += 1
            return str(v - 256 if v > 127 else v)
        if base == 0x8A:
            v = struct.unpack("<h", self.d[self.p:self.p + 2])[0]; self.p += 2
            return str(v)
        if base == 0x8C:
            v = struct.unpack("<i", self.d[self.p:self.p + 4])[0]; self.p += 4
            return str(v)
        if base == 0x8E:
            v = struct.unpack("<q", self.d[self.p:self.p + 8])[0]; self.p += 8
            return str(v)
        if base == 0x98:                     # Chars8
            n = self.d[self.p]; self.p += 1
            s = self.d[self.p:self.p + n].decode("utf-8", "replace"); self.p += n
            return s
        if base == 0x9A:                     # Chars16
            n = struct.unpack("<H", self.d[self.p:self.p + 2])[0]; self.p += 2
            s = self.d[self.p:self.p + n].decode("utf-8", "replace"); self.p += n
            return s
        if base == 0x9C:                     # Chars32
            n = struct.unpack("<i", self.d[self.p:self.p + 4])[0]; self.p += 4
            s = self.d[self.p:self.p + n].decode("utf-8", "replace"); self.p += n
            return s
        if base == 0xA8:                     # EmptyText
            return ""
        if base == 0xAA:                     # DictionaryText
            return self._dict_string()
        if base == 0xB4:                     # BoolText
            v = self.d[self.p]; self.p += 1
            return "true" if v else "false"
        if base == 0xB6:                     # UnicodeChars8
            n = self.d[self.p]; self.p += 1
            s = self.d[self.p:self.p + n].decode("utf-16-le", "replace"); self.p += n
            return s
        if base == 0xB8:                     # UnicodeChars16
            n = struct.unpack("<H", self.d[self.p:self.p + 2])[0]; self.p += 2
            s = self.d[self.p:self.p + n].decode("utf-16-le", "replace"); self.p += n
            return s
        raise ValueError(f"unsupported text record 0x{code:02x} at {self.p}")

    def _element_name(self, code):
        if code == 0x40:
            return self._string()
        if code == 0x41:
            self._string()                   # prefix
            return self._string()
        if code == 0x42:
            return self._dict_string()
        if code == 0x43:
            self._string()                   # prefix
            return self._dict_string()
        if 0x44 <= code <= 0x5D:             # PrefixDictionaryElement A..Z
            return self._dict_string()
        if 0x5E <= code <= 0x77:             # PrefixElement A..Z
            return self._string()
        raise ValueError(f"not an element record 0x{code:02x} at {self.p}")

    def _consume_attribute(self, code):
        if code in (0x04, 0x06):             # short (dict) attribute
            self._string() if code == 0x04 else self._dict_string()
            self._text_value(self._byte())
        elif code in (0x05, 0x07):           # attribute with prefix
            self._string()
            self._string() if code == 0x05 else self._dict_string()
            self._text_value(self._byte())
        elif code == 0x08:                   # xmlns=""
            self._string()
        elif code == 0x09:                   # xmlns:p=""
            self._string(); self._string()
        elif code == 0x0A:                   # xmlns (dict)
            self._dict_string()
        elif code == 0x0B:                   # xmlns:p (dict)
            self._string(); self._dict_string()
        elif 0x0C <= code <= 0x25:           # PrefixDictionaryAttribute A..Z
            self._dict_string()
            self._text_value(self._byte())
        elif 0x26 <= code <= 0x3F:           # PrefixAttribute A..Z
            self._string()
            self._text_value(self._byte())
        else:
            raise ValueError(f"not an attribute record 0x{code:02x} at {self.p}")

    @staticmethod
    def _is_element(code):
        return code == 0x40 or code == 0x41 or code == 0x42 or code == 0x43 \
            or (0x44 <= code <= 0x77)

    @staticmethod
    def _is_attribute(code):
        return code <= 0x3F and code not in (0x01, 0x02, 0x03)

    def parse(self):
        root = _Node("#document")
        stack = [root]
        while self.p < len(self.d):
            code = self._byte()
            if code == 0x01:                 # EndElement
                if len(stack) > 1:
                    stack.pop()
            elif code == 0x02:               # Comment
                self._string()
            elif self._is_element(code):
                node = _Node(self._element_name(code))
                stack[-1].children.append(node)
                stack.append(node)
            elif self._is_attribute(code):
                self._consume_attribute(code)
            elif code >= 0x80:               # text record
                value = self._text_value(code)
                node = stack[-1]
                node.text = (node.text or "") + value
                if code & 0x01:              # WithEndElement variant
                    if len(stack) > 1:
                        stack.pop()
            else:
                raise ValueError(f"unexpected record 0x{code:02x} at {self.p}")
        return root


def parse_binary_response(data: bytes) -> _Node:
    return NbfxReader(data).parse()


# The WCF static string dictionary (ServiceModel), in Add() order. On the wire a
# static dictionary string id is 2*index, so the reader looks up index = id >> 1.
WCF_DICTIONARY = [
    "mustUnderstand", "Envelope", "http://www.w3.org/2003/05/soap-envelope",
    "http://www.w3.org/2005/08/addressing", "Header", "Action", "To", "Body",
    "Algorithm", "RelatesTo", "http://www.w3.org/2005/08/addressing/anonymous",
    "URI", "Reference", "MessageID", "Id", "Identifier",
    "http://schemas.xmlsoap.org/ws/2005/02/rm", "Transforms", "Transform",
    "DigestMethod", "DigestValue", "Address", "ReplyTo",
    "SequenceAcknowledgement", "AcknowledgementRange", "Upper", "Lower",
    "BufferRemaining", "http://schemas.microsoft.com/ws/2006/05/rm",
    "http://schemas.xmlsoap.org/ws/2005/02/rm/SequenceAcknowledgement",
    "SecurityTokenReference", "Sequence", "MessageNumber",
    "http://www.w3.org/2000/09/xmldsig#",
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature", "KeyInfo",
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "http://www.w3.org/2001/04/xmlenc#", "http://schemas.xmlsoap.org/ws/2005/02/sc",
    "DerivedKeyToken", "Nonce", "Signature", "SignedInfo",
    "CanonicalizationMethod", "SignatureMethod", "SignatureValue",
    "DataReference", "EncryptedData", "EncryptionMethod", "CipherData",
    "CipherValue",
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    "Security", "Timestamp", "Created", "Expires", "Length", "ReferenceList",
    "ValueType", "Type", "EncryptedHeader",
    "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd",
    "RequestSecurityTokenResponseCollection",
    "http://schemas.xmlsoap.org/ws/2005/02/trust",
    "http://schemas.xmlsoap.org/ws/2005/02/trust#BinarySecret",
    "http://schemas.microsoft.com/ws/2006/02/transactions", "s", "Fault",
    "MustUnderstand", "role", "relay", "Code", "Reason", "Text", "Node", "Role",
    "Detail", "Value", "Subcode", "NotUnderstood", "qname", "", "From", "FaultTo",
    "EndpointReference", "PortType", "ServiceName", "PortName",
    "ReferenceProperties", "RelationshipType", "Reply", "a",
    "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity", "Identity", "Spn",
    "Upn", "Rsa", "Dns", "X509v3Certificate",
    "http://www.w3.org/2005/08/addressing/fault", "ReferenceParameters",
    "IsReferenceParameter", "http://www.w3.org/2005/08/addressing/reply",
    "http://www.w3.org/2005/08/addressing/none", "Metadata",
    "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
    "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault",
    "http://schemas.xmlsoap.org/ws/2004/06/addressingex", "RedirectTo", "Via",
    "http://www.w3.org/2001/10/xml-exc-c14n#", "PrefixList", "InclusiveNamespaces",
    "ec", "SecurityContextToken", "Generation", "Label", "Offset", "Properties",
    "Cookie", "wsc", "http://schemas.xmlsoap.org/ws/2004/04/sc",
    "http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk",
    "http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct",
    "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/SCT",
    "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/SCT", "RenewNeeded",
    "BadContextToken", "c", "http://schemas.xmlsoap.org/ws/2005/02/sc/dk",
    "http://schemas.xmlsoap.org/ws/2005/02/sc/sct",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Renew",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Renew",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel",
    "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
    "http://www.w3.org/2001/04/xmlenc#kw-aes128",
    "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
    "http://www.w3.org/2001/04/xmlenc#kw-aes192",
    "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
    "http://www.w3.org/2001/04/xmlenc#kw-aes256",
    "http://www.w3.org/2001/04/xmlenc#des-cbc",
    "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
    "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    "http://schemas.xmlsoap.org/ws/2005/02/sc/dk/p_sha1",
    "http://www.w3.org/2001/04/xmlenc#ripemd160",
    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
    "http://www.w3.org/2000/09/xmldsig#sha1",
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://www.w3.org/2001/04/xmlenc#sha512",
    "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
    "http://www.w3.org/2001/04/xmlenc#kw-tripledes",
    "http://schemas.xmlsoap.org/2005/02/trust/tlsnego#TLS_Wrap",
    "http://schemas.xmlsoap.org/2005/02/trust/spnego#GSS_Wrap",
    "http://schemas.microsoft.com/ws/2006/05/security", "dnse", "o", "Password",
    "PasswordText", "Username", "UsernameToken", "BinarySecurityToken",
    "EncodingType", "KeyIdentifier",
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary",
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#HexBinary",
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Text",
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier",
    "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ",
    "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ1510",
    "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID",
    "Assertion", "urn:oasis:names:tc:SAML:1.0:assertion",
    "http://docs.oasis-open.org/wss/oasis-wss-rel-token-profile-1.0.pdf#license",
    "FailedAuthentication", "InvalidSecurityToken", "InvalidSecurity", "k",
    "SignatureConfirmation",
    "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1",
    "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey",
    "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1",
    "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1",
    "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
    "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID",
    "AUTH-HASH", "RequestSecurityTokenResponse", "KeySize",
    "RequestedTokenReference", "AppliesTo", "Authenticator", "CombinedHash",
    "BinaryExchange", "Lifetime", "RequestedSecurityToken", "Entropy",
    "RequestedProofToken", "ComputedKey", "RequestSecurityToken", "RequestType",
    "Context", "BinarySecret", "http://schemas.xmlsoap.org/ws/2005/02/trust/spnego",
    " http://schemas.xmlsoap.org/ws/2005/02/trust/tlsnego", "wst",
    "http://schemas.xmlsoap.org/ws/2004/04/trust",
    "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue",
    "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Issue",
    "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue",
    "http://schemas.xmlsoap.org/ws/2004/04/security/trust/CK/PSHA1",
    "http://schemas.xmlsoap.org/ws/2004/04/security/trust/SymmetricKey",
    "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Nonce", "KeyType",
    "http://schemas.xmlsoap.org/ws/2004/04/trust/SymmetricKey",
    "http://schemas.xmlsoap.org/ws/2004/04/trust/PublicKey", "Claims",
    "InvalidRequest", "RequestFailed", "SignWith", "EncryptWith",
    "EncryptionAlgorithm", "CanonicalizationAlgorithm", "ComputedKeyAlgorithm",
    "UseKey", "http://schemas.microsoft.com/net/2004/07/secext/WS-SPNego",
    "http://schemas.microsoft.com/net/2004/07/secext/TLSNego", "t",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce", "RenewTarget",
    "CancelTarget", "RequestedTokenCancelled", "RequestedAttachedReference",
    "RequestedUnattachedReference", "IssuedTokens",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/Renew",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel",
    "http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey", "Access",
    "AccessDecision", "Advice", "AssertionID", "AssertionIDReference", "Attribute",
    "AttributeName", "AttributeNamespace", "AttributeStatement", "AttributeValue",
    "Audience", "AudienceRestrictionCondition", "AuthenticationInstant",
    "AuthenticationMethod", "AuthenticationStatement", "AuthorityBinding",
    "AuthorityKind", "AuthorizationDecisionStatement", "Binding", "Condition",
    "Conditions", "Decision", "DoNotCacheCondition", "Evidence", "IssueInstant",
    "Issuer", "Location", "MajorVersion", "MinorVersion", "NameIdentifier",
    "Format", "NameQualifier", "Namespace", "NotBefore", "NotOnOrAfter", "saml",
    "Statement", "Subject", "SubjectConfirmation", "SubjectConfirmationData",
    "ConfirmationMethod", "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key",
    "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches", "SubjectLocality",
    "DNSAddress", "IPAddress", "SubjectStatement",
    "urn:oasis:names:tc:SAML:1.0:am:unspecified", "xmlns", "Resource", "UserName",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
    "EmailName", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "u",
    "ChannelInstance", "http://schemas.microsoft.com/ws/2005/02/duplex",
    "Encoding", "MimeType", "CarriedKeyName", "Recipient", "EncryptedKey",
    "KeyReference", "e", "http://www.w3.org/2001/04/xmlenc#Element",
    "http://www.w3.org/2001/04/xmlenc#Content", "KeyName", "MgmtData", "KeyValue",
    "RSAKeyValue", "Modulus", "Exponent", "X509Data", "X509IssuerSerial",
    "X509IssuerName", "X509SerialNumber", "X509Certificate", "AckRequested",
    "http://schemas.xmlsoap.org/ws/2005/02/rm/AckRequested", "AcksTo", "Accept",
    "CreateSequence", "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence",
    "CreateSequenceRefused", "CreateSequenceResponse",
    "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequenceResponse", "FaultCode",
    "InvalidAcknowledgement", "LastMessage",
    "http://schemas.xmlsoap.org/ws/2005/02/rm/LastMessage",
    "LastMessageNumberExceeded", "MessageNumberRollover", "Nack", "netrm", "Offer",
    "r", "SequenceFault", "SequenceTerminated", "TerminateSequence",
    "http://schemas.xmlsoap.org/ws/2005/02/rm/TerminateSequence", "UnknownSequence",
    "http://schemas.microsoft.com/ws/2006/02/tx/oletx", "oletx", "OleTxTransaction",
    "PropagationToken", "http://schemas.xmlsoap.org/ws/2004/10/wscoor", "wscoor",
    "CreateCoordinationContext", "CreateCoordinationContextResponse",
    "CoordinationContext", "CurrentContext", "CoordinationType",
    "RegistrationService", "Register", "RegisterResponse", "ProtocolIdentifier",
    "CoordinatorProtocolService", "ParticipantProtocolService",
    "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContext",
    "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContextResponse",
    "http://schemas.xmlsoap.org/ws/2004/10/wscoor/Register",
    "http://schemas.xmlsoap.org/ws/2004/10/wscoor/RegisterResponse",
    "http://schemas.xmlsoap.org/ws/2004/10/wscoor/fault",
    "ActivationCoordinatorPortType", "RegistrationCoordinatorPortType",
    "InvalidState", "InvalidProtocol", "InvalidParameters", "NoActivity",
    "ContextRefused", "AlreadyRegistered", "http://schemas.xmlsoap.org/ws/2004/10/wsat",
    "wsat", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Completion",
    "http://schemas.xmlsoap.org/ws/2004/10/wsat/Durable2PC",
    "http://schemas.xmlsoap.org/ws/2004/10/wsat/Volatile2PC", "Prepare", "Prepared",
    "ReadOnly", "Commit", "Rollback", "Committed", "Aborted", "Replay",
    "http://schemas.xmlsoap.org/ws/2004/10/wsat/Commit",
    "http://schemas.xmlsoap.org/ws/2004/10/wsat/Rollback",
    "http://schemas.xmlsoap.org/ws/2004/10/wsat/Committed",
    "http://schemas.xmlsoap.org/ws/2004/10/wsat/Aborted",
    "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepare",
    "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepared",
    "http://schemas.xmlsoap.org/ws/2004/10/wsat/ReadOnly",
    "http://schemas.xmlsoap.org/ws/2004/10/wsat/Replay",
    "http://schemas.xmlsoap.org/ws/2004/10/wsat/fault",
    "CompletionCoordinatorPortType", "CompletionParticipantPortType",
    "CoordinatorPortType", "ParticipantPortType", "InconsistentInternalState",
    "mstx", "Enlistment", "protocol", "LocalTransactionId", "IsolationLevel",
    "IsolationFlags", "Description", "Loopback", "RegisterInfo", "ContextId",
    "TokenId", "AccessDenied", "InvalidPolicy", "CoordinatorRegistrationFailed",
    "TooManyEnlistments", "Disabled", "ActivityId",
    "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics",
    "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5APREQSHA1",
    "http://schemas.xmlsoap.org/ws/2002/12/policy", "FloodMessage", "LinkUtility",
    "Hops", "http://schemas.microsoft.com/net/2006/05/peer/HopCount", "PeerVia",
    "http://schemas.microsoft.com/net/2006/05/peer", "PeerFlooder", "PeerTo",
    "http://schemas.microsoft.com/ws/2005/05/routing", "PacketRoutable",
    "http://schemas.microsoft.com/ws/2005/05/addressing/none",
    "http://schemas.microsoft.com/ws/2005/05/envelope/none",
    "http://www.w3.org/2001/XMLSchema-instance", "http://www.w3.org/2001/XMLSchema",
    "nil", "type", "char", "boolean", "byte", "unsignedByte", "short",
    "unsignedShort", "int", "unsignedInt", "long", "unsignedLong", "float",
    "double", "decimal", "dateTime", "string", "base64Binary", "anyType",
    "duration", "guid", "anyURI", "QName", "time", "date", "hexBinary",
    "gYearMonth", "gYear", "gMonthDay", "gDay",
]
