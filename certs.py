import os
import ssl
import time
import datetime
import ipaddress
import sys
import typing
import contextlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pyasn1.type import univ, constraint, char, namedtype, tag
from pyasn1.codec.der.decoder import decode
from pyasn1.error import PyAsn1Error
import OpenSSL

import abc
import uuid


class Serializable(metaclass=abc.ABCMeta):
    """
    Abstract Base Class that defines an API to save an object's state and restore it later on.
    """

    @classmethod
    @abc.abstractmethod
    def from_state(cls, state):
        """
        Create a new object from the given state.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_state(self):
        """
        Retrieve object state.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def set_state(self, state):
        """
        Set object state to the given state.
        """
        raise NotImplementedError()

    def copy(self):
        state = self.get_state()
        if isinstance(state, dict) and "id" in state:
            state["id"] = str(uuid.uuid4())
        return self.from_state(state)

# Default expiry must not be too long: https://github.com/mitmproxy/mitmproxy/issues/815
DEFAULT_EXP = 94608000  # = 24 * 60 * 60 * 365 * 3
DEFAULT_EXP_DUMMY_CERT = 63072000  # = 2 years

# Generated with "openssl dhparam". It's too slow to generate this on startup.
DEFAULT_DHPARAM = b"""
-----BEGIN X9.42 DH PARAMETERS-----
MIIELAKCAgEAnpyXeimGxhutYL8jzOOIszomGtNWjQue7SfYflBXv8pmRrgS5Taw
ZIekOuKsl7d7kjzzWfmthLc7XU4r64RkeqDbHkkDC6xcZ2+YjjKLzh2D6j2l7sME
U1MNbWMdki/dqe6hQ0Ln36fhdM1jqpj6xThkpbsaFUEYzMQJsBliBdJ2/rugngvB
j90C0HU3Xpkrl4YM1BgA2d9jaoClSe0sMw1GBqnjWYw/C5o5L9ixYRIV/dh7IFZR
vNmcdU8HEV42VS0YMe2XO60mfzhF8oQqF4nRRuJybgag28TcsLO66PgyMeJY6Wo6
J+KcrWiyjxAGFl+HkePH9tf2Kf/c65BcCA7wUaW/XEgy48jF3P7WTT79exxECCP3
5dbDL/GowdpL1Yk8O9qL+uFrbeLG78suNincdm9QWNZg++z+EfVwzkU5plrICzdB
ztAm7Y9tE7x/x394J0YRBcejepa46i0MiPyiJ47/g15u7uIN9JIDWHh11zqIAeyS
mRRtLIdfpsstTN6wGY9hphA2daJD7Tt7kgBkeIk16J3OL/1vZydJFEinQTmfTA92
jAUL6mQAuCW01S1slMkT5LyUHkm3aM5dLwaabN5Y6v8jXrki/W3eU3Y13HXqg6NB
qfKgd8xDDH6zYP0nVVtezeqJ7ComOYd3KP/MSt3ap6FoeB4reeOqjWsCggIALX3a
HC0DjTMsDudsawnMEAWq+Fp1mCwG+UyoIgi77PMyseYQHlqdTcl+A+JcoMmJJSD4
rchfKFXs7TYBmgREck4LvtsAOA4fB6BB0N8IceONg/v2tqhMDhin1+1xqH63+tXK
qJuvCLTWgAUAZc1I8KAi36/5GrAOv8M5W/TENZKwZCc3X6Iv10UhGhJd91w6H5Rv
B2sW+m8EqOSQKxi4WtsG73ACQQ3QK01v14xoiTgojeXRvjdBKKA2VEC/nopaDG4/
GT9tK8iSHiNxj2HWc4oP9130lJpCdq4FDLZVHTmU6FzrUfbqNCYuhMAsMc45qZyZ
w6FOCKF4dRqlkY3JzsuUEiZfoycmByK6MhQJ1Ymj9i7QvJqFRL6jhMd87XPLyAxL
JzKgnbX+I0AUm3arq0aSCLUvbZt5Zszo18TsBJkyuVdloFPxzj77n4vLPWo9uo0t
MvngdQvOykJanUcXrRFLGG+ccpwdxjymsH0ssLvrnL3r5SxOFqkN7zXmHcemjuoS
adZEVQevu0ZFNWh3aFKtr/ghmfHifJypogRd0RqUVwi7Ee68a8ad+m4+Xse9mzm/
r7HUy9gb0nRQ1/IXgW+X5TGlmQtCzz3tKyUb2zBZ4vGZwJhukcHYKTWVhAezyLf2
zt8dIdffgWxrrzfqFqec98ls6kni+qMcWFqOXswCIQC+pW+ksC2+xhBP9UiwiWri
fM6kB9JgNHR6ytSwUJDLcQ==
-----END X9.42 DH PARAMETERS-----
"""


def create_ca(organization, cn, exp):
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(int(time.time() * 10000))
    cert.set_version(2)
    cert.get_subject().CN = cn
    cert.get_subject().O = organization
    cert.gmtime_adj_notBefore(-3600 * 48)
    cert.gmtime_adj_notAfter(exp)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.add_extensions([
        OpenSSL.crypto.X509Extension(
            b"basicConstraints",
            True,
            b"CA:TRUE"
        ),
        OpenSSL.crypto.X509Extension(
            b"nsCertType",
            False,
            b"sslCA"
        ),
        OpenSSL.crypto.X509Extension(
            b"extendedKeyUsage",
            False,
            b"serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC"
        ),
        OpenSSL.crypto.X509Extension(
            b"keyUsage",
            True,
            b"keyCertSign, cRLSign"
        ),
        OpenSSL.crypto.X509Extension(
            b"subjectKeyIdentifier",
            False,
            b"hash",
            subject=cert
        ),
    ])
    cert.sign(key, "sha256")
    return key, cert


def dummy_cert(privkey, cacert, commonname, sans, organization):
    """
        Generates a dummy certificate.
        privkey: CA private key
        cacert: CA certificate
        commonname: Common name for the generated certificate.
        sans: A list of Subject Alternate Names.
        organization: Organization name for the generated certificate.
        Returns cert if operation succeeded, None if not.
    """
    ss = []
    for i in sans:
        try:
            ipaddress.ip_address(i.decode("ascii"))
        except ValueError:
            ss.append(b"DNS:%s" % i)
        else:
            ss.append(b"IP:%s" % i)
    ss = b", ".join(ss)

    cert = OpenSSL.crypto.X509()
    cert.gmtime_adj_notBefore(-3600 * 48)
    cert.gmtime_adj_notAfter(DEFAULT_EXP_DUMMY_CERT)
    cert.set_issuer(cacert.get_subject())
    if commonname is not None and len(commonname) < 64:
        cert.get_subject().CN = commonname
    if organization is not None:
        cert.get_subject().O = organization
    cert.set_serial_number(int(time.time() * 10000))
    if ss:
        cert.set_version(2)
        cert.add_extensions(
            [OpenSSL.crypto.X509Extension(b"subjectAltName", False, ss)])
    cert.set_pubkey(cacert.get_pubkey())
    cert.add_extensions([
        OpenSSL.crypto.X509Extension(
            b"basicConstraints",
            True,
            b"CA:FALSE"
        ),
        OpenSSL.crypto.X509Extension(
            b"nsCertType",
            False,
            b"server, email"
        ),
        OpenSSL.crypto.X509Extension(
            b"extendedKeyUsage",
            False,
            b"serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC"
        ),
        OpenSSL.crypto.X509Extension(
            b"keyUsage",
            True,
            b"digitalSignature, keyEncipherment, dataEncipherment, keyAgreement"
        ),
        OpenSSL.crypto.X509Extension(
            b"subjectKeyIdentifier",
            False,
            b"hash",
            subject=cert
        ),
    ])
    cert.sign(privkey, "sha256")
    return Cert(cert)


class CertStoreEntry:

    def __init__(self, cert, privatekey, chain_file):
        self.cert = cert
        self.privatekey = privatekey
        self.chain_file = chain_file


TCustomCertId = bytes  # manually provided certs (e.g. mitmproxy's --certs)
TGeneratedCertId = typing.Tuple[typing.Optional[bytes], typing.Tuple[bytes, ...]]  # (common_name, sans)
TCertId = typing.Union[TCustomCertId, TGeneratedCertId]


class CertStore:

    """
        Implements an in-memory certificate store.
    """
    STORE_CAP = 100

    def __init__(
            self,
            default_privatekey,
            default_ca,
            default_chain_file,
            dhparams):
        self.default_privatekey = default_privatekey
        self.default_ca = default_ca
        self.default_chain_file = default_chain_file
        self.dhparams = dhparams
        self.certs: typing.Dict[TCertId, CertStoreEntry] = {}
        self.expire_queue = []

    def expire(self, entry):
        self.expire_queue.append(entry)
        if len(self.expire_queue) > self.STORE_CAP:
            d = self.expire_queue.pop(0)
            for k, v in list(self.certs.items()):
                if v == d:
                    del self.certs[k]

    @staticmethod
    def load_dhparam(path):

        # mitmproxy<=0.10 doesn't generate a dhparam file.
        # Create it now if necessary.
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(DEFAULT_DHPARAM)

        bio = OpenSSL.SSL._lib.BIO_new_file(path.encode(sys.getfilesystemencoding()), b"r")
        if bio != OpenSSL.SSL._ffi.NULL:
            bio = OpenSSL.SSL._ffi.gc(bio, OpenSSL.SSL._lib.BIO_free)
            dh = OpenSSL.SSL._lib.PEM_read_bio_DHparams(
                bio,
                OpenSSL.SSL._ffi.NULL,
                OpenSSL.SSL._ffi.NULL,
                OpenSSL.SSL._ffi.NULL)
            dh = OpenSSL.SSL._ffi.gc(dh, OpenSSL.SSL._lib.DH_free)
            return dh

    @classmethod
    def from_store(cls, path, basename):
        ca_path = os.path.join(path, basename + "-ca.pem")
        if not os.path.exists(ca_path):
            key, ca = cls.create_store(path, basename)
        else:
            with open(ca_path, "rb") as f:
                raw = f.read()
            ca = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM,
                raw)
            key = OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM,
                raw)
        dh_path = os.path.join(path, basename + "-dhparam.pem")
        dh = cls.load_dhparam(dh_path)
        return cls(key, ca, ca_path, dh)

    @staticmethod
    @contextlib.contextmanager
    def umask_secret():
        """
            Context to temporarily set umask to its original value bitor 0o77.
            Useful when writing private keys to disk so that only the owner
            will be able to read them.
        """
        original_umask = os.umask(0)
        os.umask(original_umask | 0o77)
        try:
            yield
        finally:
            os.umask(original_umask)

    @staticmethod
    def create_store(path, basename, organization=None, cn=None, expiry=DEFAULT_EXP):
        if not os.path.exists(path):
            os.makedirs(path)

        organization = organization or basename
        cn = cn or basename

        key, ca = create_ca(organization=organization, cn=cn, exp=expiry)
        # Dump the CA plus private key
        with CertStore.umask_secret(), open(os.path.join(path, basename + "-ca.pem"), "wb") as f:
            f.write(
                OpenSSL.crypto.dump_privatekey(
                    OpenSSL.crypto.FILETYPE_PEM,
                    key))
            f.write(
                OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    ca))

        # Dump the certificate in PEM format
        with open(os.path.join(path, basename + "-ca-cert.pem"), "wb") as f:
            f.write(
                OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    ca))

        # Create a .cer file with the same contents for Android
        with open(os.path.join(path, basename + "-ca-cert.cer"), "wb") as f:
            f.write(
                OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    ca))

        # Dump the certificate in PKCS12 format for Windows devices
        with open(os.path.join(path, basename + "-ca-cert.p12"), "wb") as f:
            p12 = OpenSSL.crypto.PKCS12()
            p12.set_certificate(ca)
            f.write(p12.export())

        # Dump the certificate and key in a PKCS12 format for Windows devices
        with CertStore.umask_secret(), open(os.path.join(path, basename + "-ca.p12"), "wb") as f:
            p12 = OpenSSL.crypto.PKCS12()
            p12.set_certificate(ca)
            p12.set_privatekey(key)
            f.write(p12.export())

        with open(os.path.join(path, basename + "-dhparam.pem"), "wb") as f:
            f.write(DEFAULT_DHPARAM)

        return key, ca

    def add_cert_file(self, spec: str, path: str) -> None:
        with open(path, "rb") as f:
            raw = f.read()
        cert = Cert(
            OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM,
                raw))
        try:
            privatekey = OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM,
                raw)
        except Exception:
            privatekey = self.default_privatekey
        self.add_cert(
            CertStoreEntry(cert, privatekey, path),
            spec.encode("idna")
        )

    def add_cert(self, entry: CertStoreEntry, *names: bytes):
        """
            Adds a cert to the certstore. We register the CN in the cert plus
            any SANs, and also the list of names provided as an argument.
        """
        if entry.cert.cn:
            self.certs[entry.cert.cn] = entry
        for i in entry.cert.altnames:
            self.certs[i] = entry
        for i in names:
            self.certs[i] = entry

    @staticmethod
    def asterisk_forms(dn: bytes) -> typing.List[bytes]:
        """
        Return all asterisk forms for a domain. For example, for www.example.com this will return
        [b"www.example.com", b"*.example.com", b"*.com"]. The single wildcard "*" is omitted.
        """
        parts = dn.split(b".")
        ret = [dn]
        for i in range(1, len(parts)):
            ret.append(b"*." + b".".join(parts[i:]))
        return ret

    def get_cert(self, commonname: typing.Optional[bytes], sans: typing.List[bytes], organization: typing.Optional[bytes] = None):
        """
            Returns an (cert, privkey, cert_chain) tuple.
            commonname: Common name for the generated certificate. Must be a
            valid, plain-ASCII, IDNA-encoded domain name.
            sans: A list of Subject Alternate Names.
            organization: Organization name for the generated certificate.
        """

        potential_keys: typing.List[TCertId] = []
        if commonname:
            potential_keys.extend(self.asterisk_forms(commonname))
        for s in sans:
            potential_keys.extend(self.asterisk_forms(s))
        potential_keys.append(b"*")
        potential_keys.append((commonname, tuple(sans)))

        name = next(
            filter(lambda key: key in self.certs, potential_keys),
            None
        )
        if name:
            entry = self.certs[name]
        else:
            entry = CertStoreEntry(
                cert=dummy_cert(
                    self.default_privatekey,
                    self.default_ca,
                    commonname,
                    sans,
                    organization),
                privatekey=self.default_privatekey,
                chain_file=self.default_chain_file)
            self.certs[(commonname, tuple(sans))] = entry
            self.expire(entry)

        return entry.cert, entry.privatekey, entry.chain_file


class _GeneralName(univ.Choice):
    # We only care about dNSName and iPAddress
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('dNSName', char.IA5String().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )),
        namedtype.NamedType('iPAddress', univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
        )),
    )


class _GeneralNames(univ.SequenceOf):
    componentType = _GeneralName()
    sizeSpec = univ.SequenceOf.sizeSpec + \
        constraint.ValueSizeConstraint(1, 1024)


class Cert(Serializable):

    def __init__(self, cert):
        """
            Returns a (common name, [subject alternative names]) tuple.
        """
        self.x509 = cert

    def __eq__(self, other):
        return self.digest("sha256") == other.digest("sha256")

    def get_state(self):
        return self.to_pem()

    def set_state(self, state):
        self.x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, state)

    @classmethod
    def from_state(cls, state):
        return cls.from_pem(state)

    @classmethod
    def from_pem(cls, txt):
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, txt)
        return cls(x509)

    @classmethod
    def from_der(cls, der):
        pem = ssl.DER_cert_to_PEM_cert(der)
        return cls.from_pem(pem)

    def to_pem(self):
        return OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            self.x509)

    def digest(self, name):
        return self.x509.digest(name)

    @property
    def issuer(self):
        return self.x509.get_issuer().get_components()

    @property
    def notbefore(self):
        t = self.x509.get_notBefore()
        return datetime.datetime.strptime(t.decode("ascii"), "%Y%m%d%H%M%SZ")

    @property
    def notafter(self):
        t = self.x509.get_notAfter()
        return datetime.datetime.strptime(t.decode("ascii"), "%Y%m%d%H%M%SZ")

    @property
    def has_expired(self):
        return self.x509.has_expired()

    @property
    def subject(self):
        return self.x509.get_subject().get_components()

    @property
    def serial(self):
        return self.x509.get_serial_number()

    @property
    def keyinfo(self):
        pk = self.x509.get_pubkey()
        types = {
            OpenSSL.crypto.TYPE_RSA: "RSA",
            OpenSSL.crypto.TYPE_DSA: "DSA",
        }
        return (
            types.get(pk.type(), "UNKNOWN"),
            pk.bits()
        )

    @property
    def cn(self):
        c = None
        for i in self.subject:
            if i[0] == b"CN":
                c = i[1]
        return c

    @property
    def organization(self):
        c = None
        for i in self.subject:
            if i[0] == b"O":
                c = i[1]
        return c

    @property
    def altnames(self):
        """
        Returns:
            All DNS altnames.
        """
        # tcp.TCPClient.convert_to_tls assumes that this property only contains DNS altnames for hostname verification.
        altnames = []
        for i in range(self.x509.get_extension_count()):
            ext = self.x509.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                try:
                    dec = decode(ext.get_data(), asn1Spec=_GeneralNames())
                except PyAsn1Error:
                    continue
                for i in dec[0]:
                    if i[0].hasValue():
                        e = i[0].asOctets()
                        altnames.append(e)

        return altnames

class KeyHelper:

    @staticmethod
    def to_bytes(key, 
        password=None,
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8):
        if password is not None:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm=serialization.NoEncryption()
        return key.private_bytes(encoding=encoding, format=format, encryption_algorithm=encryption_algorithm)

    @staticmethod
    def from_bytes(content, password=None):
        return serialization.load_pem_private_key(content, password=password, backend=default_backend())

        
