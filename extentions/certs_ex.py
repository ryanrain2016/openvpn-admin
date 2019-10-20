from config import Config
import os
from certs import create_ca, CertStore
import OpenSSL
from utils import to_bytes

def init_cert(app):
    basepath = os.path.join(Config.BASEDIR, 'conf.d')
    ca_file = os.path.join(basepath, 'ca.crt')
    ca_chain_file = os.path.join(basepath, 'ca-chain.crt')
    if not os.path.exists(ca_file):
        key, ca = create_ca(organization=to_bytes(Config.ORGANIZATION), cn=to_bytes(Config.CA_CN), exp=3600*24*365*10)
        with CertStore.umask_secret():
            with open(os.path.join(basepath, 'ca.key'), "wb") as f:
                key_byte = OpenSSL.crypto.dump_privatekey(
                        OpenSSL.crypto.FILETYPE_PEM,
                        key)
                f.write(key_byte)
            with open(ca_file, "wb") as f:
                ca_byte = OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM,
                        ca)
                f.write(ca_byte)
            with open(ca_chain_file, 'wb') as f:
                f.write(key_byte)
                f.write(ca_byte)
        dh_file = os.path.join(basepath, 'dh.pem')
        dh = CertStore.load_dhparam(dh_file)
        cs = CertStore(key, ca, ca_chain_file, dh)
        cn = to_bytes(Config.SERVER_CN)
        cert, key, _ = cs.get_cert(cn, [cn], to_bytes(Config.ORGANIZATION))
        with open(os.path.join(basepath, 'server.crt'), "wb") as f:
            cert_bytes = cert.to_pem()
            f.write(cert_bytes)
        with open(os.path.join(basepath, 'server.key'), "wb") as f:
            key_bytes = OpenSSL.crypto.dump_privatekey(
                    OpenSSL.crypto.FILETYPE_PEM,
                    key)
            f.write(key_bytes)
    ta_key = os.path.join(basepath, 'ta.key')
    if not os.path.exists(ta_key):
        os.system('openvpn --genkey --secret conf.d/ta.key')
