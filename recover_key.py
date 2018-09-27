import hashlib
import binascii
import sys
import re
import base64
import urllib


from ecdsa import SigningKey
from ecdsa import VerifyingKey
from ecdsa.numbertheory import inverse_mod

from ecdsa.curves import SECP256k1
from ecdsa.curves import NIST192p

from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import namedtype, univ



cmd1 = "adman"
sig1 = "YWRtYW4tLTBEAiAvi95NGgcgk1W0pyUKXFEo6IuEvdxhmrfLqNVpskDv5AIgFdHvz7jSXZSwvXZoS8E4Drx3Cs5k%2B7Rqm5FetXZIVZw%3D"
#sig1 = "MEUCIQDkk9vxwQ2A81geSQSTCxQEzGwTkA7gdYR0+pSr6MTNEwIgPw27w8ujpudRwe2JbYxthTs1Fh9PrIcPNO3XPgEbAEk="
#sig1 = "MEUCIQDkk9vxwQ2A81geSQSTCxQEzGwTkA7gdYR0+pSr6MTNEwIgLWHjSXOu1YJD7hgX2u/wJQfB02UT8RZyiqdl7MoRyic="
sig1 = urllib.unquote(sig1).decode('utf8') 
# sig1 = base64.b64decode(sig1).encode('hex')

cmd2 = "admon"
sig2 = "YWRtb24tLTBEAiAvi95NGgcgk1W0pyUKXFEo6IuEvdxhmrfLqNVpskDv5AIgCFIA%2FuTZb96ZEtROxKTiUy7v2i0a2DUzelG5ogeztuE%3D"
#sig2 = "MEUCIQDkk9vxwQ2A81geSQSTCxQEzGwTkA7gdYR0+pSr6MTNEwIgZG1cpKLmK1y9aCIAhzZJWdzPC+okbBwzvPj40p+ZUHg="
# sig2 = base64.b64decode(sig2).encode('hex')
sig2 = urllib.unquote(sig2).decode('utf8') 

class EcSignature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("r", univ.Integer()),
        namedtype.NamedType("s", univ.Integer()),
    )

def is_valid_der(data):
    try:
        structure, _ = der_decode(data)
        return data == der_encode(structure)
    except:
        return False

class ParseError(Exception):
    pass

class EcSignature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("r", univ.Integer()),
        namedtype.NamedType("s", univ.Integer()),
    )

def parse_ecdsa256_signature(signature):
    s = signature
    if not is_valid_der(signature):
        raise ParseError("Not a valid DER")
    try:
        signature, _ = der_decode(signature, asn1Spec=EcSignature())
    except:
        raise ParseError("Not a valid DER encoded ECDSA signature")
    try:
        r = int(signature["r"]).to_bytes(32, byteorder="big")
        s = int(signature["s"]).to_bytes(32, byteorder="big")
        signature = r + s
    except:
        raise ParseError("Not a valid DER encoded 256 bit ECDSA signature")
    return signature



curve_order = SECP256k1.order


def sha256(content):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(content)
    hash = sha256_hash.digest()
    return hash

def string_to_number(tstr):
    return int(binascii.hexlify(tstr), 16)

def recover_key(c1,sig1,c2,sig2):
    #using the same variable names as in: 
    #http://en.wikipedia.org/wiki/Elliptic_Curve_DSA
    n = curve_order

    # s1 = string_to_number(sig1[0:47])
    # s2 = string_to_number(sig2[0:47])

    sig, _ = der_decode(sig1, asn1Spec=EcSignature())
    s1 = int(sig["s"])
    r = int(sig["r"])


    sig, _ = der_decode(sig2, asn1Spec=EcSignature())
    s2 = int(sig["s"])
    # r = string_to_number(sig1[48:95])
    print s2
    print r

    z1 = string_to_number(sha256(c1))
    z2 = string_to_number(sha256(c2))

    sdiff_inv = inverse_mod(((s1-s2)%n),n)
    k = ( ((z1-z2)%n) * sdiff_inv) % n
    r_inv = inverse_mod(r,n)
    da = (((((s1*k) %n) -z1) %n) * r_inv) % n

    recovered_private_key_ec = SigningKey.from_secret_exponent(da, curve=SECP256k1)
    print recovered_private_key_ec.privkey.secret_multiplier

    return recovered_private_key_ec.to_pem()


_ , sig1 =  base64.b64decode(sig1).split("--")
_ , sig2 =  base64.b64decode(sig2).split("--") 

key = recover_key(cmd1,sig1,cmd2,sig2)
print key

'''

$ /usr/local/Cellar/openssl/1.0.2p/bin/openssl ec -inform d <48101258.2
read EC key
writing EC key
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEICw2DFusFFf2uoK5xFa/q2tatP9N+xP5/H4Qp0KrJEMLoAcGBSuBBAAK
oUQDQgAEIOptjOe8u0gzabKRHHXlYCo0KL5Elul/FK1S/UpqoONgg5xu2zIqIlV8
cB7Q+h4Gz1dPvhe9aoVRacVllnLPqQ==
-----END EC PRIVATE KEY-----

'''


private_key_ec = SigningKey.from_pem(key)
user="admin"
hash = hashlib.sha256(user).hexdigest()
cert_key = private_key_ec.sign_digest(hash)
print cert_key



