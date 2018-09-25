import hashlib
import binascii
import sys
import re
import base64
from ecdsa import SigningKey
from ecdsa import VerifyingKey
from ecdsa.numbertheory import inverse_mod

from ecdsa.curves import SECP256k1
from ecdsa.curves import NIST192p

cmd1 = "pepe"
sig1 = "MEUCIQDkk9vxwQ2A81geSQSTCxQEzGwTkA7gdYR0+pSr6MTNEwIgPw27w8ujpudRwe2JbYxthTs1Fh9PrIcPNO3XPgEbAEk="

cmd2 = "papa"
sig2 = "MEUCIQDkk9vxwQ2A81geSQSTCxQEzGwTkA7gdYR0+pSr6MTNEwIgdhk1Hvra/MHLO/dyGdLGuhBCTqRgJ4zQZz9qI9aihpo="

curve_order = SECP256k1.order


def sha1(content):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(content)
    hash = sha1_hash.digest()
    return hash

def string_to_number(tstr):
    return int(binascii.hexlify(tstr), 16)

def recover_key(c1,sig1,c2,sig2):
    #using the same variable names as in: 
    #http://en.wikipedia.org/wiki/Elliptic_Curve_DSA
    n = curve_order
    s1 = string_to_number(sig1[-24:])
    s2 = string_to_number(sig2[-24:])
    r = string_to_number(sig1[-48:-24])

    z1 = string_to_number(sha1(c1))
    z2 = string_to_number(sha1(c2))

    sdiff_inv = inverse_mod(((s1-s2)%n),n)
    k = ( ((z1-z2)%n) * sdiff_inv) % n
    r_inv = inverse_mod(r,n)
    da = (((((s1*k) %n) -z1) %n) * r_inv) % n

    recovered_private_key_ec = SigningKey.from_secret_exponent(da, curve=SECP256k1)
    return recovered_private_key_ec.to_pem()
    


key = recover_key(cmd1,base64.b64decode(sig1),cmd2,base64.b64decode(sig2))
print key

'''

14534192167135690669876199069902060499140821204002782145884363619574903997379


-----BEGIN EC PRIVATE KEY-----
MHQCAQEEICAiD63Q7anxSf5r7xrqZUi8iZeCTYWfVi6se91neAPDoAcGBSuBBAAK
oUQDQgAE1PND+pS6Q4UahAyGONcG9o8DUl8GlQyr6m7Tcpb/hT8abc7IgC7ZjoXb
bcBOZuMfWyjJdfa1tG90n0Vl8J2r3A==
-----END EC PRIVATE KEY-----
'''
