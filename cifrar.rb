require 'ecdsa'
require 'securerandom'
require 'base64'
require 'ERB'

# Crear dos signaturas, una para usuario admin, otra para usuario admon
# recover_key("admin", sig1, "admon", sig2)
# comprobar que la private key que se genera es la 5315....

$group = ECDSA::Group::Secp256k1
$private_key = 40812466068149959758717554226807910858702659189488769039833873021754530834336

def sign(str)
    digest = Digest::SHA256.digest(str) 
    temp_key = str.size 
    signature = ECDSA.sign($group, $private_key, digest, temp_key)
end


user = "admin"
sig = sign(user)
signature = Base64.strict_encode64(user+"--"+ECDSA::Format::SignatureDerString.encode(sig)) 
print ERB::Util.url_encode(signature)  + "\n"

user = "admon"
sig = sign(user)
signature = Base64.strict_encode64(user+"--"+ECDSA::Format::SignatureDerString.encode(sig)) 
print ERB::Util.url_encode(signature)  + "\n"



# Base64.decode64("MEUCIQDkk9vxwQ2A81geSQSTCxQEzGwTkA7gdYR0+pSr6MTNEwIgZG1cpKLmK1y9aCIAhzZJWdzPC+okbBwzvPj40p+ZUHg=")
# ECDSA::Format::SignatureDerString.decode(sig2)
