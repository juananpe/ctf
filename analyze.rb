require 'ecdsa'
require 'securerandom'
require 'base64'

$group = ECDSA::Group::Secp256k1
$private_key = 103614385522011914429536969673097575850042158646323051424584682794938253568266
# $private_key = 1 + SecureRandom.random_number($group.order - 1)
print $private_key
print "\n"

$public_key = $group.generator.multiply_by_scalar($private_key)
print $public_key

print "\n"

def verify?(str,signature)
	digest = Digest::SHA256.digest(str)
	ECDSA.valid_signature?($public_key, digest, signature)
end

def sign(str)
	digest = Digest::SHA256.digest(str) 
	temp_key = str.size 
	signature = ECDSA.sign($group, $private_key, digest, temp_key)
end

# cookie = 'YWRtb24tLTBEAiAvi95NGgcgk1W0pyUKXFEo6IuEvdxhmrfLqNVpskDv5AIgCFIA%2FuTZb96ZEtROxKTiUy7v2i0a2DUzelG5ogeztuE%3D'

# user, sig = Base64.decode64(cookie).split("--")
# if verify?(user,ECDSA::Format::SignatureDerString.decode(sig)) 
#	print "Verified\n"
# end

user = 'admin'
sig = sign(user)
print "Cookie:" + Base64.strict_encode64(user+"--"+ECDSA::Format::SignatureDerString.encode(sig))  + "\n"




