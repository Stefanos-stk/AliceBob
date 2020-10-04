from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519



private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

pem_public = public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
 )


private_key_4sign = Ed25519PrivateKey.generate()
public_key_4sign = private_key_4sign.public_key()

private_key_4sign = private_key_4sign.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
)


public_key_4sign = public_key_4sign.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


#this is 4 handshake sign
with open('private_key_4sign.raw', 'wb') as f:
    f.write(private_key_4sign)
f.close()

with open('public_key_4sign.raw', 'wb') as f:
    f.write(public_key_4sign)
f.close()

#This is for messags signatures
with open('private_key.pem', 'wb') as f:
    f.write(pem_private)
f.close()
with open('public_key.pem', 'wb') as x:
    x.write(pem_public)
x.close()