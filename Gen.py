from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519


# --- Alice --- #

private_key_alice = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key_alice = private_key_alice.public_key()

pem_private_alice = private_key_alice.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

pem_public_alice = public_key_alice.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
 )


#This is for messags signatures
with open('private_key_alice.pem', 'wb') as f:
    f.write(pem_private_alice)
f.close()
with open('public_key_alice.pem', 'wb') as x:
    x.write(pem_public_alice)
x.close()

# -- BOB --- #


private_key_bob = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key_bob = private_key_bob.public_key()

pem_private_bob = private_key_bob.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

pem_public_bob = public_key_bob.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
 )


#This is for messags signatures
with open('private_key_bob.pem', 'wb') as f:
    f.write(pem_private_bob)
f.close()
with open('public_key_bob.pem', 'wb') as x:
    x.write(pem_public_bob)
x.close()