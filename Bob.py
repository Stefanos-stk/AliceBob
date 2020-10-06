import sys
import socket
from os import _exit as quit
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519

from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def load_keys():
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
    )
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
    )

    with open("public_key_4sign.raw",'rb') as key_file:
        public_key_4sign = ed25519.Ed25519PublicKey.from_public_bytes(key_file.read())

    return public_key,private_key,public_key_4sign


def check_signature(key,msg,signature):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    h.verify(signature)


def rsa_decrypt(private_key, enc_msg):
    decrypted_msg = private_key.decrypt(
    enc_msg,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )

    return decrypted_msg


def aes_decrypt(aes_key, aes_iv, enc_msg):

    # Creating the cipher using aes key and aes iv
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv))
    
    # Decrypt and unpad the message
    decryptor = cipher.decryptor()
    decrypted_msg = decryptor.update(enc_msg) + decryptor.finalize()
    decrypted_msg = unpadd(decrypted_msg)

    return decrypted_msg


def unpadd(msg):
    msg  = msg.decode()
    tail = ord(msg[-1])
    msg_unpadd = msg[:(-1 * tail)]
    return msg_unpadd


def main():
    # parse arguments
    public_key,private_key,public_key_4sign  = load_keys()


    if len(sys.argv) != 3:
        print("usage: python3 %s <port>" % sys.argv[0])
        quit(1)
    port = sys.argv[1]
    #type of encryption
    type_encryption = sys.argv[2].upper() 
    
    # open a socket
    listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind socket to ip and port
    listenfd.bind(('', int(port)))
    # listen to socket

    listenfd.listen(1)
  
    # accept connection
    (connfd, addr) = listenfd.accept()

    #handshake
    handshake = connfd.recv(1024).decode()

    # No cryptography: messages are not protected.
    if type_encryption == "NONE":
        while(True):
            msg = connfd.recv(1024).decode()
            print("Received from client: %s" % msg)

    # Symmetric encryption only: the confidentiality of messages is protected.
    if type_encryption == "SYMMETRIC":

        # Getting the key and iv 
        key_enc = connfd.recv(1024)
        iv_enc = connfd.recv(1024)

        # Decrypting aes key and iv with rsa private key
        aes_key = rsa_decrypt(private_key, key_enc)
        aes_iv = rsa_decrypt(private_key, iv_enc)

        while(True):
            
            # Receiving the cipher message
            msg_ct = connfd.recv(1024)

            # Decrypt the cipher message
            msg = aes_decrypt(aes_key, aes_iv, msg_ct)

            print(len(msg))
            print("Received from client: %s" %  msg)
    
    # Using only HMAC
    if type_encryption == "MAC":
        
        # Recieving and decrypting the aes key in order to check signature
        key_enc = connfd.recv(1024)
        aes_key = rsa_decrypt(private_key, key_enc)
 
        while(True):

            # Receive message and signature
            msg_ct = connfd.recv(1024)
            signature = connfd.recv(1024)

            # Check signature (this returns an exception if signature is comprimised)
            check_signature(aes_key,msg_ct,signature)
            print("Received: ", msg_ct.decode(), "Signature: ",signature)

    # Symmetric encryption then HMAC
    if type_encryption == "SYMMETRIC_MAC":

        # Revieving the key and iv 
        key_enc = connfd.recv(1024)
        iv_enc = connfd.recv(1024)

        # Decrypting aes key and iv using the private key
        aes_key = rsa_decrypt(private_key, key_enc)
        aes_iv = rsa_decrypt(private_key, iv_enc)

        while(True):

            # Receiving the cipher message
            msg_ct = connfd.recv(1024)
            signature = connfd.recv(1024)

            # Decrypt the  message using aes
            aes_decrypt(aes_key, aes_iv, msg_ct)

            # Checking the signature: results in exception if compromised
            check_signature(aes_key,msg_ct,signature)
            print("Received from client: %s" % msg.decode().strip(), "Signature from client: ",signature)







#        # You don't need to send a response for this assignment
#        # but if you wanted to you'd do something like this
#        msg = input("Enter message for client: ")
#        connfd.send(msg.encode())

    # close connection
    connfd.close()
    listenfd.close()

if __name__ == "__main__":
    main()