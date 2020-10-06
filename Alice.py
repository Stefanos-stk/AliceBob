import sys
import socket
import os
from os import _exit as quit
from datetime import datetime
import base64


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac

from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def load_keys():
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
    )

    with open("private_key_4sign.raw",'rb') as key_file:
        private_key_4sign = ed25519.Ed25519PrivateKey.from_private_bytes(key_file.read())

    return public_key,private_key_4sign


def generate_key_iv():
    key = os.urandom(32)
    iv = os.urandom(16)
    return key,iv


def rsa_encrypt(public_key,message):
    key_encryped = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    return key_encryped


def aes_encrypt(key, iv, msg):

    #Create cipher and encrypter in CBC mode with key and iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Encrypt the message
    msg = padd(msg).encode()
    msg_ct = encryptor.update(msg) + encryptor.finalize()
    return msg_ct


def padd(s):
    block_size = 16
    remainder = len(s) % block_size
    padding_needed = block_size - remainder
    if padding_needed == 0:
        padding_needed = 16
    #return s + padding_needed * ' '
    return s + padding_needed * chr(padding_needed)


def hash_mac(key,msg):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    
    return h.finalize()


def main():
    public_key,private_4sign  = load_keys()
    key,iv =  generate_key_iv()
    # parse arguments
    if len(sys.argv) != 4:
        print("usage: python3 %s <host> <port>" % sys.argv[0])
        quit(1)
    host = sys.argv[1]
    port = sys.argv[2]
    #type of encryption
    type_encryption = sys.argv[3].upper() 

    # open a socket
    clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect to server

    clientfd.connect((host, int(port)))
    #Handshake ------------- Handshake

    b = 'B'
    tA = datetime.now().strftime("%d-%b-%Y (%H:%M:%S.%f)")
    encA_kAB_Kb_key = rsa_encrypt(public_key,("A"+str(key)).encode())
    print(str(encA_kAB_Kb_key))
    
    handshake_signature = private_4sign.sign((b+tA+str(encA_kAB_Kb_key)).encode())

    # handshake
    clientfd.send((b + tA + str(encA_kAB_Kb_key)+ str(handshake_signature)).encode())
    #clientfd.send(handshake_signature)

    # clientfd.send(encA_kAB_Kb_key)
    # clientfd.send(encA_kAB_Kb_iv)
    # clientfd.send(handshake_signature)
    #clientfd.send(b+b','+ tA+b','+encA_kAB_Kb_key+b','+encA_kAB_Kb_iv +b','+handshake_signature)



    #No cryptography: messages are not protected.
    if type_encryption == "NONE":
        while(True):
            msg = input("Enter message for server: ").encode()
            clientfd.send(msg)

    #Symmetric encryption only: the confidentiality of messages is protected.
    if type_encryption == "SYMMETRIC":

        # Generate key and iv, and encrypting it with the public key
        key_enc  =  rsa_encrypt(public_key,key)
        iv_enc  = rsa_encrypt(public_key,iv)

        # Send iv and key
        clientfd.send(key_enc)
        clientfd.send(iv_enc)

        while(True):
   
            #getting user input
            msg = input("Enter message for server: ")
            msg_ct = aes_encrypt(key, iv, msg)
            clientfd.send(msg_ct)

    #MACs only: the integrity of messages is protected.
    if type_encryption == "MAC":

        # Encrypting and sending the aes key
        key_enc  =  rsa_encrypt(public_key,key)
        clientfd.send(key_enc)

        while(True):

            # Send the message and its hmac signiture
            msg = input("Enter message for server: ").encode()
            message_signature = hash_mac(key,msg)
            clientfd.send(msg)
            clientfd.send(message_signature)

    if type_encryption == "SYMMETRIC_MAC":

        # Encrypt and send key, iv with the public key
        key_enc  =  rsa_encrypt(public_key,key)
        iv_enc  = rsa_encrypt(public_key,iv)
        clientfd.send(key_enc)
        clientfd.send(iv_enc)

        while(True):

            # Getting user input and encrypt it
            msg = input("Enter message for server: ")
            msg_ct = aes_encrypt(key, iv, msg)

            # Get a signiture for cipher message
            message_signature = hash_mac(key,msg_ct)

            # Send cipher text and signature
            clientfd.send(msg_ct)
            clientfd.send(message_signature)

#        # You don't need to receive for this assignment, but if you wanted to
#        # you would use something like this
#        msg = clientfd.recv(1024).decode()
#        print("Received from server: %s" % msg)

    # close connection
    clientfd.close()

if __name__ == "__main__":
    main()