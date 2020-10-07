import sys
import socket
import os
from os import _exit as quit
from datetime import datetime
import base64
import time


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac

from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def load_keys():

    with open("public_key_bob.pem", "rb") as key_file:
        public_key_bob = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
    )

    with open("private_key_alice.pem", "rb") as key_file:
        private_key_alice = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
    )

    return public_key_bob,private_key_alice


def generate_key_iv():
    key = os.urandom(32)
    iv = os.urandom(16)
    return key,iv

def generate_iv():
    iv = os.urandom(16)
    return iv


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
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
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
    return s + padding_needed * chr(padding_needed)


def hash_mac(key,msg):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(msg)
    
    return h.finalize()

def private_key_sign(key, msg):

    signature = key.sign(
        msg,
        padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def main():
    public_key_bob,private_key_alice  = load_keys()
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
    

    ### --- Handshake --- ###

    key_b64 = str(base64.b64encode(key))

    # Generate hmac key
    hmac_key, iv = generate_key_iv()
    hmac_key_b64 = str(base64.b64encode(hmac_key))

    
    message_count  = 0 

    b = 'B'
    tA = datetime.now().strftime("%d-%b-%Y (%H:%M:%S.%f)")
    
    
    encA_kAB_Kb_key = rsa_encrypt(public_key_bob,("A" + key_b64).encode())
    enc_hmac_key = rsa_encrypt(public_key_bob, (hmac_key_b64).encode())

    
    enc_key_b64 = base64.b64encode(encA_kAB_Kb_key)
    enc_hmac_key_b64 = base64.b64encode(enc_hmac_key)

    # Create signiture
    signiture_contents = (b+tA+str(enc_key_b64)+ str(enc_hmac_key_b64)).encode()
    handshake_signature = private_key_sign(private_key_alice, signiture_contents)
    handshake_signature_b64 = base64.b64encode(handshake_signature)
    
    
  
    # handshake
    handshake = (b + '  ' + tA + '  '  + str(enc_key_b64) + '  ' +
        str(enc_hmac_key_b64) + '  ' + str(handshake_signature_b64)).encode()
    clientfd.send(handshake)

    #No cryptography: messages are not protected.
    if type_encryption == "NONE":
        while(True):
            msg = input("Enter message for server: ")
            clientfd.send((str(message_count) + '  ' + msg ).encode())
            message_count += 1

    #Symmetric encryption only: the confidentiality of messages is protected.
    if type_encryption == "SYMMETRIC":

        while(True):

            #getting user input
            msg = input("Enter message for server: ")

            # Generate IV and encrpyt the message
            iv = generate_iv()
            iv_b64 = base64.b64encode(iv)
            msg_ct_b64 = base64.b64encode(aes_encrypt(key, iv, msg))
            print(len(msg_ct_b64))
            clientfd.send((str(iv_b64) + "  " + str(msg_ct_b64)+ "  " + str(message_count)).encode())
            message_count += 1
    #MACs only: the integrity of messages is protected.
    if type_encryption == "MAC":

        while(True):

            # Get message
            msg = input("Enter message for server: ") 

            message_signature = hash_mac(hmac_key,(msg + str(message_count)).encode())
            message_signature_b64 = base64.b64encode(message_signature)

            clientfd.send((msg + "  " + str(message_signature_b64)+ "  " +  str(message_count)).encode())
            message_count += 1

    if type_encryption == "SYMMETRIC_MAC":


        while(True):

            #getting user input
            msg = input("Enter message for server: ")

            # Generate IV and encrypt the message
            iv = generate_iv()
            iv_b64 = base64.b64encode(iv)
            msg_ct = aes_encrypt(key, iv, msg)
            msg_ct_b64 = base64.b64encode(msg_ct)
        
            message_signature = hash_mac(hmac_key, (str(msg_ct_b64) + str(message_count)).encode())
            message_signature_b64 = base64.b64encode(message_signature)

            clientfd.send((str(iv_b64) + "  " + str(msg_ct_b64) + "  " + str(message_signature_b64) + "  " + str(message_count)).encode())

            message_count += 1


#        # You don't need to receive for this assignment, but if you wanted to
#        # you would use something like this
#        msg = clientfd.recv(1024).decode()
#        print("Received from server: %s" % msg)

    # close connection
    clientfd.close()

if __name__ == "__main__":
    main()