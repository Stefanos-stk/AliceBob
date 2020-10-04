import sys
import socket
import os
from os import _exit as quit
from datetime import datetime


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

def generate_encrypted_rsa(public_key,message):
    key_encryped = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    return key_encryped

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

    b = 'B'.encode()
    tA = datetime.now().strftime("%d-%b-%Y (%H:%M:%S.%f)").encode()
    encA_kAB_Kb_key = generate_encrypted_rsa(public_key,("A"+str(key)).encode())
    encA_kAB_Kb_iv = generate_encrypted_rsa(public_key,("A"+str(iv)).encode())

    handshake_signature = private_4sign.sign(b+tA+encA_kAB_Kb_key+encA_kAB_Kb_iv)
    clientfd.send(b)
    clientfd.send(tA)
    clientfd.send(encA_kAB_Kb_key)
    clientfd.send(encA_kAB_Kb_iv)
    clientfd.send(handshake_signature)
    #clientfd.send(b+b','+ tA+b','+encA_kAB_Kb_key+b','+encA_kAB_Kb_iv +b','+handshake_signature)



    #No cryptography: messages are not protected.
    if type_encryption == "NONE":
        while(True):
            msg = input("Enter message for server: ").encode()
            clientfd.send(msg)

    #Symmetric encryption only: the confidentiality of messages is protected.
    if type_encryption == "SYMMETRIC":
        #Generate key and initializing vector, and encrypting it with the public key
        key_enc  =  generate_encrypted_rsa(public_key,key)
        iv_enc  = generate_encrypted_rsa(public_key,iv)
        #sending iv and key
        clientfd.send(key_enc)
        clientfd.send(iv_enc)

        #creating the cipher using the random generated key and CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        #initialzing the cipher encryptor
        encryptor = cipher.encryptor()
        #padding the string (not using)
        padder = pad.PKCS7(16).padder()


        while(True):
            #creating the cipher using the random generated key and CBC mode
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            #initialzing the cipher encryptor
            encryptor = cipher.encryptor()
            #getting user input
            msg = input("Enter message for server: ")
            #padding

            #pcsk7 padder
            #msg= padder.update(msg.encode())
            #msg += padder.finalize()
            msg = padd(msg).encode()
            #msg = msg.encode()
            msg_ct = encryptor.update(msg) + encryptor.finalize()
            clientfd.send(msg_ct)

    #MACs only: the integrity of messages is protected.
    if type_encryption == "MAC":
        #Encrypting and sending the aes key
        key_enc  =  generate_encrypted_rsa(public_key,key)
        clientfd.send(key_enc)
        while(True):
            msg = input("Enter message for server: ").encode()
            message_signature = hash_mac(key,msg)
            clientfd.send(msg)
            clientfd.send(message_signature)

    if type_encryption == "SYMMETRIC_MAC":
        #Generate key and initializing vector, and encrypting it with the public key
        key_enc  =  generate_encrypted_rsa(public_key,key)
        iv_enc  = generate_encrypted_rsa(public_key,iv)
        #sending iv and key
        clientfd.send(key_enc)
        clientfd.send(iv_enc)
        #creating the cipher using the random generated key and CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        #initialzing the cipher encryptor
        encryptor = cipher.encryptor()
        while(True):
            #creating the cipher using the random generated key and CBC mode
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            #initialzing the cipher encryptor
            encryptor = cipher.encryptor()
            #getting user input
            msg = input("Enter message for server: ")
            #padding
            msg = padd(msg).encode()
            msg_ct = encryptor.update(msg) + encryptor.finalize()

            #GETTING SIGNATURE FOR CIPGER MESSAGE
            message_signature = hash_mac(key,msg_ct)
            #SENDING THE ENCRYPTED ALONG WITH SIGNATURE OF THE MESSAGE
            clientfd.send(msg_ct)
            clientfd.send(message_signature)



        #msg = padd(msg).encode()
        #client.send(aes_encrypt_b64(msg))
        
        #padded_data = padder.update(msg) + padder.finalize()
        #msg_ct = encryptor.update(msg) + encryptor.finalize()
        #clientfd.send(msg_ct)

#        # You don't need to receive for this assignment, but if you wanted to
#        # you would use something like this
#        msg = clientfd.recv(1024).decode()
#        print("Received from server: %s" % msg)

    # close connection
    clientfd.close()

if __name__ == "__main__":
    main()