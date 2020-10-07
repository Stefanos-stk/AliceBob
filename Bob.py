import sys
import socket
from os import _exit as quit
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac

import base64
from datetime import datetime
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519

from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def load_keys():
    with open("private_key_bob.pem", "rb") as key_file:
        private_key_bob = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
    )
    with open("public_key_bob.pem", "rb") as key_file:
        public_key_bob = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
    )

    with open("public_key_alice.pem",'rb') as key_file:
        public_key_alice = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
    )

    return public_key_bob,private_key_bob,public_key_alice


def check_signature(key,msg,signature):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
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
    print(len(enc_msg))
    # Creating the cipher using aes key and aes iv
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    
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
    

def public_key_check_sign(public_key, signature, msg):

    public_key.verify(
        signature,
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def main():
    # Parse arguments
    public_key_bob,private_key_bob,public_key_alice  = load_keys()


    if len(sys.argv) != 3:
        print("usage: python3 %s <port>" % sys.argv[0])
        quit(1)
    port = sys.argv[1]

    # Type of encryption
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
    print("Accepting connection with address :", addr)


    #handshake
    handshake = connfd.recv(2048).decode()
    split_hand = handshake.split('  ',4)
    b = split_hand[0]
    tA = split_hand[1] 
    
    #Checking time stamps tA & tB
    datetime_object = datetime.strptime(tA, "%d-%b-%Y (%H:%M:%S.%f)")
    tB = datetime.now().strftime("%d-%b-%Y (%H:%M:%S.%f)")
    datetime_object_2 = datetime.strptime(tB, "%d-%b-%Y (%H:%M:%S.%f)")
    difference = datetime_object_2 - datetime_object

    print("Checking time stamps...")
    if timedelta(minutes= 0) <= difference <= timedelta(minutes =2):
        print("Time stamp interval OK")
    else:
        print("Time stamp interval exceeded 2 minutes. Cancelling connection.")
        quit()


    # Get AES key
    encA_kAB_Kb_key_b64 = split_hand[2].encode()
    encA_kAB_Kb_key = base64.b64decode(encA_kAB_Kb_key_b64[2:-1])
    aes_key = base64.b64decode(rsa_decrypt(private_key_bob,encA_kAB_Kb_key)[3:-1])

    # Get HMAC key
    enc_hmac_key_b64 = split_hand[3].encode()
    enc_hmac_key = base64.b64decode(enc_hmac_key_b64[2:-1])
    hmac_key = base64.b64decode(rsa_decrypt(private_key_bob,enc_hmac_key)[2:-1])

    # Check the signature
    handshake_signature = split_hand[4].encode()
    handshake_signature = base64.b64decode(handshake_signature[2:-1])
    signature_contents = (b+tA+str(encA_kAB_Kb_key_b64[2:-1])+ str(enc_hmac_key_b64[2:-1])).encode()
    public_key_check_sign(public_key_alice, handshake_signature, signature_contents)

    #counter received
    messages_received = 0

    # No cryptography: messages are not protected.
    if type_encryption == "NONE":
        while(True):
            msg = connfd.recv(1024).decode()
            
            split_msg = msg.split('  ',1)
            count = split_msg[0]
            msg = split_msg[1]
            print("Received from client: %s" % msg)
            if messages_received != int(count):
                print("Incorrect message order... quitting")
                quit()
            messages_received += 1
            

    # Symmetric encryption only: the confidentiality of messages is protected.
    if type_encryption == "SYMMETRIC":

        while(True):

            msg = connfd.recv(1028).decode()
            split_msg = msg.split('  ',2)

            # Get the IV
            iv_b64 = split_msg[0].encode()[2:-1]
            iv = base64.b64decode(iv_b64)

            # Get the msg_ct
            msg_ct_b64 = split_msg[1].encode()[2:-1]
            #print(msg_ct_b64)
            msg_ct = base64.b64decode(msg_ct_b64)

            count  = int(split_msg[2])
            # Decrypt the cipher message and print
            msg = aes_decrypt(aes_key, iv, msg_ct)
            print("Received from client: %s" %  msg)
            if messages_received != int(count):
                print("Incorrect message order... quitting")
                quit()
            messages_received += 1
    
    # Using only HMAC
    if type_encryption == "MAC":
 
        while(True):

            # Receive message and signature
            msg = connfd.recv(1024).decode()
            split_msg = msg.split('  ',2)

            # Get message
            msg = split_msg[0]

            # Get signature
            signature_b64 = split_msg[1].encode()[2:-1]
            signature = base64.b64decode(signature_b64)


            count = split_msg[2]
            # Check signature (this returns an exception if signature is comprimised)
            check_signature(hmac_key,(msg+count).encode(),signature)
            print("Received: ", msg)
            if messages_received != int(count):
                print("Incorrect message order... quitting")
                quit()
            messages_received += 1

    # Symmetric encryption then HMAC
    if type_encryption == "SYMMETRIC_MAC":
    
        while(True):
   
            msg_enc = connfd.recv(1024).decode()
            split_msg = msg_enc.split('  ',3)

            # Get the IV
            iv_b64 = split_msg[0].encode()[2:-1]
            iv = base64.b64decode(iv_b64)

            # Get the msg_ct
            msg_ct_b64 = split_msg[1].encode()[2:-1]
            #print(msg_ct_b64)
            msg_ct = base64.b64decode(msg_ct_b64)

            # Get signature
            signature_b64 = split_msg[2].encode()[2:-1]
            signature = base64.b64decode(signature_b64)

            count = split_msg[3]
            # Check signature (this returns an exception if signature is comprimised)
            check_signature(hmac_key,(str(msg_ct_b64) + count).encode(),signature)

            # Decrypt the cipher message and print
            msg = aes_decrypt(aes_key, iv, msg_ct)
            print("Received from client: %s" % msg)
            if messages_received != int(count):
                print("Incorrect message order... quitting")
                quit()
            messages_received += 1
#        # You don't need to send a response for this assignment
#        # but if you wanted to you'd do something like this
#        msg = input("Enter message for client: ")
#        connfd.send(msg.encode())

    # close connection
    connfd.close()
    listenfd.close()

if __name__ == "__main__":
    main()