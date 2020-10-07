import sys
import socket
from os import _exit as quit

import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import time 
def load_key():
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
    )
    return public_key

def main():

    public_key  = load_key()
    # parse arguments
    if len(sys.argv) != 5:
        print("usage: python3 %s <host> <in_port> <out_port> <type_enc>" % sys.argv[0])
        quit(1)

    host  = sys.argv[1]
    #From alice    
    in_port = sys.argv[2]
    #To bob
    out_port  = sys.argv[3]
    #type of encryption
    type_encryption = sys.argv[4].upper() 

    #Listening from alice
    listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listenfd.bind(('', int(in_port)))
    listenfd.listen(1)
    (connfd, addr) = listenfd.accept()



    #This is for sending to bob
    clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientfd.connect((host, int(out_port)))

    #receiving handshake
    handshake = connfd.recv(2048)
    #time.sleep(2)
    #relaying it
    clientfd.send(handshake)


    # message loop
    if type_encryption == "NONE":
        while(True):
            #Receiving
            original_msg = connfd.recv(1024).decode()
            split_msg = original_msg.split('  ',1)
            count = int(split_msg[0])
            msg = split_msg[1]
            #ATTACK 3 - UNCOMMENT FOR ATTACK
            #msg = "ATTACK"
            print("Received from client Alice: %s" % msg)
            #Relaying the message to Bob
            clientfd.send((str(count) + '  ' + msg ).encode())

            


    if type_encryption == "SYMMETRIC":

        while(True):
            #receiving the message
      
            msg = connfd.recv(1024).decode()
            split_msg = msg.split('  ',2)

            # Get the IV
            iv_b64 = split_msg[0].encode()[2:-1]
            iv = base64.b64decode(iv_b64)


            # Get the msg_ct
            msg_ct_b64 = split_msg[1].encode()[2:-1]
            msg_ct = base64.b64decode(msg_ct_b64)

            msg_ct_changed = base64.b64encode(msg_ct)
            count = int(split_msg[2])
            
            #UNCOMMENT FOR ATTACK 4
            #if len(msg_ct) >= 17:
            #    msg_ct_changed = base64.b64encode(msg_ct[:-16])
         
            print("Received from Alice to Bob: %s" %  msg_ct)

            #re-constructing the message and sending it to bob
            clientfd.send((str(iv_b64) + "  " + str(msg_ct_changed) + "  " +  str(count)).encode())
            
               
    
    if type_encryption == "MAC":
        #recieve message and Mac, print the plain text, forward
        while(True):
            #receiving the message and spliting it
            msg = connfd.recv(1024).decode()
            split_msg = msg.split('  ',2)

            # Get message
            msg = split_msg[0]

            # Get signature
            signature_b64 = split_msg[1].encode()[2:-1]
            signature = base64.b64decode(signature_b64)

            count = split_msg[2]
         
            print("Received message from Alice to Bob : ", msg, "Signature: ",signature)
            #re-constructing the message and sending it to bob
            message_signature_b64 = base64.b64encode(signature)
            clientfd.send((msg + "  " + str(message_signature_b64) + "  "+ str(count)).encode())

    if type_encryption == "SYMMETRIC_MAC":

        while True:
            #receiving the message and splitting it 
            msg_enc = connfd.recv(1024).decode()
            split_msg = msg_enc.split('  ',3)

            #getting the iv
            iv_b64 = split_msg[0].encode()[2:-1]
            iv = base64.b64decode(iv_b64)

            #getting the cipher
            msg_ct_b64 = split_msg[1].encode()[2:-1]
            msg_ct = base64.b64decode(msg_ct_b64)

            #getting the signature
            signature_b64 = split_msg[2].encode()[2:-1]
            signature = base64.b64decode(signature_b64)

            count = split_msg[3]
            print("Received from Alice to Bob : %s" % msg_ct, "Signature from client: ",signature)
            #re-constructing the message and sending it to bob
            iv_b64 = base64.b64encode(iv)
            msg_ct_b64 = base64.b64encode(msg_ct)
            message_signature_b64 = base64.b64encode(signature)

            clientfd.send((str(iv_b64) + "  " + str(msg_ct_b64) + "  " + str(message_signature_b64)+ "  " + count).encode())


    clientfd.close()
    connfd.close()
    listenfd.close()

if __name__ == "__main__":
    main()