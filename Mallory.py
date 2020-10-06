import sys
import socket
from os import _exit as quit

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


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
        print("usage: python3 %s <port>" % sys.argv[0])
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


    #Expecting handshake
    # clientfd.send(connfd.recv(1024))
    # clientfd.send(connfd.recv(1024))
    # clientfd.send(connfd.recv(1024))
    # clientfd.send(connfd.recv(1024))
    # clientfd.send(connfd.recv(1024))

    handshake = connfd.recv(1024)
    clientfd.send(handshake)


    # message loop
    if type_encryption == "NONE":
        while(True):
            #Receiving
            msg = connfd.recv(1024)
            print("Received from client Alice: %s" % msg.decode())

            #Relaying the message to Bob
            clientfd.send(msg)

    if type_encryption == "SYMMETRIC":

        #recieve the encrypted key and iv 
        key_enc = connfd.recv(1024)
        print("k")
        iv_enc = connfd.recv(1024)
        print("i")

        #send the encrytped key and iv
        clientfd.send(key_enc)
        clientfd.send(iv_enc)   

        #recieve the encrcypted message and forward it
        while(True):
            msg_enc = connfd.recv(1024)
            print(msg_enc)
            clientfd.send(msg_enc)
    
    if type_encryption == "MAC":

        #recieving and sending encrypted aes key
        key_enc = connfd.recv(1024)
        clientfd.send(key_enc)

        #recieve message and Mac, print the plain text, forward
        while(True):
            msg_ct = connfd.recv(1024)
            hash_mac = connfd.recv(1024)

            clientfd.send(msg_ct)
            clientfd.send(hash_mac)

            
            print(msg_ct)






    clientfd.close()
    connfd.close()
    listenfd.close()

if __name__ == "__main__":
    main()