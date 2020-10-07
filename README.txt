A3 Secure Channels: Maxwell Rose Stefanos Stoikos

Setup:
- Install cryptography using pip3 install cryptography

Instructions:
- We tested this on Ubuntu and Windows 
- Run "python3 Gen.py" in order to generate the key pairs required
- Check to see if the following keys are generated: private_key_alice.pem,public_key_alice.pem,private_key_bob.pem,public_key_bob.pem
- If yes then proceed with running the following commands in order, choosing one of none/symmetric/mac/symmetric_mac

1) python3 Bob.py 8047 none/symmetric/mac/symmetric_mac

(python3 Bob.py <port> <type of encryption>)
(Bob is the server)

2) python3 Mallory.py 127.0.0.1 8080 8047 none/symmetric/mac/symmetric_mac

(python3 Mallory.py <host> <in_port> <out_port> <type_enc>)
(Mallory is the adversary)

3) python3 Alice.py 127.0.0.1 8080 none/symmetric/mac/symmetric_mac

(python3 Alice.py <host> <port> <type_enc>)
(Alice is the client)

NOTE: The type_enc should match in all 3 (Alice,Bob,Mallory)