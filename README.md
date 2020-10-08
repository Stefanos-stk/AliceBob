# A3 Secure Channels: Maxwell Rose Stefanos Stoikos

# Setup:
* Install cryptography package using ```pip3 install cryptography```
* Install socket package ```pip3 install cryptography```

# Instructions:
* We tested this on Ubuntu and Windows 
* Run ```python3 Gen.py``` in order to generate the key pairs required
* Check to see if the following keys are generated: private_key_alice.pem,public_key_alice.pem,private_key_bob.pem,public_key_bob.pem
* If yes then proceed with running the following commands:
    * ```python3 Bob.py 8047 none/symmetric/mac/symmetric_mac```
    (python3 Bob.py <port> <type of encryption>)
    (Bob is the server)
    * ```python3 Mallory.py 127.0.0.1 8080 8047 none/symmetric/mac/symmetric_mac ```
    (python3 Mallory.py <host> <in_port> <out_port> <type_enc>)
    (Mallory is the man in the middle)
    * ```python3 Alice.py 127.0.0.1 8080 none/symmetric/mac/symmetric_mac ```
    (python3 Alice.py <host> <port> <type_enc>)
    (Alice is the client)
    * The type_enc should match in all 3 (Alice,Bob,Mallory)

# Handshake Protocol
```A -> B: B, tA, Enc(A,kAB; K_B), Sign(B, tA, Enc(A,kAB; K_B); k_A)```

# No Cryptography Protocol
A -> B: No encryption; text sent as plain text

# Symmetric Cryptography Protocol
A -> B: Messages encrypted using symmetric AES-256 encryption with a 32-byte key.

# Mac Signature Protocol
A -> B: Messages signed with hash_mac to tag and verify the integrity of the message

# Symmetric and Mac Signature Cryptography Protocol
A -> B: Messages encrypted using symmetric AES-256 encryption; signed with hash_mac to tag and verify the integrity of the message