from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import os


#Key Generation
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

#Shared key (ECDH + HKDF)
def derived_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    derived_key = HKDF(
        algorithm = hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure messaging'
    ).derive(shared_secret)

    return derived_key

#AES Encryption
def encrypt_message(key, message):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    return nonce + ciphertext

#AES Decryption
def decrypted_message(key, data):
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

#Simulate Alice and Bob
def secure_chat():
    print("\n--- Secure Messaging Demo --\n")

    #Generate Keys
    alice_priv, alice_pub = generate_keys()
    bob_priv, bob_pub = generate_keys()
    
    #Exchange and derive shared keys
    alice_key = derived_shared_key(alice_priv, bob_pub)
    bob_key = derived_shared_key(bob_priv, alice_pub)

    print("Shared keys match:", alice_key == bob_key)

    #Messaging Loop
    while True:
        message = input("\nAlice: ")

        if message.lower() == "quit":
            print("Ending Chat")
            break

        encrypted = encrypt_message(alice_key, message)
        print("Encrypted:", encrypted.hex())

        decrypted = decrypted_message(bob_key, encrypted)
        print("Bob receives:", decrypted)
    
secure_chat()
        
