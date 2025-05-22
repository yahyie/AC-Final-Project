from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os

class RSA:
    """
    A class to handle RSA asymmetric encryption and decryption.
    """

    @staticmethod
    def generate_keys(key_size=2048):
        """
        Generate RSA public and private key pair.
        
        Args:
            key_size: Size of the RSA key in bits (default: 2048)
            
        Returns:
            tuple: (private_key, public_key) as PEM strings
        """
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Get the public key from the private key
        public_key = private_key.public_key()
        
        # Serialize the private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize the public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')

    @staticmethod
    def encrypt_message(message, public_key_pem):
        """
        Encrypt a message using an RSA public key.
        
        Args:
            message: The message to encrypt (string)
            public_key_pem: Public key in PEM format (string)
            
        Returns:
            string: Base64-encoded encrypted message
        """
        # Convert message to bytes if it's not already
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Load the public key from PEM format
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        
        # Encrypt the message
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Encode the ciphertext as base64 for easy transmission
        return base64.b64encode(ciphertext).decode('utf-8')

    @staticmethod
    def decrypt_message(encrypted_message, private_key_pem):
        """
        Decrypt a message using an RSA private key.
        
        Args:
            encrypted_message: Base64-encoded encrypted message (string)
            private_key_pem: Private key in PEM format (string)
            
        Returns:
            string: Decrypted message
        """
        # Decode the base64 encrypted message
        ciphertext = base64.b64decode(encrypted_message.encode('utf-8'))
        
        # Load the private key from PEM format
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        
        # Decrypt the message
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return the plaintext as a string
        return plaintext.decode('utf-8')
    
class ECC:
    """
    A class to handle ECC asymmetric encryption and decryption.
    """

    @staticmethod
    def generate_ecc_keypair():
        """
        Generate an ECC key pair using the SECP256R1 curve
        
        Returns:
            tuple: (private_key, public_key) as PEM strings
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        # Serialize the private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize the public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')

    @staticmethod
    def encrypt(message, receiver_public_key_pem):
        """
        Encrypt a message using ECC-based hybrid encryption
        
        Args:
            message: The plaintext message (string)
            receiver_public_key_pem: The recipient's public key in PEM format (string)
            
        Returns:
            dict: Dictionary containing encrypted data (all values as base64 strings)
        """
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Load public key from PEM
        receiver_public_key = serialization.load_pem_public_key(
            receiver_public_key_pem.encode('utf-8')
        )
        
        # Generate an ephemeral key pair for this encryption
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # Perform ECDH to create shared secret
        shared_key = ephemeral_private_key.exchange(
            ec.ECDH(), 
            receiver_public_key
        )
        
        # Derive encryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        
        # Generate a random nonce for AES-GCM
        nonce = os.urandom(12)
        
        # Encrypt the message using AES-GCM
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, message, None)
        
        # Serialize the ephemeral public key for transmission
        ephemeral_public_pem = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Return all components needed for decryption as base64 strings
        return {
            'ephemeral_public_key': base64.b64encode(ephemeral_public_pem).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

    @staticmethod
    def decrypt(encrypted_data, receiver_private_key_pem):
        """
        Decrypt a message using ECC-based hybrid decryption
        
        Args:
            encrypted_data: Dictionary containing encrypted message components (base64 strings)
            receiver_private_key_pem: The recipient's private key in PEM format (string)
            
        Returns:
            string: The decrypted plaintext message
        """
        # Load private key from PEM
        receiver_private_key = serialization.load_pem_private_key(
            receiver_private_key_pem.encode('utf-8'),
            password=None
        )
        
        # Decode base64 components
        ephemeral_public_key = serialization.load_pem_public_key(
            base64.b64decode(encrypted_data['ephemeral_public_key'])
        )
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # Perform ECDH again to recreate shared secret
        shared_key = receiver_private_key.exchange(
            ec.ECDH(),
            ephemeral_public_key
        )
        
        # Derive encryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        
        # Decrypt the message
        aesgcm = AESGCM(derived_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Return the plaintext as a string
        return plaintext.decode('utf-8')
