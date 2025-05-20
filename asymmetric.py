from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

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