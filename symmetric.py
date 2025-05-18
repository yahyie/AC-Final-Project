import random 

class CaesarCipher:
    """
    Implementation of the Caesar cipher encryption algorithm.
    """
    
    @staticmethod
    def encrypt_decrypt(text, shift_keys, ifdecrypt):
        """
        Encrypts a text using Caesar Cipher with a list of shift keys.
        Args:
            text: The text to encrypt.
            shift_keys: A list of integers representing the shift values for each character.
            ifdecrypt: flag if decrypt or encrypt
        Returns:
            A string containing the encrypted text if encrypt and plain text if decrypt
        """
        coded_text = []
        key_list = [int(i)*-1 if ifdecrypt else int(i) for i in shift_keys]
        
        for i in range(len(text)):
            coded_text.append(chr(((ord(text[i]) + key_list[i % len(key_list)] - 32) % 94) + 32))
        
            key = key_list[i % len(key_list)]*-1 if ifdecrypt else key_list[i % len(key_list)]
        
        return "".join(coded_text)

class VernamCipher:
    """
    Implementation of the Vernam cipher encryption algorithm.
    """
    @staticmethod
    def text_to_decimal(text: str) -> str:
        """Convert text to 3-digit decimal ASCII values with leading zeros"""
        return "".join([str(ord(char)).zfill(3) for char in text])

    @staticmethod
    def decimal_to_text(decimal_str: str) -> str:
        """Convert 3-digit decimal string back to text"""
        characters = []
        for i in range(len(decimal_str)):
            if (i+1) % 3 == 0:
                characters.append(decimal_str[i-2] + decimal_str[i-1] + decimal_str[i])
        
        return "".join([str(chr(int(char))) for char in characters])

    @staticmethod
    def generate_key(length: int) -> str:
        """Generate random numeric key of specified length"""
        return "".join([str(random.randint(0,9)) for _ in range(length)])

    @staticmethod
    def vernam_encrypt(plaintext_dec: str, key_dec: str) -> str:
        return "".join([str((int(plaintext_dec[i]) - int(key_dec[i])) % 10) for i in range(len(plaintext_dec))])

    @staticmethod
    def vernam_decrypt(ciphertext_dec: str, key_dec: str) -> str:
        """Decrypt decimal ciphertext using Vernam cipher"""
        return ("".join([str((int(ciphertext_dec[i]) + int(key_dec[i])) % 10) for i in range(len(ciphertext_dec))]))