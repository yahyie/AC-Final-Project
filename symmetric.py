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

