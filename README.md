# 🔐 CipherNest 🔐
![block_decryption_screenshot.png](https://github.com/yahyie/AC-Final-Project/blob/main/Screenshots/Home.png?raw=true)


#### BSCS 3A
#### Applied Cryptography CSAC 329 Cryptographic Application
#### May 2025

---
##### The application can be accessed online via the following link:   https://kesove9448.pythonanywhere.com/
---

## 👥 Members:
1. Jayp Bazar *(Leader / Programmer)*
2. Mark Wayne Cleofe *(Programmer)*
3. Quennie Magno *(Designer / Documentation)*

---

## 📘 Introduction

This project, CipherNest, is an interactive application designed to allow users to explore and experiment with fundamental cryptographic algorithms. The purpose of CipherNest is to provide a hands-on learning experience with various encryption, decryption, and hashing concepts. Cryptography is the science of encoding and decoding messages to protect their confidentiality, integrity, and authenticity. It is of paramount importance in the digital age, serving as the foundation for secure communication, data protection, and privacy. Understanding its core principles is crucial for anyone involved in information technology and digital security. CipherNest aims to demystify these concepts by providing a clear and engaging platform for users to see cryptographic algorithms in action. The application provides a user-friendly interface that allows users to encrypt, decrypt, and hash messages/files using different cryptographic algorithms.

---

## 🎯 Project Objectives

This project aims to achieve the following:
1.  Develop a user-friendly application that implements a variety of cryptographic techniques to secure communication, data, and information exchange.
2.  Provide accessible information and descriptions for each implemented cryptographic algorithm within the application and documentation, including brief history, pseudocode, process description, and use cases.
3.  Utilize standard Python cryptographic modules/libraries for the implementation of algorithms.
4.  Allow users to encrypt, decrypt, and hash both text and files (where applicable) using the implemented algorithms.
5.  Ensure the application is well-documented, including a comprehensive README.md file and clear commit history from all group members.

---

## 🧠 Discussions

### Application Architecture and UI Choice:

CipherNest is a web-based application developed using the **Flask** framework in Python. Flask was chosen for its simplicity, flexibility, and suitability for creating web UIs. The application follows a client-server architecture:
* **Frontend (Client-Side)**: HTML, CSS, and JavaScript are used to create an interactive and responsive user interface. Templates for different ciphers are rendered to allow users to input text, select modes (encrypt/decrypt), and view results. AJAX is used for some operations to update parts of the page without a full reload, enhancing user experience.
* **Backend (Server-Side)**: Python with Flask handles the cryptographic logic. Different routes are defined for each cryptographic algorithm. These routes process user input from the forms, call the appropriate cryptographic functions from `symmetric.py`, `asymmetric.py`, and `hashing.py`, and then return the results to the frontend.

The UI is designed to be intuitive, with a clear sidebar for navigation between different ciphers and distinct sections for input, key management, and output for each algorithm.

### Implemented Cryptographic Algorithms:

#### Symmetric Algorithms:

1.  **Caesar Cipher**
    * **Type:** Symmetric
    * **Brief History/Background:** One of the simplest and most widely known encryption techniques. It is named after Julius Caesar, who used it in his private correspondence. It's a type of substitution cipher in which each letter in the plaintext is replaced by a letter some fixed number of positions down or up the alphabet.
    * **Description of the Process/How it Works:**
        Each character in the plaintext is shifted by a certain number of places (the key) down the alphabet. For example, with a left shift of 3, 'D' would be replaced by 'A', and 'E' would become 'B'. The same shift key is used for both encryption and decryption (by shifting in the opposite direction). The application supports multiple shift keys, applying them sequentially and repeating if the key length is shorter than the text.
    * **Pseudocode Overview (Encryption):**
        ```
        FUNCTION caesar_encrypt_decrypt(text, shift_keys, is_decryption):
          IF is_decryption:
            key_list = invert_and_convert_keys_to_int(shift_keys)
          ELSE:
            key_list = convert_keys_to_int(shift_keys)
          
          coded_text = EMPTY_LIST
          FOR i FROM 0 TO length(text) - 1:
            char_code = get_ascii_code(text[i])
            current_key = key_list[i MOD length(key_list)]
            new_char_code = (char_code + current_key - 32) MOD 94 + 32
            coded_text.append(character_from_code(new_char_code))
          RETURN join(coded_text)
        ```
    * **Libraries Used:** No external cryptographic libraries are used; it's implemented using basic Python operations.
    * **How it's integrated:** A Flask route `/caesar-cipher` handles GET and POST requests. Users input text and shift keys via an HTML form. The backend Python function `CaesarCipher.encrypt_decrypt` performs the operation.

2.  **Vernam Cipher (One-Time Pad variant)**
    * **Type:** Symmetric
    * **Brief History/Background:** Patented by Gilbert Vernam in 1919, it's a theoretically unbreakable cipher if the key is truly random, used only once, and is at least as long as the message. This implementation uses a numeric key.
    * **Description of the Process/How it Works:**
        The plaintext is first converted to a sequence of 3-digit decimal ASCII values. A numeric key of the same length as this decimal string is generated (for encryption) or provided (for decryption). Encryption involves subtracting each digit of the key from the corresponding digit of the decimal plaintext, modulo 10. Decryption involves adding the key digits, modulo 10.
    * **Pseudocode Overview (Encryption):**
        ```
        FUNCTION vernam_encrypt(plaintext_decimal_string, key_decimal_string):
          ciphertext_decimal_string = EMPTY_STRING
          FOR i FROM 0 TO length(plaintext_decimal_string) - 1:
            plain_digit = integer(plaintext_decimal_string[i])
            key_digit = integer(key_decimal_string[i])
            cipher_digit = (plain_digit - key_digit) MOD 10
            ciphertext_decimal_string.append(string(cipher_digit))
          RETURN ciphertext_decimal_string
        ```
    * **Libraries Used:** `random` module for key generation.
    * **How it's integrated:** A Flask route `/vernam-cipher` is used. The `VernamCipher` class methods handle text-to-decimal conversion, key generation, encryption, and decryption.

3.  **Block Cipher (Custom XOR-based)**
    * **Type:** Symmetric
    * **Brief History/Background:** Block ciphers operate on fixed-size blocks of data. This is a custom implementation using XOR operations.
    * **Description of the Process/How it Works:**
        The plaintext is divided into 8-character blocks. If the last block is smaller, it's padded with `_` characters during encryption. An 8-character key is required. Each character in a block is XORed with the corresponding character in the key (the key is repeated if necessary). The result of encryption is a hex string. Decryption reverses the process, XORing the ciphertext (after converting from hex) with the same key and removing padding.
    * **Pseudocode Overview (Encryption):**
        ```
        FUNCTION block_encrypt(text, key):
          IF length(key) IS NOT 8: RETURN "Error: Key must be 8 chars"
          IF length(text) MOD 8 > 0:
            text = text + "_" * (8 - (length(text) MOD 8))
          
          byte_key = encode_to_ascii(key)
          byte_text = encode_to_ascii(text)
          result_bytearray = EMPTY_BYTEARRAY
          
          FOR i FROM 0 TO length(byte_text) - 1 STEP 8:
            block = byte_text[i TO i+7]
            FOR j FROM 0 TO length(block) - 1:
              xor_result = block[j] XOR byte_key[j MOD length(byte_key)] // Corrected to use modulo for key repetition
              result_bytearray.append(xor_result)
          RETURN bytes_to_hex_string(result_bytearray)
        ```
    * **Libraries Used:** No external cryptographic libraries.
    * **How it's integrated:** Via the `/block-cipher` Flask route. The `BlockCipher.encrypt_decrypt` method processes the text.

#### Asymmetric Algorithms:

1.  **RSA (Rivest-Shamir-Adleman)**
    * **Type:** Asymmetric
    * **Brief History/Background:** One of the first public-key cryptosystems, widely used for secure data transmission. It was described in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman. Its security relies on the practical difficulty of factoring the product of two large prime numbers.
    * **Description of the Process/How it Works:**
        Key generation involves creating a public and a private key. The public key can be shared with anyone, while the private key is kept secret. To encrypt a message, the sender uses the recipient's public key. To decrypt, the recipient uses their private key. This implementation uses Optimal Asymmetric Encryption Padding (OAEP) with SHA-256 for added security.
    * **Pseudocode Overview (Encryption):**
        ```
        FUNCTION rsa_encrypt(message, public_key_pem):
          public_key = load_pem_public_key(public_key_pem)
          ciphertext = public_key.encrypt(
            message_bytes,
            OAEP_padding_with_SHA256
          )
          RETURN base64_encode(ciphertext)
        ```
    * **Libraries Used:** `cryptography` (specifically `rsa`, `padding`, `hashes`, `serialization`).
    * **How it's integrated:** The `/rsa` route handles encryption/decryption, and `/rsa-genkey` handles key generation. The `RSA` class in `asymmetric.py` contains methods for key generation, encryption, and decryption.

2.  **ECC (Elliptic Curve Cryptography)**
    * **Type:** Asymmetric
    * **Brief History/Background:** An approach to public-key cryptography based on the algebraic structure of elliptic curves over finite fields. ECC allows for smaller keys compared to non-EC cryptography (like RSA) to provide equivalent security.
    * **Description of the Process/How it Works:**
        This implementation uses a hybrid encryption scheme. An ephemeral (temporary) ECC key pair is generated. Elliptic Curve Diffie-Hellman (ECDH) is used with the ephemeral private key and the recipient's public key to derive a shared secret. This shared secret is then used with HKDF (HMAC-based Key Derivation Function) to derive a symmetric key for AES-GCM encryption. The ephemeral public key, nonce, and ciphertext are sent to the recipient. The recipient uses their private key and the sender's ephemeral public key to re-derive the shared secret and then the symmetric key for decryption.
    * **Pseudocode Overview (Encryption):**
        ```
        FUNCTION ecc_encrypt(message, receiver_public_key_pem):
          receiver_public_key = load_pem_public_key(receiver_public_key_pem)
          ephemeral_private_key = generate_ecc_private_key(SECP256R1)
          ephemeral_public_key = ephemeral_private_key.public_key()
          
          shared_key = ephemeral_private_key.exchange(ECDH, receiver_public_key)
          derived_symmetric_key = HKDF(shared_key, length=32, algorithm=SHA256, salt=None, info='handshake data')
          
          nonce = generate_random_bytes(12)
          aesgcm = AESGCM(derived_symmetric_key)
          ciphertext = aesgcm.encrypt(nonce, message_bytes, None)
          
          RETURN {
            'ephemeral_public_key': base64_encode(serialize_pem(ephemeral_public_key)),
            'nonce': base64_encode(nonce),
            'ciphertext': base64_encode(ciphertext)
          }
        ```
    * **Libraries Used:** `cryptography` (specifically `ec`, `hashes`, `serialization`, `HKDF`, `AESGCM`), `os`, `base64`.
    * **How it's integrated:** Routes `/ecc` (main page), `/ecc-genkey` (key generation), `/ecc-encrypt`, and `/ecc-decrypt` are used. The `ECC` class in `asymmetric.py` provides the core logic.

#### Hashing Functions:

The application implements four hashing functions: MD5, SHA-1, SHA-256, and SHA-512. All hashing functions support hashing text. The general process involves taking an input text, encoding it to UTF-8, and then applying the respective hashing algorithm to produce a fixed-size hexadecimal string (the hash). They also provide a verification function to check if a given text produces a known hash.

1.  **MD5 (Message Digest Algorithm 5)**
    * **Type:** Hash
    * **Brief History/Background:** A widely used hash function producing a 128-bit hash value. While historically popular, MD5 is now considered cryptographically broken and unsuitable for further use in security applications due to vulnerabilities to collision attacks.
    * **Description of the Process/How it Works:** Takes input message, processes it in blocks, and produces a 128-bit hash.
    * **Pseudocode Overview (Hashing):**
        ```
        FUNCTION md5_generate_hash(text):
          message_bytes = encode_to_utf8(text)
          md5_object = initialize_md5()
          md5_object.update(message_bytes)
          RETURN md5_object.hexdigest()
        ```
    * **Libraries Used:** `hashlib`.
    * **How it's integrated:** Route `/md5` for the page, `/md5-hash` for generating hash, and `/verify-md5` for verification. Logic is in `MD5Hash` class in `hashing.py`.

2.  **SHA-1 (Secure Hash Algorithm 1)**
    * **Type:** Hash
    * **Brief History/Background:** Produces a 160-bit hash value. Like MD5, SHA-1 is also considered insecure against well-funded attackers and has been deprecated for most cryptographic uses since 2011.
    * **Description of the Process/How it Works:** Similar to MD5 but produces a longer hash and uses a different internal structure.
    * **Pseudocode Overview (Hashing):**
        ```
        FUNCTION sha1_generate_hash(text):
          message_bytes = encode_to_utf8(text)
          sha1_object = initialize_sha1()
          sha1_object.update(message_bytes)
          RETURN sha1_object.hexdigest()
        ```
    * **Libraries Used:** `hashlib`.
    * **How it's integrated:** Route `/sha1` for the page, `/sha1-hash` for generating hash, and `/verify-sha1` for verification. Logic is in `SHA1Hash` class in `hashing.py`.

3.  **SHA-256 (Secure Hash Algorithm 256-bit)**
    * **Type:** Hash
    * **Brief History/Background:** Part of the SHA-2 family, designed by the NSA. It produces a 256-bit hash value and is widely used in many security applications and protocols, including TLS, SSL, PGP, SSH, IPsec, and Bitcoin.
    * **Description of the Process/How it Works:** More complex internal operations than SHA-1, resulting in a stronger hash.
    * **Pseudocode Overview (Hashing):**
        ```
        FUNCTION sha256_generate_hash(text):
          message_bytes = encode_to_utf8(text)
          sha256_object = initialize_sha256()
          sha256_object.update(message_bytes)
          RETURN sha256_object.hexdigest()
        ```
    * **Libraries Used:** `hashlib`.
    * **How it's integrated:** Route `/sha256` for the page, `/sha256-hash` for generating hash, and `/verify-sha256` for verification. Logic is in `SHA256Hash` class in `hashing.py`.

4.  **SHA-512 (Secure Hash Algorithm 512-bit)**
    * **Type:** Hash
    * **Brief History/Background:** Also part of the SHA-2 family, producing a 512-bit hash value. It offers a higher security level than SHA-256, especially against future cryptanalytic attacks and on 64-bit processors.
    * **Description of the Process/How it Works:** Similar structure to SHA-256 but uses larger word sizes and more rounds.
    * **Pseudocode Overview (Hashing):**
        ```
        FUNCTION sha512_generate_hash(text):
          message_bytes = encode_to_utf8(text)
          sha512_object = initialize_sha512()
          sha512_object.update(message_bytes)
          RETURN sha512_object.hexdigest()
        ```
    * **Libraries Used:** `hashlib`.
    * **How it's integrated:** Route `/sha512` for the page, `/sha512-hash` for generating hash, and `/verify-sha512` for verification. Logic is in `SHA512Hash` class in `hashing.py`.

---

## 🧪 Sample Run / Outputs

This section will include screen snippets (screenshots) or text-based output examples for each algorithm's functionality (encryption, decryption, hashing for both text and files where applicable).

**Note:** File encryption/decryption and file hashing functionalities are planned extensions based on the project description but current code focuses on text. Screenshots will demonstrate the UI for text operations.

#### Caesar Cipher:
* **Encryption:**
    * Input Text: `HELLO WORLD`
    * Shift Keys: `3`
    * Output: `KHOOR ZRUOG`
    * (Placeholder for Screenshot: `caesar_encryption_screenshot.png`)
* **Decryption:**
    * Input Text: `KHOOR ZRUOG`
    * Shift Keys: `3`
    * Output: `HELLO WORLD`
       ![block_decryption_screenshot.png](https://github.com/yahyie/AC-Final-Project/blob/main/Screenshots/CaesarCipher.png?raw=true)

#### Vernam Cipher:
* **Encryption:**
    * Input Text: `HI`
    * Generated Key: (e.g., `123456` - assuming ASCII "H"=072, "I"=073 -> "072073")
    * Output Ciphertext (Decimal): (e.g., `959627` if `text_to_decimal` output is `072073` and key is `123456`, then $(0-1)\%10=9, (7-2)\%10=5, (2-3)\%10=9, (0-4)\%10=6, (7-5)\%10=2, (3-6)\%10=7$)
    * (Placeholder for Screenshot: `vernam_encryption_screenshot.png`)
* **Decryption:**
    * Input Ciphertext (Decimal): `959627`
    * Key: `123456`
    * Output Plaintext: `HI`
       *![block_decryption_screenshot.png](https://github.com/yahyie/AC-Final-Project/blob/main/Screenshots/VernamCipher.png?raw=true)

#### Block Cipher (Custom XOR):
* **Encryption:**
    * Input Text: `TESTTEXT`
    * Key: `MYSECRET`
    * Output: (Hex string output, e.g., `1F 0A 1C 1A 1B 0A 1C 0B`)
    * (Placeholder for Screenshot: `block_encryption_screenshot.png`)
* **Decryption:**
    * Input Hex Text: `1F 0A 1C 1A 1B 0A 1C 0B`
    * Key: `MYSECRET`
    * Output: `TESTTEXT`
      ![block_decryption_screenshot.png](https://github.com/yahyie/AC-Final-Project/blob/main/Screenshots/BlockCipher.png?raw=true)

#### RSA Encryption:
* **Key Generation:**
    * (Show example of generated public and private keys)
    * (Placeholder for Screenshot: `rsa_keygen_screenshot.png`)
* **Encryption:**
    * Input Text: `SECRETMSG`
    * Public Key: (Paste generated Public Key)
    * Output: (Base64 encoded ciphertext)
    * (Placeholder for Screenshot: `rsa_encryption_screenshot.png`)
* **Decryption:**
    * Input Ciphertext: (Paste Base64 encoded ciphertext)
    * Private Key: (Paste generated Private Key)
    * Output: `SECRETMSG`
       ![block_decryption_screenshot.png](https://github.com/yahyie/AC-Final-Project/blob/main/Screenshots/RSAEncryption.png?raw=true)

#### ECC Encryption:
* **Key Generation:**
    * (Show example of generated public and private ECC keys)
    * (Placeholder for Screenshot: `ecc_keygen_screenshot.png`)
* **Encryption:**
    * Input Text: `ECC TEST`
    * Recipient's Public Key: (Paste generated Public Key)
    * Output: (Dictionary including ephemeral public key, nonce, ciphertext - all base64)
    * (Placeholder for Screenshot: `ecc_encryption_screenshot.png`)
* **Decryption:**
    * Input Encrypted Data (Ephemeral PubKey, Nonce, Ciphertext): (Paste corresponding parts)
    * Recipient's Private Key: (Paste generated Private Key)
    * Output: `ECC TEST`
       ![block_decryption_screenshot.png](https://github.com/yahyie/AC-Final-Project/blob/main/Screenshots/ECCEncryption.png?raw=true)

#### MD5 Hashing:
* **Generate Hash:**
    * Input Text: `Hello CipherNest`
    * Output Hash: (e.g., `8d6f9b9198b357b45dd69342679f08f3`)
    * (Placeholder for Screenshot: `md5_hashing_screenshot.png`)
* **Verify Hash:**
    * Input Text: `Hello CipherNest`
    * Hash to Verify: `8d6f9b9198b357b45dd69342679f08f3`
    * Output: `Hash Verified ✓`
      ![block_decryption_screenshot.png](https://github.com/yahyie/AC-Final-Project/blob/main/Screenshots/MD5.png?raw=true)

#### SHA-1 Hashing:
* **Generate Hash:**
    * Input Text: `Hello CipherNest`
    * Output Hash: (e.g., `a9b81e5c6f87a901a8c46c3b7b878876c53512d5`)
    ![block_decryption_screenshot.png](https://github.com/yahyie/AC-Final-Project/blob/main/Screenshots/SHA-1.png?raw=true)

#### SHA-256 Hashing:
* **Generate Hash:**
    * Input Text: `Hello CipherNest`
    * Output Hash: (e.g., `d18e2a3d2c0423992bf78f683594e5b192f1b8183d08c87465219844c1c99a87`)
  ![SHA-256](https://github.com/yahyie/AC-Final-Project/blob/main/Screenshots/SHA-256.png?raw=true)

#### SHA-512 Hashing:
* **Generate Hash:**
    * Input Text: `Hello CipherNest`
    * Output Hash: (e.g., `1e7b9a3f...` long hash)
       ![SHA-256](https://github.com/yahyie/AC-Final-Project/blob/main/Screenshots/SHA-512.png?raw=true)

---



