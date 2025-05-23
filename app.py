from flask import Flask, render_template, request, redirect, url_for, jsonify
from symmetric import CaesarCipher, VernamCipher, BlockCipher
from asymmetric import RSA, ECC
from hashing import MD5Hash, SHA1Hash, SHA256Hash, SHA512Hash

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/caesar-cipher', methods=['GET', 'POST'])
def caesar_cipher():
    contents = {
        'id': "#caesar-cipher",
        'title': "Caesar Cipher",
        'type': "Symmetric",
    }

    if request.method == 'POST':    
        text = request.form.get('text-input')
        shift_keys = str(request.form.get('shift-values')).split(' ')
        is_decryption = request.form.get('mode') == 'decrypt'

        output = CaesarCipher.encrypt_decrypt(text, shift_keys, is_decryption)

        # Repeat the keys until it matches the length of the text
        repeated_keys = (shift_keys * ((len(text) + len(shift_keys) - 1) // len(shift_keys)))[:len(text)]

        # Check if it's an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'text': text,
                'keys': repeated_keys,
                'output': output
            })

    return render_template("caesar.html", contents=contents)

@app.route('/vernam-cipher', methods=['GET', 'POST'])
def vernam_cipher():
    contents = {
        'id': "#vernam-cipher",
        'title': "Vernam Cipher",
        'type': "Symmetric",
    }

    if request.method == 'POST':
        text = request.form.get('text-input')
        mode = request.form.get('mode')

        decimal_text = VernamCipher.text_to_decimal(text)
        key = VernamCipher.generate_key(len(decimal_text)) if mode == 'encrypt' else request.form.get('random-keys')
        decimal_output = VernamCipher.vernam_encrypt(decimal_text, key) if mode == 'encrypt' else VernamCipher.vernam_decrypt(decimal_text, key)
        output = VernamCipher.decimal_to_text(decimal_output)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'text': text,
                'decimal_text': decimal_text,
                'key': key,
                'decimal_output': decimal_output,
                'output': output
            })

    return render_template("vernam.html", contents=contents)

@app.route('/block-cipher', methods=['GET', 'POST'])
def block_cipher():
    contents = {
        'id': "#block-cipher",
        'title': "Block Cipher",
        'type': "Symmetric",
    }
    
    if request.method == 'POST':
        text = request.form.get('text-input')
        key = request.form.get('key')
        mode = request.form.get('mode')

        output = BlockCipher.encrypt_decrypt(text, key, mode)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'text': text,
                'key': key,
                'output': output
            })

    return render_template("block.html", contents=contents)

@app.route('/rsa', methods=['GET', 'POST'])
def rsa_encryption():
    contents = {
        'id': "#rsa",
        'title': "RSA Encryption",
        'type': "Asymmetric",
    }

    if request.method == 'POST':
        text = request.form.get('text-input')
        used_key = request.form.get('key')
        mode = request.form.get('mode')

        output = RSA.encrypt_message(text, used_key) if mode == 'encrypt' else RSA.decrypt_message(text, used_key)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'text': text,
                'used_key': used_key,
                'output': output
            })
            
        return render_template("rsa.html", contents=contents, text=text, key=used_key, output=output)

    return render_template("rsa.html", contents=contents)

@app.route('/rsa-genkey', methods=['GET', 'POST'])
def rsa_genkeys():
    private_key, public_key = RSA.generate_keys()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'public_key': public_key,
            'private_key': private_key
        })
    
    return redirect(url_for('rsa_encryption'))

@app.route('/ecc', methods=['GET', 'POST'])
def ecc_encryption():
    contents = {
        'id': "#ecc",
        'title': "ECC Encryption",
        'type': "Asymmetric",
    }

    if request.method == 'POST':
        text = request.form.get('text-input')
        key = request.form.get('key')
        mode = request.form.get('mode')

        if mode == 'encrypt':
            encrypted_data =  ECC.encrypt(text, key)
        else:
            output = ECC.decrypt(encrypted_data, key) if encrypted_data else "Error: You must encrypt first."

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            if mode == 'encrypt':
                return jsonify({
                    'text': text,
                    'used_key': key,
                }.update(encrypted_data)) 
            else:
                return jsonify({
                    'text': text,
                    'used_key': key,
                    'output': output
                })

    return render_template("ecc.html", contents=contents)

@app.route('/ecc-genkey', methods=['GET', 'POST'])
def ecc_genkeys():
    private_key, public_key = ECC.generate_ecc_keypair()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'public_key': public_key,
            'private_key': private_key
        })
    
    return redirect(url_for('ecc'))

@app.route('/ecc-encrypt', methods=['POST'])
def ecc_encrypt():
    try:
        data = request.get_json()
        message = data.get('message')
        public_key = data.get('public_key')
        
        if not message or not public_key:
            return jsonify({'error': 'Missing required parameters'}), 400
            
        encrypted_data = ECC.encrypt(message, public_key)
        return jsonify(encrypted_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ecc-decrypt', methods=['POST'])
def ecc_decrypt():
    try:
        data = request.get_json()
        encrypted_data = data.get('encrypted_data')
        private_key = data.get('private_key')
        
        if not encrypted_data or not private_key:
            return jsonify({'error': 'Missing required parameters'}), 400
            
        decrypted_message = ECC.decrypt(encrypted_data, private_key)
        return jsonify({'message': decrypted_message})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/md5', methods=['GET', 'POST'])
def md5():
    contents = {
        'id': "#md5",
        'title': "MD5",
        'type': "Hash",
    }

    return render_template("md5.html", contents=contents)

@app.route('/md5-hash', methods=['POST'])
def md5_hash():
    if request.method == 'POST':
        text = request.form.get('text-input')
        hash_result = MD5Hash.generate_hash(text)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'text': text,
                'hash': hash_result
            })
    
    return redirect(url_for('md5'))

@app.route('/verify-md5', methods=['POST'])
def verify_md5():
    try:
        data = request.get_json()
        text = data.get('text')
        hash_to_verify = data.get('hash')
        
        if not text or not hash_to_verify:
            return jsonify({'error': 'Missing required parameters'}), 400
            
        is_match = MD5Hash.verify_hash(text, hash_to_verify)
        return jsonify({'match': is_match})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sha1', methods=['GET', 'POST'])
def sha1():
    contents = {
        'id': "#sha1",
        'title': "SHA-1",
        'type': "Hash",
    }
    return render_template("sha1.html", contents=contents)

@app.route('/sha1-hash', methods=['POST'])
def sha1_hash():
    if request.method == 'POST':
        text = request.form.get('text-input')
        hash_result = SHA1Hash.generate_hash(text)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'text': text,
                'hash': hash_result
            })
    
    return redirect(url_for('sha1'))

@app.route('/verify-sha1', methods=['POST'])
def verify_sha1():
    try:
        data = request.get_json()
        text = data.get('text')
        hash_to_verify = data.get('hash')
        
        if not text or not hash_to_verify:
            return jsonify({'error': 'Missing required parameters'}), 400
            
        is_match = SHA1Hash.verify_hash(text, hash_to_verify)
        return jsonify({'match': is_match})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sha256', methods=['GET', 'POST'])
def sha256():
    contents = {
        'id': "#sha256",
        'title': "SHA-256",
        'type': "Hash",
    }
    return render_template("sha256.html", contents=contents)

@app.route('/sha256-hash', methods=['POST'])
def sha256_hash():
    if request.method == 'POST':
        text = request.form.get('text-input')
        hash_result = SHA256Hash.generate_hash(text)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'text': text,
                'hash': hash_result
            })
    
    return redirect(url_for('sha256'))

@app.route('/verify-sha256', methods=['POST'])
def verify_sha256():
    try:
        data = request.get_json()
        text = data.get('text')
        hash_to_verify = data.get('hash')
        
        if not text or not hash_to_verify:
            return jsonify({'error': 'Missing required parameters'}), 400
            
        is_match = SHA256Hash.verify_hash(text, hash_to_verify)
        return jsonify({'match': is_match})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sha512', methods=['GET', 'POST'])
def sha512():
    contents = {
        'id': "#sha512",
        'title': "SHA-512",
        'type': "Hash",
    }
    return render_template("sha512.html", contents=contents)

@app.route('/sha512-hash', methods=['POST'])
def sha512_hash():
    if request.method == 'POST':
        text = request.form.get('text-input')
        hash_result = SHA512Hash.generate_hash(text)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'text': text,
                'hash': hash_result
            })
    
    return redirect(url_for('sha512'))

@app.route('/verify-sha512', methods=['POST'])
def verify_sha512():
    try:
        data = request.get_json()
        text = data.get('text')
        hash_to_verify = data.get('hash')
        
        if not text or not hash_to_verify:
            return jsonify({'error': 'Missing required parameters'}), 400
            
        is_match = SHA512Hash.verify_hash(text, hash_to_verify)
        return jsonify({'match': is_match})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
