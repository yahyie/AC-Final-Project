from flask import Flask, render_template, request, redirect, url_for, jsonify
from symmetric import CaesarCipher

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
    if request.method == 'POST':
        pass

    contents = {
        'id': "#vernam-cipher",
        'title': "Vernam Cipher",
        'type': "Symmetric",
    }

    return render_template("vernam.html", contents=contents)

@app.route('/block-cipher', methods=['GET', 'POST'])
def block_cipher():
    if request.method == 'POST':
        pass

    contents = {
        'id': "#block-cipher",
        'title': "Block Cipher",
        'type': "Symmetric",
    }

    return render_template("block.html", contents=contents)

@app.route('/rsa', methods=['GET', 'POST'])
def rsa_cipher():
    if request.method == 'POST':
        pass

    contents = {
        'id': "#rsa",
        'title': "RSA Cipher",
        'type': "Asymmetric",
    }

    return render_template("rsa.html", contents=contents)

@app.route('/diffie-hellman', methods=['GET', 'POST'])
def diffie_hellman():
    if request.method == 'POST':
        pass

    contents = {
        'id': "#diffie-hellman",
        'title': "Diffie-Hellman",
        'type': "Asymmetric",
    }

    return render_template("diffie-hellman.html", contents=contents)

@app.route('/md5', methods=['GET', 'POST'])
def md5():
    if request.method == 'POST':
        pass

    contents = {
        'id': "#md5",
        'title': "MD5",
        'type': "Hash",
    }

    return render_template("md5.html", contents=contents)

@app.route('/sha1', methods=['GET', 'POST'])
def sha1():
    if request.method == 'POST':
        pass

    contents = {
        'id': "#sha1",
        'title': "SHA-1",
        'type': "Hash",
    }

    return render_template("sha1.html", contents=contents)

@app.route('/sha256', methods=['GET', 'POST'])
def sha256():
    if request.method == 'POST':
        pass

    contents = {
        'id': "#sha256",
        'title': "SHA-256",
        'type': "Hash",
    }

    return render_template("sh256.html", contents=contents)

@app.route('/sha512', methods=['GET', 'POST'])
def sha512():
    if request.method == 'POST':
        pass

    contents = {
        'id': "#sha512",
        'title': "SHA-512",
        'type': "Hash",
    }

    return render_template("sha512.html", contents=contents)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
