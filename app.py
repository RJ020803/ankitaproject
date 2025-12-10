import os
from io import BytesIO
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from cryptography.fernet import Fernet, InvalidToken
from encrypt import encrypt_bytes, decrypt_bytes, detect_image_extension

app = Flask(__name__)
app.secret_key = os.urandom(24)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    file = request.files.get("image")
    key_option = request.form.get("key_option")
    provided_key = request.form.get("key") or ""

    if not file or file.filename == "":
        flash("Please choose an image file to encrypt.")
        return redirect(url_for("index"))

    data = file.read()

    if key_option == "generate":
        key = Fernet.generate_key()
    else:
        if not provided_key:
            flash("Please provide a valid key or choose to generate one.")
            return redirect(url_for("index"))
        key = provided_key.encode()

    token = encrypt_bytes(data, key)

    out_name = file.filename + ".encrypted"
    return render_template("result.html",
                           action="encrypt",
                           key=key.decode(),
                           filename=out_name,
                           filedata=token.hex())


@app.route("/download_encrypted/<hexdata>/<filename>")
def download_encrypted(hexdata, filename):
    try:
        data = bytes.fromhex(hexdata)
    except Exception:
        flash("Invalid data for download.")
        return redirect(url_for("index"))

    return send_file(BytesIO(data), as_attachment=True, download_name=filename)


@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    file = request.files.get("enc_file")
    provided_key = request.form.get("dkey") or ""

    if not file or file.filename == "":
        flash("Please choose an encrypted file to decrypt.")
        return redirect(url_for("index"))

    if not provided_key:
        flash("Please provide the encryption key used to encrypt the file.")
        return redirect(url_for("index"))

    token = file.read()
    key = provided_key.encode()

    try:
        data = decrypt_bytes(token, key)
    except InvalidToken:
        flash("Decryption failed: invalid key or corrupted file.")
        return redirect(url_for("index"))

    ext = detect_image_extension(data) or "png"
    out_name = os.path.splitext(file.filename)[0] + f".decrypted.{ext}"

    return send_file(BytesIO(data), as_attachment=True, download_name=out_name, mimetype=f"image/{ext}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
