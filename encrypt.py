from cryptography.fernet import Fernet
import imghdr


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_bytes(token: bytes, key: bytes) -> bytes:
    f = Fernet(key)
    return f.decrypt(token)


def detect_image_extension(data: bytes) -> str | None:
    kind = imghdr.what(None, h=data)
    if kind == 'jpeg':
        return 'jpeg'
    return kind
