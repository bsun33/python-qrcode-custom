import qrcode
import base64, hashlib
import os
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.colormasks import SolidFillColorMask
from qrcode.image.styles.colormasks import SolidFillColorMask_Customized
from binascii import hexlify
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def gen_fernet_key(password:bytes) -> bytes:
        assert isinstance(password, bytes)
        hlib = hashlib.md5()
        hlib.update(password)
        return base64.urlsafe_b64encode(hlib.hexdigest().encode('latin-1'))

qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)

pwd = "red-blue-green-yellow"
key = gen_fernet_key(pwd.encode('utf-8'))
fernet = Fernet(key)
token = fernet.encrypt(b"Every one is unique!")

qr.add_data(token)
qr.make(fit=True)

img = qr.make_image(image_factory=StyledPilImage, color_mask=SolidFillColorMask_Customized())

type(img)  # qrcode.image.pil.PilImage
img.save("color.png")

print(img.getcolors(256))

qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(token)
qr.make(fit=True)

img = qr.make_image(image_factory=StyledPilImage, color_mask=SolidFillColorMask())

type(img)  # qrcode.image.pil.PilImage
img.save("black_white.png")

print("======")
print(img.getcolors(256))
