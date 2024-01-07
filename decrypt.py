import PySimpleGUI as sg
import base64, hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def gen_fernet_key(password:bytes) -> bytes:
        assert isinstance(password, bytes)
        hlib = hashlib.md5()
        hlib.update(password)
        return base64.urlsafe_b64encode(hlib.hexdigest().encode('latin-1'))

pwd = "red-blue-green-yellow"
key = gen_fernet_key(pwd.encode('utf-8'))
fernet = Fernet(key)

def if_decrypt(image):
     colors = image.getcolors(256)
     for color in colors:
          x, y = color
          r, g, b = y
          if r == 0 and g == 0 and b == 0:
               return False
     return True

def decode_qr_codes(file_path):
    from pyzbar.pyzbar import decode
    from PIL import Image

    image = Image.open(file_path)
    d = decode(image)

    text_in_file = d[0].data.decode('ascii')
    if if_decrypt(image):
         text_in_file = fernet.decrypt(text_in_file).decode('utf-8')

    sg.popup(f'Msg:\t\t\t{text_in_file}\n')


layout = [ [sg.Text('find the file')],
            [sg.Input(), sg.FileBrowse(button_text='select file')],
            [sg.OK()]]


window = sg.Window("QR code scanner").Layout(layout)

# Event Loop to process "events" and get the "values" of the inputs
while True:
    event, values = window.read()
    if event in (None, 'OK'):	# if user closes window or clicks cancel
        file = values[0]
        break

decode_qr_codes(file)
