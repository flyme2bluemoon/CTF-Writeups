import os

from Crypto.Cipher import AES
from hashlib import sha256, sha512
from base64 import b64encode
from Crypto.Util.Padding import pad, unpad

from jinja2 import Template

def encrypt(plaintext, passphrase):
    key = sha256(passphrase.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return b64encode(ciphertext).decode("utf-8")

with open("writeup.html", "r") as f:
    template = Template(f.read())

title = input("title: ")
passwd = input("passwd: ")

print(passwd == None)

js = ""
if passwd == "":
    passwd = "unlocked"
    js = "decrypt('unlocked');"

with open(f"src/{title}.md", "r") as f:
    md = f.read()

encrypted = encrypt(md, passwd)
passwd_hash = sha512(passwd.encode()).hexdigest()

os.system(f"mkdir {title}")

os.chdir(title)

with open(f"index.html", "w") as f:
    html = template.render(title=title, encrypted=encrypted, passwd_hash=passwd_hash, js=js)
    f.write(html)