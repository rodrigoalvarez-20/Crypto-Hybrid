from utils.cipher import decipher_aes, decipher_rsa, get_keys
import os

def select_file(message):
    sel_file = input(message)

    if not os.path.isfile(sel_file):
        print("No se ha encontrado el archivo")
        select_file(message)
    
    return sel_file

def get_file_content_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def save_contents_to_file(file_path, content):
    with open(file_path, "w") as f:
        f.write(content)

def process_decrypt(file_contents):
    file_plain = file_contents.decode()
    cipher_parts = file_plain.split("\n==🔒==\n")
    if len(cipher_parts) == 1:
            #No hay un valor cifrado
        print("El archivo no contiene un texto cifrado")
        return None
        
    cipher_body = cipher_parts[1].split("\n==🗝==\n")[0] # Descifrar con aes
    cipher_key = cipher_parts[1].split("\n==🗝==\n")[1].split("\n==🔐==\n")[0] # Descifrar con RSA, este es el vector de inicializacion
    priv_key, _ = get_keys()
    iv = decipher_rsa(priv_key.encode(), cipher_key)
    plain_text = decipher_aes(iv, cipher_body)
    return plain_text
    
