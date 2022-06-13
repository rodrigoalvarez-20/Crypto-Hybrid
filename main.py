from base64 import b64decode
import os

from utils.cipher import cipher_aes, cipher_rsa, decipher_aes, decipher_rsa, generate_keys, get_keys, sign, verify_sign
from utils.common import get_file_content_bytes, process_decrypt, save_contents_to_file, select_file
from utils.hashy import get_hash, get_hash_from_text

def menu():
    print("Menu principal")
    print("="*20)
    print("1. (Re)Generar llaves")
    print("2. Cifrar")
    print("3. Firmar")
    print("4. Descifrar")
    print("5. Verificar")
    print("6. Salir")
    op_sel = input("Elige la(s) opcion(es): ")
    selected_options = op_sel.split(",")

    # Verificamos si ha seleccionado el re-generar claves
    if "1" in selected_options:
        generate_keys()
        exit(0)
    
    selected_file = select_file("Introduce la ruta del archivo a trabajar: ")
    file_contents = get_file_content_bytes(selected_file)
    out_data = file_contents.decode()
    generate_file = False

    if "2" in selected_options:
        # Cifrar contenido de out_data con AES cbc
        # Cifrar Con la llave publica del receptor los datos del vector de inicializacion, utilizando RSA
        enc_data, iv = cipher_aes(file_contents)
        public_rec_key = select_file("Introduce la ruta de la llave publica del receptor: ")
        pub_key_data = get_file_content_bytes(public_rec_key)
        iv_enc = cipher_rsa(pub_key_data, iv)

        out_data += "\n==🔒==\n"
        out_data += enc_data.decode()
        out_data += "\n==🗝==\n"
        out_data += iv_enc.decode()
        generate_file = True

    if "3" in selected_options:
        # firmar el contenido del mensaje original (Generar el hash y obtener el digesto), el hash se cifra con RSA utilizando mi privada
        file_digest = get_hash(selected_file)
        priv_key, _ = get_keys()
        hsh_enc = sign(file_digest.encode(), priv_key.encode())
        if "error" in hsh_enc:
            print(hsh_enc[1])
            exit(0) 
        out_data += "\n==🔐==\n"
        out_data += hsh_enc[1].decode()
        generate_file = True
    
    if "4" in selected_options:
        content = process_decrypt(file_contents)
        if content != None:
            save_contents_to_file("out.txt", content.decode())
    
    if "5" in selected_options:
        file_plain = file_contents.decode()
        has_cipher_value = file_plain.find("\n==🔒==\n")
        original_text = ""
        if has_cipher_value == -1:
            # No se ha encontrado el valor cifrado, obtener el valor en plano del archivo seleccionado
            original_text = file_plain.split("\n==🔐==\n")[0]
        else:
            original_text = process_decrypt(file_contents).decode()

        original_hash = get_hash_from_text(original_text.encode())
        # Solicitar la ruta de la llave a utilizar para verificar
        public_key_path = select_file("Introduzca la ruta de la llave a utilizar para la verificacion: ")
        public_key_data = get_file_content_bytes(public_key_path)
        signed_data = file_plain.split("\n==🔐==\n")[1].encode()
        signed_data = b64decode(signed_data)
        verify_data = verify_sign(original_hash.encode(), signed_data, public_key_data)

        print(verify_data[1])
        

    if generate_file:
        file_parts = selected_file.split(os.sep)
        file_name = file_parts[len(file_parts)-1]
        file_parts = file_name.split(".")
        out_file_name = file_parts[0] + "_enc." + file_parts[1]
        save_contents_to_file( out_file_name, out_data)
    

    

if __name__ == "__main__":
    menu()
