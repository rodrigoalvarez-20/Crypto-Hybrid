from base64 import b64decode, b64encode
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature


from hashlib import md5

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

KEYS_PATH = f"{os.getcwd()}/keys"
AES_KEY = md5("CRYP70".encode('utf8')).digest()

def generate_keys():
    # Creamos el directorio si es que no existe
    if not os.path.isdir(KEYS_PATH):
        print("Generating Keys folder")
        os.mkdir(KEYS_PATH)

    # Eliminamos los contenidos del directorio
    for f in os.listdir(KEYS_PATH):
        os.remove(os.path.join(KEYS_PATH, f))

    """
    Función que permite generar un par de claves (publica y privada) en la carpeta "keys"
    Si se desea regenerar estos archivos, simplemente basta con borrarlos de la carpeta y ejecutar esta función
    """
    # Se utiliza RSA para la generación de llaves, se tiene un exponente arbitrario bastante grande y 
    # el tamaño de la llave es de 1024 bits
    key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)
    # Se genera una llave privada en formato PEM, esto con la finalidad de poder leer el archivo de una manera más facil
    encrypted_pem_private_key = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

    # A partir del valor de la llave privada obtenida, se genera una llave publica, con el mismo formato PEM
    pem_public_key = key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    pk_path = KEYS_PATH + "/private.pem"
    pub_path = KEYS_PATH + "/public.pem"

    with open(pk_path, "w") as pKey:
        pKey.write(encrypted_pem_private_key.decode("utf-8"))
    
    # Guardamos los bytes obtenidos de la llave publica a un archivo
    with open(pub_path, "w") as pubKey:
        pubKey.write(pem_public_key.decode("utf-8"))

def get_keys():
    """
    Función que permite obtener los datos de ambas llaves.
    Primero se abre la llave privada y a partir de ella, se obtiene la llave publica
    @return private_key_str: Cadena con el valor de nuestra llave privada
    @return public_key_str: Cadena con el valor de nuestra llave publica
    """
    # Se debe de abrir el archivo de la llave privada
    with open(KEYS_PATH + "/private.pem", "rb") as pKey:
        # Se carga los datos de la llave (PEM) 
        private_key = serialization.load_pem_private_key(pKey.read(), password=None)
        # A partir de estos datos obtenidos, se genera la llave publica
        pub_key = private_key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        # Se debe de obtener los bytes de nuestra llave privada
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        private_key_str = pem.decode('utf-8') # Ya que los valores obtenidos vienen en bytes, se hace un decode
        public_key_str = pub_key.decode('utf-8')
        return private_key_str, public_key_str

def cipher_aes(data):
    aes = AES.new(AES_KEY, AES.MODE_CBC)
    cipher_content = aes.encrypt(pad(data, AES.block_size))
    return  b64encode(cipher_content), b64encode(aes.iv)

def decipher_aes(iv, data):
    raw = b64decode(data)
    init_vect = b64decode(iv)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, init_vect)
    return unpad(cipher.decrypt(raw), AES.block_size)

def cipher_rsa(key_data, data):
    # Cargar la llave y cifrar los datos
    key = RSA.import_key(key_data)
    return b64encode(PKCS1_OAEP.new(key).encrypt(data))

def decipher_rsa(key_data, data):
    decoded_data = b64decode(data)
    key = RSA.import_key(key_data)
    return PKCS1_OAEP.new(key).decrypt(decoded_data)

def sign(value, key_data) -> tuple:
    """
    Función que permite firmar un valor dado.
    Para esto se ocupa la llave privada de quien está firmando
    @param value: Valor en cadena que se desea firmar
    @param key_path: Ruta de la llave a utilizar
    @return Tuple: Una tupla de valores (Codigo de estado, Mensaje/Error)
    """
    try:
        # Se abre la llave privada en modo binario
        # Se hace la carga de la llave privada (se convierten los bytes del archivo a una instancia de llave privada)
        private = serialization.load_pem_private_key(key_data, backend=default_backend(), password=None)
        # Mediante la función SIGN y un padding adecuado, se genera la firma de dicho texto o valor
        # Cabe decir que se ha ocupado el SHA256, por su seguridad
        signed_hash = private.sign(value, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())
        return ("ok",  b64encode(signed_hash))
    except UnsupportedAlgorithm:
        print("La llave de firma es incorrecta para el modo de operacion")
        return ("error", "La llave de firma es incorrecta para el modo de operacion")
    except ValueError:
        print("Error al generar la firma")
        return ("error", "Error al generar la firma")

def verify_sign(plain_value, sign_value, key_data) -> tuple:
    try:
        public = serialization.load_pem_public_key(key_data, backend=default_backend())
        public.verify(signature=sign_value, data=plain_value, padding= padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),algorithm=hashes.SHA256())
        return ("ok", "Los hashes coinciden")
    except InvalidSignature as ex:
        print(ex)
        return ("error", "La firma es inválida")
    except ValueError:
        print("La llave seleccionada no coincide con el formato para verificar (PRIVATE_KEY_SELECTED)")
        return ("error", "La llave seleccionada no coincide con el formato necesario (PRIVATE_KEY_SELECTED)")

if __name__ == "__main__":
    get_keys()