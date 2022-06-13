import hashlib

# get hash from text in file
def get_hash(filename):
    """
    Función para generar un hash de los datos dentro de un archivo
    @param filename: Ruta del archivo a generar el hash
    @return str: Valor del digesto generado de los datos del archivo
    """
    h = hashlib.sha1() # Para fines de esta practica, se utiliza el algoritmo de SHA1
    b = bytearray(128*1024) # Esta variable nos permite definir el tamaño del bloque a partir del cual se iran generando los hashes
    mv = memoryview(b) # Utilizamos un memoryview para hacer mas rapida la manipulación de bytes del archivo
    with open(filename, 'rb', buffering=0) as f: # Abrimos el archivo
        for n in iter(lambda: f.readinto(mv), 0): # Se itera cada linea del archivo
            h.update(mv[:n]) # Se va actualizando el valor del hash
    return h.hexdigest() # Se regresa el digesto obtenido


def get_hash_from_text(text):
    h = hashlib.sha1() # Para fines de esta practica, se utiliza el algoritmo de SHA1
    h.update(text)
    return h.hexdigest()