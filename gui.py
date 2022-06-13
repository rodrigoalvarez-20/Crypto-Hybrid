from base64 import b64decode
from functools import partial
import os
from tkinter import CENTER, DISABLED, END, GROOVE, Checkbutton, IntVar, StringVar, Text, Tk, Frame, Label, filedialog, Button, TOP, LEFT, messagebox

from tkinter.font import NORMAL

from utils.cipher import cipher_aes, cipher_rsa, generate_keys, get_keys, sign, verify_sign
from utils.common import get_file_content_bytes, process_decrypt, save_contents_to_file
from utils.hashy import get_hash, get_hash_from_text

root = Tk()

# Valores globales
global file_path, key_path
file_path = ""
key_path = ""

# Valores para los checkboxes
cifrar_cb = IntVar()
firmar_cb = IntVar()
descifrar_cb = IntVar()
verificar_cb = IntVar()
file_name = StringVar()
key_name = StringVar()

cb_arr = [
    {
        "text": "Cifrar archivo",
        "var": cifrar_cb
    },
    {
        "text": "Firmar archivo",
        "var": firmar_cb
    },
    {
        "text": "Descifrar archivo",
        "var": descifrar_cb
    },
    {
        "text": "Verificar archivo",
        "var": verificar_cb
    }
]

root.geometry("740x780")
root.title("Cryptography")  # Titulo de la ventana

Tops = Frame(root, width=740, relief=GROOVE)  # Contenedor principal
Tops.pack(side=TOP)

f1 = Frame(root, width=740, height=780,
           relief=GROOVE)
f1.pack(side=LEFT)


def open_file(type, preview = None, label = None):
    file_types = (
        ('Text files', '*.txt'),
        ('PEM files', '*.pem'),
        ('Key files', '*.key'),
        ('All files', '*.*')
    )

    # Selector de archivos propio del S.O.
    f = filedialog.askopenfile(filetypes=file_types)
    global file_path, key_path
    if f is not None:  
        if type == "file":
            file_path = f.name
        elif type == "key":
            key_path = f.name

        file_name_parts = f.name.split("/")

        if preview != None:
            preview.config(state=NORMAL)
            preview.delete("1.0", END)
            preview.insert("1.0", f.read())
            preview.config(state=DISABLED)
        
        if label != None:
            if type == "file":
                file_name.set(file_name_parts[len(file_name_parts) - 1])
                label.config(textvariable=file_name)
            elif type == "key":
                key_name.set(file_name_parts[len(file_name_parts) - 1])
                label.config(textvariable=key_name)
            
    else:
        messagebox.showinfo("Advertencia", "No seleccionó ningun archivo")
        if type == "file":
            file_name.set("")
            label.config(textvariable= file_name)
            preview.config(state=NORMAL)
            preview.delete("1.0", END)
            preview.config(state=DISABLED)
        elif type == "key":
            key_name.set("")
            label.config(textvariable=key_name)

def handle_cb_change(button):
    if cifrar_cb.get() == 1 or descifrar_cb.get() == 1 or verificar_cb.get() == 1:
        button.config(state=NORMAL)
    else:
        button.config(state=DISABLED)

def start(preview = None):
    cb_values = [cb["var"].get() for cb in cb_arr]
    file_contents = get_file_content_bytes(file_path)
    out_data = file_contents.decode()
    generate_file = False
    
    if (cb_values[0] or cb_values[1]) and (cb_values[2] or cb_values[3]):
        messagebox.showerror("Error", "Solo se permite Cifrado/Firma o Descifrado/Verificacion a la vez")
        return 

    if cb_values[0]:
        # Se ha seleccionado Cifrado
        enc_data, iv = cipher_aes(file_contents)
        pub_key_data = get_file_content_bytes(key_path)
        iv_enc = cipher_rsa(pub_key_data, iv)
        out_data += "\n==🔒==\n"
        out_data += enc_data.decode()
        out_data += "\n==🗝==\n"
        out_data += iv_enc.decode()
        generate_file = True
    
    if cb_values[1]:
        file_digest = get_hash(file_path)
        priv_key, _ = get_keys()
        hsh_enc = sign(file_digest.encode(), priv_key.encode())
        if "error" in hsh_enc:
            print(hsh_enc[1])
            messagebox.showerror("Error", hsh_enc[1])
            exit(0)
        out_data += "\n==🔐==\n"
        out_data += hsh_enc[1].decode()
        generate_file = True

    if cb_values[2]:
        content = process_decrypt(file_contents)
        if content != None:
            save_contents_to_file("out.txt", content.decode())
            preview.config(state=NORMAL)
            preview.delete("1.0", END)
            preview.insert("1.0",content)
            preview.config(state=DISABLED)
        else:
            messagebox.showerror("Error", "Ha ocurrido un error al descifrar el texto")

    if cb_values[3]:
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
        public_key_data = get_file_content_bytes(key_path)
        signed_data = file_plain.split("\n==🔐==\n")[1].encode()
        signed_data = b64decode(signed_data)
        verify_data = verify_sign(
            original_hash.encode(), signed_data, public_key_data)

        messagebox.showinfo("Información", verify_data[1])

    if generate_file:
        file_parts = file_path.split(os.sep)
        file_name = file_parts[len(file_parts)-1]
        file_parts = file_name.split(".")
        out_file_name = file_parts[0] + "_enc." + file_parts[1]
        save_contents_to_file(out_file_name, out_data)
        preview.config(state=NORMAL)
        preview.delete("1.0", END)
        preview.insert("1.0", out_data)
        preview.config(state=DISABLED)
        messagebox.showinfo("Información", "Se ha generado el archivo de salida")

txtPreviewFile = Text(Tops, height=17)
lblFileName = Label(Tops, font=("helvetica", 18))
lblKeyName = Label(Tops, font=("helvetica", 18))
txtPreviewOutput = Text(Tops, height=17, state=DISABLED)
btnKey = Button(Tops, text="Abrir archivo", command=partial(
    open_file, "key", None, lblKeyName), state=DISABLED)

Label(Tops, font=('helvetica', 32, 'bold'),
    text="Criptografía híbrida", fg="Black", bd=10, anchor=CENTER).grid(row=0, column=0, columnspan=4)

Label(Tops, font=('helvetica', 24),
    text="Selecciona las acciones deseadas", fg="Black", bd=10, anchor=CENTER).grid(row=1, column=0, columnspan=4)

for i, cb in enumerate(cb_arr):
    _cb = Checkbutton(Tops, font=("helvetica", 18), text=cb["text"], fg="Black", anchor=CENTER, variable=cb["var"], command=partial(handle_cb_change, btnKey))
    _cb.grid(row=2, column=i, padx=12)

Label(Tops, font=("helvetica", 18),
    text="Selecciona el archivo a trabajar", anchor=CENTER).grid(row=3, column=0, columnspan=2, pady=6)

Button(Tops, text="Abrir archivo", command=partial(
    open_file, "file", txtPreviewFile, lblFileName)).grid(row=3, column=2, pady=6)

lblFileName.grid(row=3, column=3, pady=6)

txtPreviewFile.grid(row=5, column=0, columnspan=4)

Label(Tops, font=("helvetica", 18),
    text="Selecciona el archivo de llave a utilizar", anchor=CENTER).grid(row=4, column=0, columnspan=2, pady=6)

btnKey.grid(row=4, column=2, pady=6)

lblKeyName.grid(row=4, column=3, pady=6)

Label(Tops, font=("helvetica", 18),
    text="Salida", anchor=CENTER).grid(row=6, column=0, columnspan=2, pady=6)

txtPreviewOutput.grid(row=7, column=0, columnspan=4)

Button(Tops, text="(Re) Generar llaves", command=generate_keys).grid(row=8, column=0, pady=6)
Button(Tops, text="Iniciar",
    command=partial(start, txtPreviewOutput)).grid(row=8, column=1, pady=6)

root.mainloop()
