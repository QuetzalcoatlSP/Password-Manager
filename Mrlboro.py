
import os
from cryptography.fernet import Fernet

def cargar_o_crear_clave():
    if not os.path.exists("master.key"):
        clave = Fernet.generate_key()
        with open("master.key", "wb") as archivo_clave:
            archivo_clave.write(clave)
    else:
        with open("master.key", "rb") as archivo_clave:
            clave = archivo_clave.read()
    return clave

def guardar_password(servicio, usuario, password, f):
    token = f.encrypt(password.encode())
    with open("passwords.txt", "a") as archivo:
        archivo.write(f"{servicio}|{usuario}|{token.decode()}\n")

def consultar_passwords(f):
    if not os.path.exists("passwords.txt"):
        print("\nNo hay contraseñas guardadas.")
        return
    
    with open("passwords.txt", "r") as archivo:
        print("\n--- Tus Credenciales ---")
        for linea in archivo:
            datos = linea.strip().split("|")
            if len(datos) == 3:
                serv, usu, token = datos
                pass_decifrada = f.decrypt(token.encode()).decode()
                print(f"Servicio: {serv} | Usuario: {usu} | Password: {pass_decifrada}")

def ejecutar():
    clave = cargar_o_crear_clave()
    f = Fernet(clave)
    
    while True:
        print("\n1. Guardar nueva contraseña")
        print("2. Ver contraseñas guardadas")
        print("3. Salir")
        opcion = input("Selecciona una opción: ")
        
        if opcion == "1":
            ser = input("Servicio: ")
            usu = input("Usuario: ")
            pas = input("Contraseña: ")
            guardar_password(ser, usu, pas, f)
            print("Guardado con éxito.")
        elif opcion == "2":
            consultar_passwords(f)
        elif opcion == "3":
            break
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    ejecutar()