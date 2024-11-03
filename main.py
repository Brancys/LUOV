from keygen import keygen_luov
from sign_gen import sign
import json, os

# Cargar parámetros desde el archivo params.json
with open("params.json", "r") as f:
    params = json.load(f)
    
# Parámetros para LUOV
r = params['r']
m = params['m']
v = params['v']

def load_private_seed(folder_name):
  # Ruta al archivo de la clave secreta
  sk_file_path = os.path.join(folder_name, "sk.txt")

  # Leer el contenido del archivo
  with open(sk_file_path, "rb") as sk_file:
    private_seed = sk_file.read()  # Leer la clave secreta como bytes

  return private_seed

# Ejeutar la generación de claves
# keygen_luov() 
# Las claves ya están generadas

folder_name = f"keys/LUOV_{r}_{m}_{v}"

# Firmar un mensaje
private_seed = load_private_seed(folder_name)
message = "Este es un mensaje de prueba que quiero firmar.".encode('utf-8')

signature, salt = sign(message, private_seed)

# Mostrar la firma y el salt
print("Firma generada: ", signature)
print("Salt utilizado: ", salt)