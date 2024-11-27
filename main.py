from keygen import keygen_luov
from sign_gen import sign
from verify import verify
import json, os

# Cargar parámetros desde el archivo params.json
with open("params.json", "r") as f:
    params = json.load(f)
    
# Parámetros para LUOV
r = params['r']
m = params['m']
v = params['v']
print(f" Parametros: r = {r}, m = {m}, v = {v}")

n = m + v

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

private_seed = load_private_seed(f"keys/LUOV_{r}_{m}_{v}")
print("Private seed loaded: ", private_seed)

# Firmar un mensaje
message = "Este es un mensaje de prueba que quiero firmar.".encode('utf-8')
print("Generando firma para el mensaje: ", message)
signature, salt = sign(private_seed, message, m, v, r, n)
print("Firma generada: ", signature)
print("Salt utilizado: ", salt)


# Verificar la firma
print("Verificando firma...")
verification = verify(private_seed, message,signature, salt, r,m,v,1)
print(f'Firma correcta? : {verification}')