from keygen import keygen_luov
from sign_gen import sign, verify_signature

# Ejeutar la generación de claves
keygen_luov()

# Firmar un mensaje
message = "Este es un mensaje de prueba que quiero firmar.".encode('utf-8')
private_seed = b"private_seed"
signature = sign(message, private_seed)