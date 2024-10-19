import numpy as np
import json
from Crypto.Hash import SHAKE256
from keygen import FindPk1, FindPk2, squeeze_public_map, squeeze_T, BuildAugmentedMatrix  # Importar funciones necesarias

# Cargar parámetros desde el archivo params.json
with open("params.json", "r") as f:
    params = json.load(f)

# Parámetros para LUOV-7-83-283 desde params.json
r = params['r']  # Obtiene el valor de r
m = params['m']  # Obtiene el valor de m
v = params['v']  # Obtiene el valor de v

def H(private_seed):
    """
    Calcula la función hash H utilizando SHAKE256.
    
    :param private_seed: Clave privada
    :return: Salida de la función hash (32 bytes)
    """
    shake = SHAKE256.new()
    shake.update(private_seed)
    return shake.read(32)  # Devuelve los primeros 32 bytes como semilla pública

def hash_digest(message, salt):
    """
    Genera el hash digest para el mensaje dado y el salt.
    
    :param message: Mensaje que se va a firmar
    :param salt: Salt utilizado en el proceso
    :return: Vector de hash digest como elementos de F_2
    """
    input_to_hash = message + b'\x00' + salt + m.to_bytes(4, byteorder='big')  # Convertir m a bytes
    hash_output = H(input_to_hash)

    bits_needed = m * r  # Total de bits necesarios
    digest_bits = int.from_bytes(hash_output, byteorder='big')  # Convertir hash_output a un entero

    hash_vector = []
    for i in range(bits_needed):
        bit = (digest_bits >> i) & 1  # Extraer el bit i
        hash_vector.append(bit)

    return np.array(hash_vector)  # Convertir a un array de NumPy para facilitar su uso

def F(v):
    """
    Función F que representa el sistema de ecuaciones.
    
    :param v: Vector de variables
    :return: Resultado de la función F
    """
    # Implementar la lógica de la función F según el algoritmo
    pass

def sign(message, private_seed):
    """
    Genera una firma digital para el mensaje dado utilizando la clave privada.
    
    :param message: Mensaje a firmar (debe ser una cadena de bytes)
    :param private_seed: Clave privada utilizada para firmar
    :return: (s, salt) - Firma generada y salt utilizado
    """
    public_seed = H(private_seed)  # Generar la semilla pública
    C, L, Q1 = squeeze_public_map(public_seed, v, m)  # Obtener el mapa público

    # Generar un salt aleatorio
    salt = np.random.bytes(16)

    while True:
        # Generar un vector v aleatorio
        v_random = np.random.bytes((v * r) // 8)  # Cambia según la longitud necesaria
        
        # Calcular el hash digest del mensaje
        h = hash_digest(message, salt)  # Calcular h utilizando la función hash_digest

        # Construir la matriz aumentada
        T = squeeze_T(private_seed, v, m)  # Definir T aquí
        A = BuildAugmentedMatrix(C, L, Q1, T, h, v_random)
        
        # Verificar si el sistema tiene una solución única
        if F(v_random | o) == h:  # Asegúrate de que F esté implementado correctamente
            break

    # Procesar el resultado para obtener la firma
    s = (np.concatenate((np.eye(1), -T)), v_random)  # Cambia esta lógica según sea necesario
    
    return s, salt