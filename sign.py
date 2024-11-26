from hashlib import shake_256
from hashlib import shake_128
import numpy as np
import os
from Func.BuildAugmentedMatrix import BuildAugmentedMatrix
from Func.generate_C_L_Q1 import generate_C_L_Q1
from Func.GaussianElimination import GaussianElimination


def H(private_seed, m, v):
    # Paso 1: Calcular la salida de hash con shake_256 de longitud 32 + ceil(m * v / 8) bytes
    output_length = 32 + ((m * v + 7) // 8)
    hash_output = shake_256(private_seed).digest(output_length)
    
    # Paso 2: Extraer los primeros 32 bytes como la public_seed
    public_seed = hash_output[:32]
    
    # Paso 3: Usar los siguientes ceil(m * v / 8) bytes para construir la matriz T
    T_bytes = hash_output[32:]
    T = []
    
    # Construir la matriz T de tamaño v x m en el campo F2
    bits_needed = m * v
    current_bit = 0
    row = []
    
    for byte in T_bytes:
        for bit in range(8):
            if current_bit < bits_needed:
                # Añadir el bit (byte >> (7 - bit)) & 1 a la fila actual
                row.append((byte >> (7 - bit)) & 1)
                current_bit += 1
                
                # Si la fila tiene m bits, agregarla a T y empezar una nueva fila
                if len(row) == m:
                    T.append(row)
                    row = []
            else:
                break
    
    return public_seed, T

def generate_salt(length=16):
    # Genera un salt de la longitud especificada (16 bytes por defecto)
    salt = os.urandom(length)
    return salt

def generate_hash_digest_H(message: bytes, salt: bytes, m: int, r: int):
    """
    Generates the hash digest h using the concatenation M || 0x00 || salt.

    Args:
        message (bytes): The message to be signed.
        salt (bytes): A random 16-byte salt.
        m (int): The number of polynomials in the public key.
        r (int): The degree of the field extension (bit length per element in F2^r).
        use_shake256 (bool): If True, uses SHAKE256; otherwise, uses SHAKE128.

    Returns:
        bytes: The hash digest interpreted as m elements of F2^r.
    """
    # Concatenate message, 0x00 byte, and salt
    concatenated_input = message + b'\x00' + salt
    
    # Choose SHAKE128 or SHAKE256 based on security requirements
    shake = shake_128()
    shake.update(concatenated_input)
    
    # Generate hash digest of the required length (mr bits or mr//8 bytes)
    output_length = (m * r) // 8  # Convert bits to bytes
    hash_digest = shake.digest(output_length)
    
    return hash_digest

def sign(private_seed: bytes, message_bytes: bytes, m: int, v: int, r: int, n: int):
    # Calcular public_seed y T
    public_seed, T = H(private_seed, m, v)

    # Convertir C, L y Q1 a arreglos de NumPy
    C, L, Q1 = generate_C_L_Q1(public_seed, m, n, v)


    # Generar un salt aleatorio
    salt = generate_salt()

    # Calcular el hash digest h
    hash_digest = generate_hash_digest_H(message_bytes, salt, m, r)
    hash_digest_int = [int(byte) for byte in hash_digest]
    

    i = 0
    # Repetir hasta encontrar una solución válida
    solution_found = False
    while not solution_found:
        print(f'Iteración {i}')
        i += 1
        
        # 6. Generar valores aleatorios para las variables de vinagre
        vinegar_variables = os.urandom(r * v // 8)
        vinegar_variables_int = [int(byte) for byte in vinegar_variables]

        
        # 7. Construir la matriz aumentada para el sistema lineal
        augmented_matrix = BuildAugmentedMatrix(C, L, Q1, T, hash_digest_int, vinegar_variables_int)

        # 8-9. Aplicar eliminación gaussiana en la matriz aumentada
        solution_vector = GaussianElimination(augmented_matrix)

        # 10-11. Si el sistema tiene una solución única, ensamblar s' = (v || o)
        if solution_vector is not None:
            oil_variables = solution_vector
            s_prime = np.concatenate((vinegar_variables, oil_variables))
            solution_found = True

    # 14. Calcular s = (1v -T 0 1m) * s'
    s = np.dot(np.block([[np.identity(v, dtype=int), -np.array(T, dtype=int)],
                         [np.zeros((m, v), dtype=int), np.identity(m, dtype=int)]]), s_prime)

    # Devolver la firma y el salt
    return s, salt


# # Ejemplo de uso
# private_seed = b'\x01' * 32  # Ejemplo de private_seed de 32 bytes

# # Parámetros de ejemplo
# r = 7
# m = 57
# v = 197
# n = m + v
# message = "Este es un mensaje de prueba que quiero firmar."
# message_bytes = message.encode('utf-8')

# # LUOV-7-57-197
# # LUOV-7-83-283 
# # LUOV-7-110-374

# sign(private_seed, message_bytes, m, v, r, n)