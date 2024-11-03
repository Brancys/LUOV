import numpy as np
import json
from Crypto.Hash import SHAKE256
from keygen import FindPk1, FindPk2, initialize_and_absorb, squeeze_public_seed, initialize_public_sponge

# Cargar parámetros desde el archivo params.json
with open("params.json", "r") as f:
    params = json.load(f)
    
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

def squeeze_T(private_seed, v, m):
    """Genera la matriz T de tamaño v x m a partir de la semilla privada."""
    # Inicializa la esponja con la semilla privada
    sponge = SHAKE256.new()
    sponge.update(private_seed)  # Actualiza la esponja con la semilla privada

    total_bytes = v * m  # Número total de bytes necesarios para una matriz de tamaño v x m
    T_bytes = sponge.read(total_bytes)  # Leer los bytes correspondientes
    
    # Convertir los bytes en una matriz de NumPy con dimensiones v x m
    T = np.frombuffer(T_bytes, dtype=np.uint8).reshape((v, m))
    
    return T

def squeeze_public_map(public_sponge, v, m):
    C = public_sponge.read(32)

    # Leer suficientes bytes para L
    L_bytes = public_sponge.read(m * m)  # Asumiendo que L debería ser de forma (m, m)

    # Asegúrate de que tienes suficientes bytes
    if len(L_bytes) < m * m:
        raise ValueError("No se han leído suficientes bytes para L.")
    
    # Convertir L a un array de NumPy con la forma correcta
    L = np.frombuffer(L_bytes, dtype=np.uint8).reshape((m, m))  # Cambia la forma según sea necesario

    # Verificación de la forma de L
    print(f"L shape after reshaping: {L.shape}")  # Debugging line to check the shape of L

    # Calculamos el tamaño esperado para Q1 basado en los valores de m y v
    q1_size = (v * (v + 1)) // 2 + (v * m)

    # Extraemos los bytes para Q1 desde el public_sponge
    Q1_bytes = public_sponge.read(q1_size * m)
    
    # Transformamos los bytes en una matriz de NumPy de forma (m, q1_size)
    Q1 = np.frombuffer(Q1_bytes, dtype=np.uint8).reshape((m, q1_size))

    return C, L, Q1

def hash_digest(message, salt):
    """Genera el digest del hash para el mensaje y el salt."""
    concatenated = message + salt  # Concatenar mensaje y salt

    # Generar el hash usando SHAKE256
    hash_output = H(concatenated)  # Obtener el hash
    hash_size = (m * r) // 8  # Ajusta el tamaño según sea necesario

    # Asegúrate de que el hash sea del tipo correcto
    h = np.frombuffer(hash_output, dtype=np.uint8)[:hash_size]  # Convertir a uint8 y ajustar tamaño
    return h

def sign(message, private_seed):
    """
    Genera una firma digital para el mensaje dado utilizando la clave privada.
    
    :param message: Mensaje a firmar (debe ser una cadena de bytes)
    :param private_seed: Clave privada utilizada para firmar
    :return: (s, salt) - Firma generada y salt utilizado
    """
    public_seed = H(private_seed)  # Generar la semilla pública

    # Inicializar la esponja pública con la semilla pública
    public_sponge = SHAKE256.new()
    public_sponge.update(public_seed)

   # Obtener el mapa público
    C, L, Q1 = squeeze_public_map(public_sponge, v, m)

    # Imprimir las formas para depuración
    print(f"C shape: {len(C)}, L shape: {L.shape}, Q1 shape: {Q1.shape}")

    # Generar un salt aleatorio
    salt = np.random.bytes(16)

    while True:
        # Generar un vector v aleatorio como un array de bytes
        v_random = np.random.bytes((v * r) // 8)  # Cambia según la longitud necesaria
        
        # Convertir v_random a un array de NumPy
        v_random = np.frombuffer(v_random, dtype=np.uint8)  # Convertir bytes a uint8

        # Calcular el hash digest del mensaje
        h = hash_digest(message, salt)  # Calcular h utilizando la función hash_digest

        # Construir la matriz aumentada
        T = squeeze_T(private_seed, v, m)  # Asegúrate de que private_seed es de tipo bytes
        A = BuildAugmentedMatrix(C, L, Q1, T, h, v_random)  # Asegúrate de que v_random es un array

        # Verificar si el sistema tiene una solución única
        # Aquí debes implementar la lógica para verificar la unicidad
        if F(v_random | o) == h:  # Asegúrate de que F esté implementado correctamente
            break

    # Procesar el resultado para obtener la firma
    s = (np.concatenate((np.eye(1), -T)), v_random)  # Cambia esta lógica según sea necesario
    
    return s, salt

# Función para construir la matriz aumentada
def BuildAugmentedMatrix(C, L, Q1, T, h, v):
    # Asegúrate de que todas las dimensiones sean correctas
    print(f"Shape of h: {h.shape}, Shape of C: {len(C)}, Shape of L: {L.shape}, Shape of v: {v.shape}")

    # Convertir h y C a un array de la misma forma
    if h.shape[0] != len(C):
        raise ValueError(f"Dimension mismatch: h has shape {h.shape}, C has length {len(C)}")

    # Expandir h y C si es necesario
    h_expanded = np.tile(h, (L.shape[0], 1)).flatten()  # Expandir h
    C_expanded = np.tile(C, (L.shape[0], 1)).flatten()  # Expandir C

    # Asegúrate de que v tenga la forma correcta
    if v.ndim == 1:  # Si v es un vector, lo convertimos en matriz columna
        v = v.reshape(-1, 1)

    # Verificar la forma de concatenated_v
    concatenated_v = np.concatenate((v.flatten(), np.zeros(1, dtype=v.dtype)))  # Convertir a 1D
    print(f"Shape of concatenated_v: {concatenated_v.shape}")

    # Verificar si L puede multiplicarse por concatenated_v
    if L.shape[1] != concatenated_v.shape[0]:
        raise ValueError("Las dimensiones no son compatibles con la multiplicación de matrices.")

    # RHS del sistema
    RHS = h_expanded - C_expanded - (L @ concatenated_v)

    return RHS  # o cualquier otra matriz que estés construyendo