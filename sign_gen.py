import numpy as np
from Crypto.Hash import SHAKE256
from keygen import FindPk1, FindPk2, squeeze_public_map, squeeze_T, BuildAugmentedMatrix, get_parameters

# Cargar parámetros desde el archivo params.json
params = get_parameters()
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
    input_to_hash = message + b'\x00' + salt + m.to_bytes(4, byteorder='big')
    hash_output = H(input_to_hash)

    bits_needed = m * r  # Total de bits necesarios
    digest_bits = int.from_bytes(hash_output, byteorder='big')

    hash_vector = []
    for i in range(bits_needed):
        bit = (digest_bits >> i) & 1  # Extraer el bit i
        hash_vector.append(bit)

    return np.array(hash_vector)  # Convertir a un array de NumPy para facilitar su uso

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
        # Aquí debes implementar la lógica para verificar la unicidad
        if F(v_random | o) == h:  # Asegúrate de que F esté implementado correctamente
            break

    # Procesar el resultado para obtener la firma
    s = (np.concatenate((np.eye(1), -T)), v_random)  # Cambia esta lógica según sea necesario
    
    return s, salt

# Implementación de BuildAugmentedMatrix
def BuildAugmentedMatrix(C, L, Q1, T, h, v):
    """
    Construye la matriz aumentada para el sistema lineal F(v||0) = h.
    
    :param C: Parte constante del mapa público P
    :param L: Parte lineal del mapa público P
    :param Q1: Parte cuadrática del mapa público P
    :param T: Matriz de transformación lineal
    :param h: Hash digest
    :param v: Asignación a las variables de vinagre
    :return: LHS || RHS - La matriz aumentada
    """
    # Inicialización de las matrices
    RHS = h - C - L @ (np.concatenate((v, np.zeros(1))))  # RHS del sistema
    LHS = np.zeros((m, m + 1), dtype=int)  # LHS inicializada

    for k in range(1, m + 1):
        Pk1 = FindPk1(k, Q1, v)
        Pk2 = FindPk2(k, Q1, v, m)

        # Evaluar términos de fk que son cuadráticos en variables de vinagre
        RHS[k - 1] -= v @ Pk1

        # Términos que son bilineales en las variables de vinagre y las variables de aceite
        Fk2 = (Pk1 + Pk1.T) @ T + Pk2
        LHS[k - 1] += Fk2

    return LHS, RHS

# Función para validar la firma (puedes agregarla si es necesaria)
def verify_signature(message, signature, public_key):
    """
    Verifica la firma digital del mensaje dado utilizando la clave pública.
    
    :param message: Mensaje que fue firmado
    :param signature: Firma a verificar
    :param public_key: Clave pública utilizada para la verificación
    :return: True si la firma es válida, False de lo contrario
    """
    # Para el proyecto 3, esta función no es necesaria aun y no se implementará
    pass