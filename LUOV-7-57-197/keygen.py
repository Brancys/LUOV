import binascii
import base64
from Crypto.Hash import SHAKE256
import os
import numpy as np

# Parámetros para LUOV-7-57-197
r = 7
m = 57
v = 197
shake_bits = 256
sig_size = 440  # bytes
pk_size_neto = 82
pk_size = pk_size_neto * 1024  # bytes (11.5 KB para la clave pública)
sk_size_kb = 32  # Tamaño de la clave privada en kilobytes (32 KB)
sk_size = sk_size_kb * 1024  # Tamaño en bytes (32 KB)
message_recovery_size = 32  # bytes

# Campo finito F_2 para operaciones
def gf2_add(a, b):
    return a ^ b

def gf2_mult(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
    return result

# Generador de SHAKE256 para bytes aleatorios
def shake256_random_bytes(output_length, seed=None):
    shake = SHAKE256.new()
    if seed:
        shake.update(seed)
    return shake.read(output_length)

def FindPk1(k, Q1, v):
    """
    Encuentra la matriz Pk,1 de tamaño v x v
    """
    Pk1 = np.zeros((v, v), dtype=int)
    column = 0
    for i in range(v):
        for j in range(i, v):
            if column < Q1.shape[1]:  # Verificar que column no exceda los límites de Q1
                Pk1[i, j] = Q1[k, column]
            column += 1
        column += v  # Saltar los términos xi*xv+1 hasta xi*xv+m
    return Pk1

def FindPk2(k, Q1, v, m):
    """
    Encuentra la matriz Pk,2 de tamaño v x m
    """
    Pk2 = np.zeros((v, m), dtype=int)
    column = 0
    for i in range(v):
        column += v - i + 1  # Saltar términos de x_i^2 a x_ixv
        for j in range(m):
            if column < Q1.shape[1]:  # Verificar que column no exceda los límites de Q1
                Pk2[i, j] = Q1[k, column]
            column += 1
    return Pk2

# Inicializar y absorber (Esponja privada)
def initialize_and_absorb(seed):
    sponge = SHAKE256.new()
    sponge.update(seed)
    return sponge

# Squeezing para obtener la semilla pública
def squeeze_public_seed(sponge):
    return sponge.read(32)

# Squeezing para obtener T
def squeeze_T(sponge, v, m):
    """Genera la matriz T de tamaño v x m a partir de la semilla privada."""
    total_bytes = v * m  # Número total de bytes necesarios para una matriz de tamaño v x m
    T_bytes = sponge.read(total_bytes)  # Leer los bytes correspondientes
    
    # Convertir los bytes en una matriz de NumPy con dimensiones v x m
    T = np.frombuffer(T_bytes, dtype=np.uint8).reshape((v, m))
    
    return T

# Inicializar la esponja pública
def initialize_public_sponge(public_seed):
    public_sponge = SHAKE256.new()
    public_sponge.update(public_seed)
    return public_sponge

# Squeezing para obtener el mapa público (C, L, Q1)
def squeeze_public_map(public_sponge):
    C = public_sponge.read(32)
    L = public_sponge.read(32)
    # Calcular el tamaño de Q1 dinámicamente
    q1_size = m * ((v * (v + 1) // 2) + (v * m))

    Q1_bytes = public_sponge.read(q1_size)
    Q1 = np.frombuffer(Q1_bytes, dtype=np.uint8).reshape((m, -1))  # Convertir a matriz de NumPy
    return C, L, Q1

def compute_Pk3(Pk1, Pk2, T):
    """
    Calcula la matriz Pk3 a partir de Pk1, Pk2 y T utilizando la fórmula:
    Pk3 = -T^T Pk1 T + T^T Pk2
    """
    # Calculamos los términos de la fórmula
    term1 = -T.T @ Pk1 @ T  # Primer término: -T^T Pk1 T
    term2 = T.T @ Pk2       # Segundo término: T^T Pk2

    # Sumamos ambos términos
    Pk3 = term1 + term2

    return Pk3


def find_Q2(Q1, T):
    """Genera la matriz Q2 basada en la matriz T y Q1, ajustada al tamaño esperado."""
    # Inicializamos Q2 como una matriz binaria con el tamaño correcto
    Q2 = np.zeros((m, (m * (m + 1)) // 2), dtype=int)

    for k in range(m):  # Corregido el rango para que coincida con la indexación en Python
        Pk1 = FindPk1(k, Q1, v)  # Corregido el orden de los argumentos
        Pk2 = FindPk2(k, Q1, v, m)  # Corregido el orden de los argumentos
        Pk3 = compute_Pk3(Pk1, Pk2, T)  # Asegúrate de tener la función `compute_Pk3`
        column = 0  # Corregido el valor inicial de column
        for i in range(m):
            Q2[k, column] = Pk3[i, i]  # Leer los elementos diagonales de Pk3
            column += 1
            for j in range(i + 1, m):
                Q2[k, column] = Pk3[i, j] + Pk3[j, i]  # Sumar los elementos fuera de la diagonal
                column += 1

    # Compactar Q2 usando numpy.packbits
    Q2_packed = np.packbits(Q2, axis=1)

    return Q2_packed

# Conversión de clave privada a hexadecimal
def private_key_to_hex(private_key):
    return binascii.hexlify(private_key).decode('utf-8')

# Conversión de clave privada a Base64
def private_key_to_base64(private_key):
    return base64.b64encode(private_key).decode('utf-8')

# Función para generar claves LUOV (Algoritmo keygen)
def keygen_luov():
    print("Generando claves LUOV...")

    # Paso 1: Generar semilla privada y esponja privada
    private_seed = shake256_random_bytes(sk_size)
    print(f"Semilla privada generada (tamaño: {len(private_seed)} bytes)")

    private_sponge = initialize_and_absorb(private_seed)

    # Paso 2: Generar semilla pública
    public_seed = squeeze_public_seed(private_sponge)
    print(f"Semilla pública generada (tamaño: {len(public_seed)} bytes)")

    # Paso 3: Generar valor intermedio T
    T = squeeze_T(private_sponge, v, m)  # Pasamos las dimensiones de T (v x m)
    print(f"Valor T generado (tamaño: {T.shape} bytes)")

    # Paso 4: Inicializar esponja pública con la semilla pública
    public_sponge = initialize_public_sponge(public_seed)

    # Paso 5: Generar mapa público (C, L, Q1)
    C, L, Q1 = squeeze_public_map(public_sponge)
    print(f"Mapa público generado: C (tamaño: {len(C)} bytes), L (tamaño: {len(L)} bytes), Q1 (tamaño: {len(Q1)} bytes)")

    # Paso 6: Calcular Q2 a partir de Q1 y T
    Q2 = find_Q2(Q1, T)
    print(f"Q2 generado (tamaño: {len(Q2)} bytes)")

    # Convertir Q2 a bytes
    Q2_bytes = Q2.tobytes()

    # Concatenar la semilla pública con Q2 (ahora en bytes)
    public_key = public_seed + Q2_bytes

    print(f"Clave pública seed: {len(public_seed)} bytes")
    print(f"Clave pública generada (tamaño: {len(public_key)} bytes)")

    # Guardar las claves en archivos
    try:
        with open("LUOV-7-57-197/sk.txt", "wb") as sk_file:
            sk_file.write(private_seed)
        print("Clave secreta guardada en 'sk.txt'")
    except Exception as e:
        print(f"Error guardando la clave secreta: {e}")

    try:
        with open("LUOV-7-57-197/pk.txt", "wb") as pk_file:
            pk_file.write(public_key)
        print("Clave pública guardada en 'pk.txt'")
    except Exception as e:
        print(f"Error guardando la clave pública: {e}")

    # Convertir clave privada a formato legible
    private_seed_hex = private_key_to_hex(private_seed)
    private_seed_base64 = private_key_to_base64(private_seed)

    # Imprimir la clave privada en distintos formatos
    print("Las claves han sido generadas y guardadas en archivos:")
    print("Clave secreta: 'clave_secreta_sk.txt'")
    print("Clave pública: 'clave_publica_pk.txt'")

    return private_seed, public_seed, Q2

# Ejecutar la función para generar las claves
keygen_luov()
