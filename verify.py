from sign import generate_hash_digest_H
import numpy as np
import galois

def decode_signature(signature:bytes,r:int)->np.ndarray:
  signature_without_salt = signature[:-16]
  signature_bits = ''
  for i in signature_without_salt:
    signature_bits+=int8_to_binString(i)
  signature_array = []
  while len(signature_bits)>r:
    signature_array.append(int(signature_bits[:r],2))
    signature_bits = signature_bits[r:]
  return np.array(signature_array)

def extract_seed_and_q2(public_key:bytes,m:int)->tuple[bytes,np.ndarray]:
  public_seed = public_key[:32]
  Q2_bytes = public_key[32:]
  Q2_bits = []
  for i in Q2_bytes:
    bits = int8_to_bits(i)
    bits.reverse()
    Q2_bits += int8_to_bits(i)
  Q2_bits = np.array(Q2_bits[:int(m*(m*(m+1)/2))])
  return public_seed,Q2_bits.reshape((m,int(m*(m+1)/2)),order='F')

def evaluatePublicMap(public_key:bytes,s:bytes,v:int,m:int,lvl:int,r:int):
  public_seed,Q2 = extract_seed_and_q2(public_key,m)
  GF = galois.GF(2**r)
  C,L,Q1 = G(v,m,lvl,public_seed)

  C = GF(C)
  L = GF(L)
  Q1 = GF(Q1)

  Q = np.concatenate([Q1,Q2],axis=1)

  s_decoded = GF(decode_signature(s,r))

  e = C + L@s_decoded
  column = 0
  n= m+v
  for i in range(n):
    for j in range(i,n):
      for k in range(m):
          e[k] = e[k]+Q[k,column]*s_decoded[i]*s_decoded[j]
      column+=1
  return e

def get_salt(signature:bytes)->bytes:
  return signature[-16:]

def verify(public_key: bytes, message: str, signature: bytes, salt: bytes, r: int, m: int, v: int, lvl: int) -> bool:
    """
    Verifica la validez de una firma candidata dada una clave pública y un mensaje.

    :param public_key: La clave pública en formato bytes.
    :param message: El mensaje que se firmó.
    :param candidate_signature: La firma candidata en formato bytes.
    :param v: Parámetro del esquema de firma.
    :param m: Parámetro del esquema de firma.
    :param lvl: Nivel del esquema de firma.
    :param r: Parámetro relacionado con el campo finito.
    
    :return: `True` si la firma es válida, `False` si no lo es.
    """
    
    # Crear el campo finito GF(2^r)
    GF = galois.GF(2**r)
    
    # Calcular el digest del mensaje con la función generate_hash_digest_H
    h = GF(generate_hash_digest_H(message, salt, m, lvl, r))
    
    # Evaluar el mapa público usando la clave pública y la firma candidata
    e = evaluatePublicMap(public_key, signature, v, m, lvl, r)
    
    # Verificar si el digest h coincide con la evaluación e
    return h == e