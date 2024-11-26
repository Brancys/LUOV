import numpy as np

def FindPk1(k, Q1, v):
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
    Pk2 = np.zeros((v, m), dtype=int)
    column = 0
    for i in range(v):
        column += v - i + 1  # Saltar términos de x_i^2 a x_ixv
        for j in range(m):
            if column < Q1.shape[1]:  # Verificar que column no exceda los límites de Q1
                Pk2[i, j] = Q1[k, column]
            column += 1
    return Pk2

def BuildAugmentedMatrix(C, L, Q1, T, h, v):
    m = len(h)
    Q1 = np.array(Q1)

    # Cambiamos el tipo de datos a int64 para evitar desbordamiento
    RHS = [int(h[i]) - int(C[i]) - sum(int(L[i][j]) * int(v[j] if j < len(v) else 0) for j in range(len(L[0])))
           for i in range(m)]
    
    # Crear la matriz LHS también con tipo de datos int64
    LHS = [[int(L[i][j]) - int(T[j % len(T)][i]) if j >= len(T) else int(L[i][j]) 
            for j in range(len(L[0]))] for i in range(m)]

    # Cambia el rango de k para que no exceda el número de filas de Q1
    for k in range(min(m, Q1.shape[0])):  # Asegurarse de que k no exceda las filas de Q1
        Pk_1 = FindPk1(k, Q1, len(v))
        Pk_2 = FindPk2(k, Q1, len(v), m)
        RHS[k] -= sum(int(v[i]) * int(Pk_1[i][j]) * int(v[j]) for i in range(len(v)) for j in range(len(v)))  
        Fk_2 = [[-int(Pk_1[i][j]) - int(Pk_1[j][i]) + int(Pk_2[i][j]) for j in range(m)] for i in range(len(v))]
        LHS[k] = [LHS[k][j] + sum(Fk_2[i][j] * v[i] for i in range(len(v))) for j in range(m)]
    
    LHS = np.array(LHS, dtype=np.int64)
    RHS = np.array(RHS, dtype=np.int64).reshape(-1, 1)
    augmented_matrix = np.hstack((LHS, RHS))

    return augmented_matrix
