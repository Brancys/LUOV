import numpy as np

def GaussianElimination(matrix):
    """
    Applies Gaussian elimination with partial pivoting to solve a system of linear equations.
    
    Args:
    - matrix (list of lists): Augmented matrix representing the system of equations.
    
    Returns:
    - list or None: Solution vector if a unique solution exists, otherwise None.
    """
    # Convert the matrix to a numpy array for easier manipulation
    matrix = np.array(matrix, dtype=np.float64)
    rows, cols = matrix.shape

    for i in range(min(rows, cols - 1)):
        # Partial pivoting: Find the maximum element in the current column
        max_row = i + np.argmax(abs(matrix[i:, i]))
        if matrix[max_row, i] == 0:
            continue  # If pivot is zero, skip to the next column
        # Swap the current row with the max_row for numerical stability
        matrix[[i, max_row]] = matrix[[max_row, i]]
        
        # Normalize the pivot row
        matrix[i] = matrix[i] / matrix[i, i]
        
        # Eliminate all entries below the pivot
        for j in range(i + 1, rows):
            matrix[j] = matrix[j] - matrix[j, i] * matrix[i]

    # Back-substitution to solve for the solution vector
    solution = np.zeros(cols - 1, dtype=np.float64)
    for i in range(rows - 1, -1, -1):
        if matrix[i, i] == 0:
            if matrix[i, -1] != 0:
                return None  # No solution
            continue  # Skip row if it's all zeros (free variable)
        solution[i] = matrix[i, -1] - np.dot(matrix[i, i+1:cols-1], solution[i+1:])

    return solution
