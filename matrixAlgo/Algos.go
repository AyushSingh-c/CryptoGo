package matrixAlgo

import (
	"fmt"
	"math/big"
)

// gives C=AB%p for big int matrices
func MultiplyMatricesModP(MatrixA [][]*big.Int, MatrixB [][]*big.Int, p ...*big.Int) ([][]*big.Int, error) {
	var (
		prod = big.NewInt(1)
		An   = len(MatrixA)
		Am   = len(MatrixA[0])
		Bn   = len(MatrixB)
		Bm   = len(MatrixB[0])
	)
	if Am != Bn {
		return nil, fmt.Errorf("Matrices cannot be multiplied because of dimension mismatch")
	}
	MultipliedMatrix := make([][]*big.Int, An)
	for i := 0; i < An; i++ {
		MultipliedMatrix[i] = make([]*big.Int, Bm)
		for j := 0; j < Bm; j++ {
			MultipliedMatrix[i][j] = big.NewInt(0)
			for k := 0; k < Am; k++ {
				prod.Mul(MatrixA[i][k], MatrixB[k][j])
				MultipliedMatrix[i][j].Add(prod, MultipliedMatrix[i][j])
				if len(p) != 0 {
					MultipliedMatrix[i][j].Mod(MultipliedMatrix[i][j], p[0])
				}
			}
		}
	}
	return MultipliedMatrix, nil
}

func MakeIdentity(n int) [][]*big.Int {
	I := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		I[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			I[i][j] = big.NewInt(0)
			if i == j {
				I[i][j] = big.NewInt(1)
			}
		}
	}
	return I
}

func DeepCopyMatrix(src [][]*big.Int) [][]*big.Int {
	var (
		n = len(src)
		m = len(src[0])
	)
	dest := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		dest[i] = make([]*big.Int, m)
		for j := 0; j < m; j++ {
			dest[i][j] = new(big.Int).Set(src[i][j])
		}
	}
	return dest
}

// gives C=A^exp%p
func MatrixExponentiationModP(Matrix [][]*big.Int, exp *big.Int, p ...*big.Int) ([][]*big.Int, error) {
	var (
		tempExp = new(big.Int).Set(exp)
		mod     = big.NewInt(1)
		n       = len(Matrix)
		m       = len(Matrix[0])
		tempMat = DeepCopyMatrix(Matrix)
		result  = MakeIdentity(n)
	)
	if m != n {
		return nil, fmt.Errorf("Matrix is not a square matrix. Matrix dimensions are %dX%d", n, m)
	}

	if exp.Cmp(mod) == 0 {
		return tempMat, nil
	}

	for tempExp.Cmp(big.NewInt(0)) == 1 {
		if mod.Mod(tempExp, big.NewInt(2)).Cmp(big.NewInt(1)) == 0 {
			if len(p) != 0 {
				result, _ = MultiplyMatricesModP(result, tempMat, p[0])
			} else {
				result, _ = MultiplyMatricesModP(result, tempMat)
			}
		}
		if len(p) != 0 {
			tempMat, _ = MultiplyMatricesModP(tempMat, tempMat, p[0])
		} else {
			tempMat, _ = MultiplyMatricesModP(tempMat, tempMat)
		}
		tempExp.Div(tempExp, big.NewInt(2))
	}
	return result, nil
}
