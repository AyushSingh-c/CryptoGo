package rsaDecrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"factordbapi"
	"fmt"
	"log"
	"math/big"
	"os"
)

type PublicInfo struct {
	N, C, E *big.Int
}

func CfExpansion(n, d *big.Int) []*big.Int {
	var (
		e    = []*big.Int{}
		q, r = big.NewInt(0), big.NewInt(0)
		N    = new(big.Int).Set(n)
		D    = new(big.Int).Set(d)
	)
	q.Div(N, D)
	r.Mod(N, D)
	e = append(e, new(big.Int).Set(q))

	for r.Cmp(big.NewInt(0)) != 0 {
		N.Set(D)
		D.Set(r)
		q.Div(N, D)
		r.Mod(N, D)
		e = append(e, new(big.Int).Set(q))
	}
	return e
}

func Convergents(n, d *big.Int) ([]*big.Int, []*big.Int) {
	cN, cD := []*big.Int{}, []*big.Int{}
	cE := CfExpansion(n, d)
	for i := 0; i < len(cE); i++ {
		ni := big.NewInt(0)
		di := big.NewInt(0)
		if i == 0 {
			ni = cE[i]
			di = big.NewInt(1)
		} else if i == 1 {
			ni.Mul(cE[i], cE[i-1])
			ni.Add(ni, big.NewInt(1))
			di = cE[i]
		} else {
			ni.Mul(cE[i], cN[i-1])
			ni.Add(ni, cN[i-2])
			di.Mul(cE[i], cD[i-1])
			di.Add(di, cD[i-2])
		}
		cN = append(cN, ni)
		cD = append(cD, di)
	}

	return cN, cD
}

func RootsFromPhi(Phi, N *big.Int) (*big.Int, *big.Int) {
	var (
		B     = big.NewInt(0)
		Det   = big.NewInt(0)
		root1 = big.NewInt(0)
		root2 = big.NewInt(0)
		temp  = big.NewInt(0)
	)

	B.Sub(Phi, N)
	B.Sub(B, big.NewInt(1))

	temp.Add(B, big.NewInt(2))
	temp.Mul(temp, temp)
	Det.Mul(big.NewInt(4), Phi)
	Det.Sub(temp, Det)
	if Det.Cmp(big.NewInt(0)) < 0 {
		return root1, root2
	}
	Det, _ = Kthroot_halley(big.NewInt(2), Det)
	root1.Add(B, Det)
	root2.Sub(Det, B)
	root1.Mul(root1, big.NewInt(-1))
	root1.Div(root1, big.NewInt(2))
	root2.Div(root2, big.NewInt(2))
	return root1, root2
}

func WienerAttack(rsaInfo PublicInfo) (*big.Int, error) {
	var (
		possibleK, possibleD = Convergents(rsaInfo.E, rsaInfo.N)
		possibleP, possibleQ = big.NewInt(0), big.NewInt(0)
		possiblePhi          = big.NewInt(0)
		temp                 = big.NewInt(0)
	)
	for i := 0; i < len(possibleK); i++ {
		if possibleK[i].Cmp(big.NewInt(0)) == 0 {
			continue
		}
		possiblePhi.Mul(rsaInfo.E, possibleD[i])
		possiblePhi.Sub(possiblePhi, big.NewInt(1))
		possiblePhi.Div(possiblePhi, possibleK[i])
		possibleP, possibleQ = RootsFromPhi(possiblePhi, rsaInfo.N)
		if rsaInfo.N.Cmp(temp.Mul(possibleP, possibleQ)) == 0 {
			break
		}
	}
	if rsaInfo.N.Cmp(temp.Mul(possibleP, possibleQ)) != 0 {
		return nil, fmt.Errorf("RSA public key is difficult to crack with Wiener Attack")
	}

	possibleP.Sub(possibleP, big.NewInt(1))
	possibleQ.Sub(possibleQ, big.NewInt(1))
	possiblePhi = new(big.Int).Mul(possibleP, possibleQ)

	// compute d = e^-1 mod phi(n)
	d, err := ModInverse(rsaInfo.E, possiblePhi)
	if err != nil {
		return nil, err
	}

	// compute m = c^d mod n
	m := new(big.Int).Exp(rsaInfo.C, d, rsaInfo.N)

	return m, nil
}

// ExtendedGCD returns the GCD and the Bézout coefficients of a and b
func ExtendedGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	// base case
	if b.Cmp(big.NewInt(0)) == 0 {
		return new(big.Int).Set(a), big.NewInt(1), big.NewInt(0)
	}
	// recursive case
	q := new(big.Int).Div(a, b)
	r := new(big.Int).Mod(a, b)
	gcd, x, y := ExtendedGCD(b, r)
	tmp := new(big.Int).Mul(q, y)
	x.Sub(x, tmp)
	return gcd, y, x
}

// ModInverse returns the modular inverse of a mod m
func ModInverse(a, m *big.Int) (*big.Int, error) {
	gcd, x, _ := ExtendedGCD(a, m)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("no inverse exists")
	}
	return x.Mod(x, m), nil
}

func isNormalRSAPublicKey(factors []factordbapi.Factor) (bool, *big.Int, *big.Int) {
	if len(factors) != 2 {
		return false, nil, nil
	}

	p, _ := new(big.Int).SetString(factors[0].Number, 10)
	q, _ := new(big.Int).SetString(factors[1].Number, 10)

	if p != nil && q != nil && factors[0].Power == 1 && factors[1].Power == 1 {
		return true, p, q
	}
	return false, nil, nil
}

// DecryptRSA decrypts a ciphertext using RSA parameters
func DecryptRSA_FactorN(rsaInfo PublicInfo) (*big.Int, error) {
	// check if n is p*q type
	factors, _ := factordbapi.GetFactors(rsaInfo.N.String())
	check, p, q := isNormalRSAPublicKey(factors)
	if !check {
		fmt.Println("No regular/easy RSA public key. Factors calculated are:")
		fmt.Println(factors)
		if len(factors) > 2 {
			return nil, fmt.Errorf("RSA public key is not in the form p*q")
		}
		return nil, fmt.Errorf("RSA public key is difficult to crack(factorize)")
	}
	// compute phi(n) = (p-1)*(q-1)
	p.Sub(p, big.NewInt(1))
	q.Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(p, q)

	// compute d = e^-1 mod phi(n)
	d, err := ModInverse(rsaInfo.E, phi)
	if err != nil {
		return nil, err
	}

	// compute m = c^d mod n
	m := new(big.Int).Exp(rsaInfo.C, d, rsaInfo.N)

	return m, nil
}

// return int closest to a^1/k
func Kthroot_newton(k *big.Int, a *big.Int) (cbrt *big.Int, count int) {
	step := func(k *big.Int, a *big.Int, x *big.Int) *big.Int {
		temp1 := big.NewInt(0)
		temp2 := big.NewInt(0)
		temp := big.NewInt(0)
		temp1.Sub(k, big.NewInt(1))
		temp2.Exp(x, temp1, nil)
		temp1.Mul(temp1, x)
		temp2.Div(a, temp2)
		temp.Add(temp1, temp2)
		temp.Div(temp, k)
		return temp // temp = (1.0/k)*((k-1)*x + a/math.Pow(x, k-1))
	}
	x := big.NewInt(1)
	y := step(k, a, x)
	count = 0
	for {
		x = y
		y = step(k, a, x)
		if x.Cmp(y) == 0 {
			break
		}
		count += 1
	}
	return x, count
}

// return int closest to a^1/k
func Kthroot_halley(k *big.Int, a *big.Int) (cbrt *big.Int, count int) {
	step := func(k *big.Int, a *big.Int, x *big.Int) *big.Int {
		var (
			temp1 = big.NewInt(0)
			temp2 = big.NewInt(0)
			temp  = big.NewInt(0)
			f     = big.NewInt(0)
			f1    = big.NewInt(0)
			f2    = big.NewInt(0)
		)

		f.Exp(x, temp.Sub(k, big.NewInt(2)), nil)
		f1.Mul(k, x)
		f1.Mul(f1, f)
		f2.Mul(k, temp.Sub(k, big.NewInt(1)))
		f2.Mul(f2, f)
		f.Mul(x, f)
		f.Mul(x, f)
		f.Sub(f, a)

		temp1.Mul(f1, f1)
		temp1.Mul(big.NewInt(2), temp1)
		temp2.Mul(f, f2)
		temp.Mul(f, f1)
		temp.Mul(big.NewInt(2), temp)
		temp.Div(temp, temp1.Sub(temp1, temp2))
		return temp.Sub(x, temp) // temp = (1.0/k)*((k-1)*x + a/math.Pow(x, k-1))
	}
	x := big.NewInt(1)
	y := step(k, a, x)
	count = 0
	for {
		x = y
		y = step(k, a, x)
		if x.Cmp(y) == 0 {
			break
		}
		count += 1
	}
	return x, count
}

func DecryptRSAFromFactor(I PublicInfo, p, q *big.Int) (*big.Int, error) {
	var (
		temp1 = big.NewInt(1)
		temp2 = big.NewInt(1)
		phi   = temp1.Mul(temp1.Sub(p, temp1), temp2.Sub(q, temp2))
	)
	d, err := ModInverse(I.E, phi)
	if err != nil {
		return nil, err
	}
	if temp1.Mul(p, q).Cmp(I.N) != 0 {
		return nil, fmt.Errorf("RSA public key is not in the form p*q")
	}
	m := new(big.Int).Exp(I.C, d, I.N)
	return m, nil
}

// apply when all e's are equal
func CrtAttack(rsaInfo []PublicInfo) (*big.Int, bool) {
	var (
		temp   = big.NewInt(0)
		prod   = big.NewInt(1)
		result = big.NewInt(0)
	)

	if len(rsaInfo) < 2 {
		return big.NewInt(0), false
	}

	for _, i := range rsaInfo {
		prod.Mul(prod, i.N)
	}

	for _, i := range rsaInfo {
		temp.Div(prod, i.N)
		inv, err := ModInverse(temp, i.N)
		if err != nil {
			return big.NewInt(0), false // no inverse exists
		}
		temp.Mul(temp, inv)
		temp.Mul(temp, i.C)
		result.Add(result, temp)
	}

	return result.Mod(result, prod), true
}

func CheckDecrypt(rsaInfo PublicInfo, message string) bool {
	temp := new(big.Int).SetBytes([]byte(message))
	temp.Exp(temp, rsaInfo.E, rsaInfo.N)
	return temp.Cmp(rsaInfo.C) == 0
}

func LinearSieve(n int) []int {
	primes := make([]int, 0)
	lp := make([]int, n+1)

	for i := 2; i <= n; i++ {
		if lp[i] == 0 {
			primes = append(primes, i)
			lp[i] = i
		}
		for _, p := range primes {
			j := i * p
			if j > n || p > lp[i] {
				break
			}
			lp[j] = p
		}
	}
	return primes
}

// if n = p*q where p and q are smooth primes then this algo will give the values of p,q from n
func Pollard_P_minus_One(n *big.Int) (*big.Int, error) {
	B := 10
	limit := 1000000
	g := big.NewInt(1)
	primes := LinearSieve(limit)

	for B <= limit && g.Cmp(n) == -1 {
		source := rand.Reader
		r, err := rand.Int(source, new(big.Int).Sub(n, big.NewInt(3)))
		if err != nil {
			return big.NewInt(1), err
		}

		a := r.Add(r, big.NewInt(2))
		g, _, _ = ExtendedGCD(a, n)
		if g.Cmp(big.NewInt(1)) == 1 {
			return g, nil
		}

		// compute a^M
		for _, p := range primes {
			if p >= B {
				continue
			}

			p_power := 1
			for p_power*p <= B {
				p_power = p_power * p
			}
			a.Exp(a, big.NewInt(int64(p_power)), n)

			g, _, _ = ExtendedGCD(new(big.Int).Sub(a, big.NewInt(1)), n)
			if g.Cmp(big.NewInt(1)) == 1 && g.Cmp(n) == -1 {
				return g, nil
			}
		}
		B *= 2
	}
	return big.NewInt(1), errors.New("RSA public key is not a smooth prime")
}

func ReadRSAPubKey(fileName string) *rsa.PublicKey {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	fileInfo, _ := file.Stat()
	size := fileInfo.Size()
	buffer := make([]byte, size)
	file.Read(buffer)
	block, _ := pem.Decode([]byte(buffer))
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	return cert.PublicKey.(*rsa.PublicKey)
}
