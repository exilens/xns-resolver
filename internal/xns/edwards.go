package xns

import (
	"errors"
	"math/big"
)

type point struct {
	x *big.Int
	y *big.Int
}

var (
	edP, _   = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	edL, _   = new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	edD      = mod(mul(big.NewInt(-121665), inv(big.NewInt(121666))))
	edI      = new(big.Int).Exp(big.NewInt(2), new(big.Int).Div(new(big.Int).Sub(edP, big.NewInt(1)), big.NewInt(4)), edP)
	identity = point{big.NewInt(0), big.NewInt(1)}
)

func validOwnerPoint(raw []byte) error {
	p, err := decodePoint(raw)
	if err != nil {
		return err
	}
	if equal(p, identity) {
		return invalidPoint("identity point")
	}
	if !equal(scalarMult(p, edL), identity) {
		return invalidPoint("point is outside the prime-order subgroup")
	}
	return nil
}

func decodePoint(raw []byte) (point, error) {
	if len(raw) != 32 {
		return identity, errors.New("encoded point must be 32 bytes")
	}
	yBytes := append([]byte(nil), raw...)
	sign := yBytes[31] >> 7
	yBytes[31] &= 0x7f
	reverse(yBytes)
	y := new(big.Int).SetBytes(yBytes)
	if y.Cmp(edP) >= 0 {
		return identity, invalidPoint("non-canonical y coordinate")
	}

	y2 := mul(y, y)
	xx := mul(sub(y2, big.NewInt(1)), inv(add(mul(edD, y2), big.NewInt(1))))
	exp := new(big.Int).Div(new(big.Int).Add(edP, big.NewInt(3)), big.NewInt(8))
	x := new(big.Int).Exp(xx, exp, edP)
	if sub(mul(x, x), xx).Sign() != 0 {
		x = mul(x, edI)
	}
	if sub(mul(x, x), xx).Sign() != 0 {
		return identity, invalidPoint("point is not on the curve")
	}
	if x.Sign() == 0 && sign == 1 {
		return identity, invalidPoint("invalid sign bit")
	}
	if byte(x.Bit(0)) != sign {
		x = sub(edP, x)
	}
	return point{x, y}, nil
}

func scalarMult(p point, n *big.Int) point {
	result := identity
	addend := p
	for i := 0; i < n.BitLen(); i++ {
		if n.Bit(i) == 1 {
			result = addPoint(result, addend)
		}
		addend = addPoint(addend, addend)
	}
	return result
}

func addPoint(a, b point) point {
	x1, y1 := a.x, a.y
	x2, y2 := b.x, b.y
	xNum := add(mul(x1, y2), mul(x2, y1))
	xDen := inv(add(big.NewInt(1), mul(edD, mul(mul(x1, x2), mul(y1, y2)))))
	yNum := add(mul(y1, y2), mul(x1, x2))
	yDen := inv(sub(big.NewInt(1), mul(edD, mul(mul(x1, x2), mul(y1, y2)))))
	return point{mul(xNum, xDen), mul(yNum, yDen)}
}

func equal(a, b point) bool {
	return a.x.Cmp(b.x) == 0 && a.y.Cmp(b.y) == 0
}

func add(a, b *big.Int) *big.Int { return mod(new(big.Int).Add(a, b)) }
func sub(a, b *big.Int) *big.Int { return mod(new(big.Int).Sub(a, b)) }
func mul(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }
func inv(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(mod(new(big.Int).Set(a)), edP)
}
func mod(a *big.Int) *big.Int {
	a.Mod(a, edP)
	if a.Sign() < 0 {
		a.Add(a, edP)
	}
	return a
}

func reverse(raw []byte) {
	for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
		raw[i], raw[j] = raw[j], raw[i]
	}
}
