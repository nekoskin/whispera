package util

// Concat returns a new slice consisting of a followed by b.
// It avoids subtle aliasing problems that linters warn about
// when using append on a different destination slice variable.
// ОПТИМИЗАЦИЯ: Для маленьких слайсов используем более эффективный подход
func Concat(a, b []byte) []byte {
	totalLen := len(a) + len(b)
	// ОПТИМИЗАЦИЯ: Для маленьких слайсов (<256 байт) используем стек-аллокацию через массив
	if totalLen <= 256 {
		var buf [256]byte
		copy(buf[:], a)
		copy(buf[len(a):], b)
		out := make([]byte, totalLen)
		copy(out, buf[:totalLen])
		return out
	}
	// Для больших слайсов используем стандартный подход
	out := make([]byte, totalLen)
	copy(out, a)
	copy(out[len(a):], b)
	return out
}
