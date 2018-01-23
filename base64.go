package crypt

const (
	alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

func base64_24Bit(src []byte) []byte {
	if len(src) == 0 {
		return []byte{} // TODO: return nil
	}

	dstlen := (len(src)*8 + 5) / 6
	dst := make([]byte, dstlen)

	di, si := 0, 0
	n := len(src) / 3 * 3
	for si < n {
		val := uint(src[si+2])<<16 | uint(src[si+1])<<8 | uint(src[si])
		dst[di+0] = alphabet[val&0x3f]
		dst[di+1] = alphabet[val>>6&0x3f]
		dst[di+2] = alphabet[val>>12&0x3f]
		dst[di+3] = alphabet[val>>18]
		di += 4
		si += 3
	}

	rem := len(src) - si
	if rem == 0 {
		return dst
	}

	val := uint(src[si+0])
	if rem == 2 {
		val |= uint(src[si+1]) << 8
	}

	dst[di+0] = alphabet[val&0x3f]
	dst[di+1] = alphabet[val>>6&0x3f]
	if rem == 2 {
		dst[di+2] = alphabet[val>>12]
	}
	return dst
}
