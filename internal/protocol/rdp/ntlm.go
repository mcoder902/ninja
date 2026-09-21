package rdp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	ntlmSig = "NTLMSSP\x00"

	ntlmTypeNegotiate    = 1
	ntlmTypeChallenge    = 2
	ntlmTypeAuthenticate = 3

	negotiateUnicode     = 0x00000001
	negotiateNTLMKey     = 0x00000200
	negotiateAlwaysSign  = 0x00008000
	negotiateExtendedSec = 0x00080000
	negotiateTargetInfo  = 0x00800000
	negotiate128Bit      = 0x20000000
	negotiate56Bit       = 0x80000000
)

func GenerateNTLMNegotiate() []byte {
	buf := make([]byte, 32)
	copy(buf[0:8], ntlmSig)
	binary.LittleEndian.PutUint32(buf[8:12], ntlmTypeNegotiate)

	flags := uint32(negotiateUnicode | negotiateNTLMKey | negotiateExtendedSec | negotiate128Bit | negotiate56Bit)
	binary.LittleEndian.PutUint32(buf[12:16], flags)
	return buf
}

type NTLMChallenge struct {
	ServerChallenge [8]byte
	TargetInfo      []byte
	Flags           uint32
}

func ParseNTLMChallenge(data []byte) (*NTLMChallenge, error) {
	if len(data) < 32 || string(data[0:8]) != ntlmSig {
		return nil, fmt.Errorf("rdp/ntlm: invalid NTLM signature")
	}
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != ntlmTypeChallenge {
		return nil, fmt.Errorf("rdp/ntlm: expected type 2 challenge, got %d", msgType)
	}

	ch := &NTLMChallenge{}
	copy(ch.ServerChallenge[:], data[24:32])
	ch.Flags = binary.LittleEndian.Uint32(data[20:24])

	if len(data) >= 48 {
		tiLen := binary.LittleEndian.Uint16(data[40:42])
		tiOffset := binary.LittleEndian.Uint32(data[44:48])
		if int(tiOffset+uint32(tiLen)) <= len(data) {
			ch.TargetInfo = data[tiOffset : tiOffset+uint32(tiLen)]
		}
	}
	return ch, nil
}

func GenerateNTLMAuthenticate(domain, user, password string, ch *NTLMChallenge) ([]byte, error) {
	var clientNonce [8]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		return nil, err
	}

	ntlmHash := md4Hash(toUnicode(password))
	h := hmac.New(md5.New, ntlmHash)
	h.Write(toUnicode(strings.ToUpper(user)))
	h.Write(toUnicode(domain))
	ntlmV2Hash := h.Sum(nil)

	now := time.Now().UTC().UnixNano()/100 + 116444736000000000
	var blob bytes.Buffer
	blob.Write([]byte{0x01, 0x01, 0x00, 0x00})
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00})
	_ = binary.Write(&blob, binary.LittleEndian, now)
	blob.Write(clientNonce[:])
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00})
	if len(ch.TargetInfo) > 0 {
		blob.Write(ch.TargetInfo)
	}
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00})

	hProof := hmac.New(md5.New, ntlmV2Hash)
	hProof.Write(ch.ServerChallenge[:])
	hProof.Write(blob.Bytes())
	ntProofStr := hProof.Sum(nil)

	ntChallengeResp := append(ntProofStr, blob.Bytes()...)

	hLM := hmac.New(md5.New, ntlmV2Hash)
	hLM.Write(ch.ServerChallenge[:])
	hLM.Write(clientNonce[:])
	lmChallengeResp := append(hLM.Sum(nil), clientNonce[:]...)

	userBytes := toUnicode(user)
	domainBytes := toUnicode(domain)
	workstationBytes := toUnicode("WORKSTATION")

	fixedHeaderLen := 64
	offset := fixedHeaderLen

	buf := make([]byte, offset)
	copy(buf[0:8], ntlmSig)
	binary.LittleEndian.PutUint32(buf[8:12], ntlmTypeAuthenticate)

	buf = appendField(buf, 12, lmChallengeResp, &offset)
	buf = appendField(buf, 20, ntChallengeResp, &offset)
	buf = appendField(buf, 28, domainBytes, &offset)
	buf = appendField(buf, 36, userBytes, &offset)
	buf = appendField(buf, 44, workstationBytes, &offset)

	binary.LittleEndian.PutUint16(buf[52:54], 0)
	binary.LittleEndian.PutUint16(buf[54:56], 0)
	binary.LittleEndian.PutUint32(buf[56:60], uint32(offset))

	flags := uint32(negotiateUnicode | negotiateNTLMKey | negotiateExtendedSec | negotiate128Bit | negotiate56Bit)
	binary.LittleEndian.PutUint32(buf[60:64], flags)

	return buf, nil
}

func appendField(buf []byte, fieldOffset int, data []byte, currentOffset *int) []byte {
	binary.LittleEndian.PutUint16(buf[fieldOffset:fieldOffset+2], uint16(len(data)))
	binary.LittleEndian.PutUint16(buf[fieldOffset+2:fieldOffset+4], uint16(len(data)))
	binary.LittleEndian.PutUint32(buf[fieldOffset+4:fieldOffset+8], uint32(*currentOffset))
	buf = append(buf, data...)
	*currentOffset += len(data)
	return buf
}

func toUnicode(s string) []byte {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

func md4Hash(data []byte) []byte {
	var a, b, c, d uint32 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
	padded := padMD4(data)
	for i := 0; i < len(padded); i += 64 {
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = binary.LittleEndian.Uint32(padded[i+j*4 : i+j*4+4])
		}
		aa, bb, cc, dd := a, b, c, d

		a = rot((a + (b&c | ^b&d) + x[0]), 3)
		d = rot((d + (a&b | ^a&c) + x[1]), 7)
		c = rot((c + (d&a | ^d&b) + x[2]), 11)
		b = rot((b + (c&d | ^c&a) + x[3]), 19)
		a = rot((a + (b&c | ^b&d) + x[4]), 3)
		d = rot((d + (a&b | ^a&c) + x[5]), 7)
		c = rot((c + (d&a | ^d&b) + x[6]), 11)
		b = rot((b + (c&d | ^c&a) + x[7]), 19)
		a = rot((a + (b&c | ^b&d) + x[8]), 3)
		d = rot((d + (a&b | ^a&c) + x[9]), 7)
		c = rot((c + (d&a | ^d&b) + x[10]), 11)
		b = rot((b + (c&d | ^c&a) + x[11]), 19)
		a = rot((a + (b&c | ^b&d) + x[12]), 3)
		d = rot((d + (a&b | ^a&c) + x[13]), 7)
		c = rot((c + (d&a | ^d&b) + x[14]), 11)
		b = rot((b + (c&d | ^c&a) + x[15]), 19)

		a = rot((a + (b&c | b&d | c&d) + x[0] + 0x5a827999), 3)
		d = rot((d + (a&b | a&c | b&c) + x[4] + 0x5a827999), 5)
		c = rot((c + (d&a | d&b | a&b) + x[8] + 0x5a827999), 9)
		b = rot((b + (c&d | c&a | d&a) + x[12] + 0x5a827999), 13)
		a = rot((a + (b&c | b&d | c&d) + x[1] + 0x5a827999), 3)
		d = rot((d + (a&b | a&c | b&c) + x[5] + 0x5a827999), 5)
		c = rot((c + (d&a | d&b | a&b) + x[9] + 0x5a827999), 9)
		b = rot((b + (c&d | c&a | d&a) + x[13] + 0x5a827999), 13)
		a = rot((a + (b&c | b&d | c&d) + x[2] + 0x5a827999), 3)
		d = rot((d + (a&b | a&c | b&c) + x[6] + 0x5a827999), 5)
		c = rot((c + (d&a | d&b | a&b) + x[10] + 0x5a827999), 9)
		b = rot((b + (c&d | c&a | d&a) + x[14] + 0x5a827999), 13)
		a = rot((a + (b&c | b&d | c&d) + x[3] + 0x5a827999), 3)
		d = rot((d + (a&b | a&c | b&c) + x[7] + 0x5a827999), 5)
		c = rot((c + (d&a | d&b | a&b) + x[11] + 0x5a827999), 9)
		b = rot((b + (c&d | c&a | d&a) + x[15] + 0x5a827999), 13)

		a = rot((a + (b ^ c ^ d) + x[0] + 0x6ed9eba1), 3)
		d = rot((d + (a ^ b ^ c) + x[8] + 0x6ed9eba1), 9)
		c = rot((c + (d ^ a ^ b) + x[4] + 0x6ed9eba1), 11)
		b = rot((b + (c ^ d ^ a) + x[12] + 0x6ed9eba1), 15)
		a = rot((a + (b ^ c ^ d) + x[2] + 0x6ed9eba1), 3)
		d = rot((d + (a ^ b ^ c) + x[10] + 0x6ed9eba1), 9)
		c = rot((c + (d ^ a ^ b) + x[6] + 0x6ed9eba1), 11)
		b = rot((b + (c ^ d ^ a) + x[14] + 0x6ed9eba1), 15)
		a = rot((a + (b ^ c ^ d) + x[1] + 0x6ed9eba1), 3)
		d = rot((d + (a ^ b ^ c) + x[9] + 0x6ed9eba1), 9)
		c = rot((c + (d ^ a ^ b) + x[5] + 0x6ed9eba1), 11)
		b = rot((b + (c ^ d ^ a) + x[13] + 0x6ed9eba1), 15)
		a = rot((a + (b ^ c ^ d) + x[3] + 0x6ed9eba1), 3)
		d = rot((d + (a ^ b ^ c) + x[11] + 0x6ed9eba1), 9)
		c = rot((c + (d ^ a ^ b) + x[7] + 0x6ed9eba1), 11)
		b = rot((b + (c ^ d ^ a) + x[15] + 0x6ed9eba1), 15)

		a += aa
		b += bb
		c += cc
		d += dd
	}
	res := make([]byte, 16)
	binary.LittleEndian.PutUint32(res[0:4], a)
	binary.LittleEndian.PutUint32(res[4:8], b)
	binary.LittleEndian.PutUint32(res[8:12], c)
	binary.LittleEndian.PutUint32(res[12:16], d)
	return res
}

func rot(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

func padMD4(data []byte) []byte {
	bitLen := uint64(len(data)) * 8
	data = append(data, 0x80)
	for (len(data) % 64) != 56 {
		data = append(data, 0x00)
	}
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], bitLen)
	return append(data, lenBuf[:]...)
}
