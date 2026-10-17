package rdp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

const (
	ntlmSig = "NTLMSSP\x00"

	ntlmTypeNegotiate    = 1
	ntlmTypeChallenge    = 2
	ntlmTypeAuthenticate = 3

	negotiateUnicode     = 0x00000001
	requestTarget        = 0x00000004
	negotiateSign        = 0x00000010
	negotiateSeal        = 0x00000020
	negotiateNTLMKey     = 0x00000200
	negotiateAlwaysSign  = 0x00008000
	negotiateExtendedSec = 0x00080000
	negotiateTargetInfo  = 0x00800000
	negotiateVersion     = 0x02000000
	negotiate128Bit      = 0x20000000
	negotiateKeyExch     = 0x40000000
	negotiate56Bit       = 0x80000000

	defaultNTLMFlags = uint32(
		negotiateUnicode |
			requestTarget |
			negotiateSign |
			negotiateSeal |
			negotiateNTLMKey |
			negotiateAlwaysSign |
			negotiateExtendedSec |
			negotiateTargetInfo |
			negotiateVersion |
			negotiate128Bit |
			negotiateKeyExch |
			negotiate56Bit,
	)
)

var ntlmVersionBytes = []byte{0x0a, 0x00, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f}

func GenerateNTLMNegotiate() []byte {
	buf := make([]byte, 40)
	copy(buf[0:8], ntlmSig)
	binary.LittleEndian.PutUint32(buf[8:12], ntlmTypeNegotiate)
	binary.LittleEndian.PutUint32(buf[12:16], defaultNTLMFlags)
	copy(buf[32:40], ntlmVersionBytes)
	return buf
}

type NTLMChallenge struct {
	Raw             []byte
	ServerChallenge [8]byte
	TargetInfo      []byte
	TargetName      string
	Flags           uint32
}

type NTLMSessionSecurity struct {
	clientSigningKey []byte
	clientCipher     *rc4.Cipher
	seqNum           uint32
}

func (s *NTLMSessionSecurity) Seal(plaintext []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	s.clientCipher.XORKeyStream(ciphertext, plaintext)

	var seqBuf [4]byte
	binary.LittleEndian.PutUint32(seqBuf[:], s.seqNum)

	h := hmac.New(md5.New, s.clientSigningKey)
	h.Write(seqBuf[:])
	h.Write(plaintext)
	mac := h.Sum(nil)[:8]

	checksum := make([]byte, 8)
	s.clientCipher.XORKeyStream(checksum, mac)

	sig := make([]byte, 16)
	binary.LittleEndian.PutUint32(sig[0:4], 1)
	copy(sig[4:12], checksum)
	copy(sig[12:16], seqBuf[:])

	s.seqNum++
	return append(sig, ciphertext...)
}

func ParseNTLMChallenge(data []byte) (*NTLMChallenge, error) {
	if len(data) < 32 || string(data[0:8]) != ntlmSig {
		return nil, fmt.Errorf("rdp/ntlm: invalid NTLM signature")
	}
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != ntlmTypeChallenge {
		return nil, fmt.Errorf("rdp/ntlm: expected type 2 challenge, got %d", msgType)
	}
	rawCopy := make([]byte, len(data))
	copy(rawCopy, data)

	ch := &NTLMChallenge{Raw: rawCopy}
	copy(ch.ServerChallenge[:], data[24:32])
	ch.Flags = binary.LittleEndian.Uint32(data[20:24])

	if len(data) >= 20 {
		tNameLen := binary.LittleEndian.Uint16(data[12:14])
		tNameOffset := binary.LittleEndian.Uint32(data[16:20])
		if int(tNameOffset+uint32(tNameLen)) <= len(data) && tNameLen > 0 {
			ch.TargetName = fromUnicode(data[tNameOffset : tNameOffset+uint32(tNameLen)])
		}
	}

	if len(data) >= 48 {
		tiLen := binary.LittleEndian.Uint16(data[40:42])
		tiOffset := binary.LittleEndian.Uint32(data[44:48])
		if int(tiOffset+uint32(tiLen)) <= len(data) {
			ch.TargetInfo = make([]byte, tiLen)
			copy(ch.TargetInfo, data[tiOffset:tiOffset+uint32(tiLen)])
		}
	}
	return ch, nil
}

func fromUnicode(b []byte) string {
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}

func extractServerTimestamp(targetInfo []byte) []byte {
	for i := 0; i+4 <= len(targetInfo); {
		avId := binary.LittleEndian.Uint16(targetInfo[i : i+2])
		avLen := int(binary.LittleEndian.Uint16(targetInfo[i+2 : i+4]))
		if avId == 0 {
			break
		}
		if avId == 7 && avLen == 8 && i+4+8 <= len(targetInfo) {
			return targetInfo[i+4 : i+4+8]
		}
		i += 4 + avLen
	}
	return nil
}

func buildTargetInfoWithMICFlag(targetInfo []byte) []byte {
	var out bytes.Buffer
	flagsFound := false
	for i := 0; i+4 <= len(targetInfo); {
		avId := binary.LittleEndian.Uint16(targetInfo[i : i+2])
		avLen := int(binary.LittleEndian.Uint16(targetInfo[i+2 : i+4]))
		if avId == 0 || i+4+avLen > len(targetInfo) {
			break
		}
		val := targetInfo[i+4 : i+4+avLen]
		if avId == 6 && avLen == 4 {
			flagsFound = true
			v := binary.LittleEndian.Uint32(val) | 0x00000002
			var headerAndVal [8]byte
			binary.LittleEndian.PutUint16(headerAndVal[0:2], 6)
			binary.LittleEndian.PutUint16(headerAndVal[2:4], 4)
			binary.LittleEndian.PutUint32(headerAndVal[4:8], v)
			out.Write(headerAndVal[:])
		} else {
			out.Write(targetInfo[i : i+4+avLen])
		}
		i += 4 + avLen
	}
	if !flagsFound {
		var headerAndVal [8]byte
		binary.LittleEndian.PutUint16(headerAndVal[0:2], 6)
		binary.LittleEndian.PutUint16(headerAndVal[2:4], 4)
		binary.LittleEndian.PutUint32(headerAndVal[4:8], 0x00000002)
		out.Write(headerAndVal[:])
	}
	out.Write([]byte{0x00, 0x00, 0x00, 0x00}) // MsvAvEOL
	return out.Bytes()
}

func GenerateNTLMAuthenticate(type1 []byte, domain, user, password string, ch *NTLMChallenge) ([]byte, *NTLMSessionSecurity, error) {
	var clientNonce [8]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		return nil, nil, err
	}

	ntlmHash := md4Hash(toUnicode(password))
	h := hmac.New(md5.New, ntlmHash)
	h.Write(toUnicode(strings.ToUpper(user)))
	h.Write(toUnicode(domain))
	ntlmV2Hash := h.Sum(nil)

	var timestampBytes []byte
	hasServerTime := false
	if serverTime := extractServerTimestamp(ch.TargetInfo); len(serverTime) == 8 {
		timestampBytes = serverTime
		hasServerTime = true
	} else {
		now := time.Now().UTC().UnixNano()/100 + 116444736000000000
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], uint64(now))
		timestampBytes = b[:]
	}

	var blob bytes.Buffer
	blob.Write([]byte{0x01, 0x01, 0x00, 0x00})
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00})
	blob.Write(timestampBytes)
	blob.Write(clientNonce[:])
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00})
	if len(ch.TargetInfo) > 0 {
		blob.Write(buildTargetInfoWithMICFlag(ch.TargetInfo))
	} else {
		blob.Write([]byte{0x00, 0x00, 0x00, 0x00})
	}
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00})

	hProof := hmac.New(md5.New, ntlmV2Hash)
	hProof.Write(ch.ServerChallenge[:])
	hProof.Write(blob.Bytes())
	ntProofStr := hProof.Sum(nil)
	ntChallengeResp := append(ntProofStr, blob.Bytes()...)

	var lmChallengeResp []byte
	if hasServerTime {
		lmChallengeResp = make([]byte, 24)
	} else {
		hLM := hmac.New(md5.New, ntlmV2Hash)
		hLM.Write(ch.ServerChallenge[:])
		hLM.Write(clientNonce[:])
		lmChallengeResp = append(hLM.Sum(nil), clientNonce[:]...)
	}

	// محاسبه کلید پایه نشست و تبادل کلید (KEY_EXCH)
	hSess := hmac.New(md5.New, ntlmV2Hash)
	hSess.Write(ntProofStr)
	keyExchangeKey := hSess.Sum(nil)

	exportedSessionKey := make([]byte, 16)
	if _, err := rand.Read(exportedSessionKey); err != nil {
		return nil, nil, err
	}

	rc4KeyEx, err := rc4.NewCipher(keyExchangeKey)
	if err != nil {
		return nil, nil, err
	}
	encryptedRandomSessionKey := make([]byte, 16)
	rc4KeyEx.XORKeyStream(encryptedRandomSessionKey, exportedSessionKey)

	userBytes := toUnicode(user)
	domainBytes := toUnicode(domain)
	workstationBytes := toUnicode("WORKSTATION")

	// هدر ۸۸ بایتی استاندارد (۶۴ بایت پایه + ۸ بایت Version + ۱۶ بایت MIC)
	fixedHeaderLen := 88
	offset := fixedHeaderLen
	buf := make([]byte, offset)
	copy(buf[0:8], ntlmSig)
	binary.LittleEndian.PutUint32(buf[8:12], ntlmTypeAuthenticate)

	buf = appendField(buf, 12, domainBytes, &offset)
	buf = appendField(buf, 20, userBytes, &offset)
	buf = appendField(buf, 28, workstationBytes, &offset)
	buf = appendField(buf, 36, lmChallengeResp, &offset)
	buf = appendField(buf, 44, ntChallengeResp, &offset)
	buf = appendField(buf, 52, encryptedRandomSessionKey, &offset)

	// توجه: چیدمان استاندارد فیلدهای NTLM Type 3:
	// 12: LmChallengeResponse, 20: NtChallengeResponse, 28: DomainName, 36: UserName, 44: Workstation, 52: EncryptedRandomSessionKey
	offset = fixedHeaderLen
	buf = buf[:fixedHeaderLen]
	buf = appendField(buf, 28, domainBytes, &offset)
	buf = appendField(buf, 36, userBytes, &offset)
	buf = appendField(buf, 44, workstationBytes, &offset)
	buf = appendField(buf, 12, lmChallengeResp, &offset)
	buf = appendField(buf, 20, ntChallengeResp, &offset)
	buf = appendField(buf, 52, encryptedRandomSessionKey, &offset)

	flags := defaultNTLMFlags & ch.Flags
	flags |= negotiateUnicode | requestTarget | negotiateSign | negotiateSeal | negotiateNTLMKey | negotiateExtendedSec | negotiateTargetInfo | negotiateVersion | negotiate128Bit | negotiateKeyExch
	binary.LittleEndian.PutUint32(buf[60:64], flags)
	copy(buf[64:72], ntlmVersionBytes)
	// buf[72:88] اکنون صفر است؛ محاسبه MIC روی کل پیام‌های 1، 2 و 3:
	hMIC := hmac.New(md5.New, exportedSessionKey)
	hMIC.Write(type1)
	hMIC.Write(ch.Raw)
	hMIC.Write(buf)
	copy(buf[72:88], hMIC.Sum(nil))

	// استخراج کلیدهای Sign و Seal کلاینت برای CredSSP PubKeyAuth
	signHash := md5.New()
	signHash.Write(exportedSessionKey)
	signHash.Write([]byte("session key to client-to-server signing key magic constant\x00"))
	clientSigningKey := signHash.Sum(nil)

	sealHash := md5.New()
	sealHash.Write(exportedSessionKey)
	sealHash.Write([]byte("session key to client-to-server sealing key magic constant\x00"))
	clientSealingKey := sealHash.Sum(nil)

	clientCipher, err := rc4.NewCipher(clientSealingKey)
	if err != nil {
		return nil, nil, err
	}

	sec := &NTLMSessionSecurity{
		clientSigningKey: clientSigningKey,
		clientCipher:     clientCipher,
		seqNum:           0,
	}

	return buf, sec, nil
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
	h := md4.New()
	_, _ = h.Write(data)
	return h.Sum(nil)
}
