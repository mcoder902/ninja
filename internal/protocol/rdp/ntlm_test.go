package rdp

import "testing"

// TestParseNTLMChallengeOffsetOverflow رگرسیون سرریز uint32 در محاسبه
// offset+length است. قبلاً مقدارهایی مثل 0xFFFFFFFF+2 با دورریز به 1 از چک
// عبور می‌کردند و عبارت اسلایس پانیک می‌داد؛ الان باید فیلد کل خراب Drop شود.
func TestParseNTLMChallengeOffsetOverflow(t *testing.T) {
	data := make([]byte, 64)
	copy(data[0:8], "NTLMSSP\x00")
	data[8] = 2 // NTLMSSP_MESSAGE_TYPE_CHALLENGE

	// TargetName: len=2, offset=0xFFFFFFFF → در uint32 به 1 دور می‌ریزد
	data[12] = 2
	data[16] = 0xFF
	data[17] = 0xFF
	data[18] = 0xFF
	data[19] = 0xFF

	// TargetInfo: len=8, offset=0xFFFFFFF8 → در uint32 به 0 دور می‌ریزد
	data[40] = 8
	data[44] = 0xF8
	data[45] = 0xFF
	data[46] = 0xFF
	data[47] = 0xFF

	ch, err := ParseNTLMChallenge(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ch.TargetName != "" || ch.TargetInfo != nil {
		t.Fatalf("out-of-range fields must be dropped, got TargetName=%q TargetInfo=%v",
			ch.TargetName, ch.TargetInfo)
	}
}

// TestParseNTLMChallengeValidOffsets چک می‌کند فیلدهای درست همان‌طور که قبل
// از پچ کار می‌کردند همچنان پارس می‌شوند (هیچ رگرسیون مثبت کاذب نباشد).
func TestParseNTLMChallengeValidOffsets(t *testing.T) {
	// 32 هدر + TargetName(8) + TargetInfo(8) + TargetInfo هدر در 40..47
	data := make([]byte, 56)
	copy(data[0:8], "NTLMSSP\x00")
	data[8] = 2
	for i := range data[24:32] {
		data[24+i] = byte(i + 1) // server challenge
	}

	// TargetName در آفست 32، طول 8 (4 کاراکتر UTF-16: "SERV")
	data[12] = 8
	data[16] = 32
	copy(data[32:40], []byte("S\x00E\x00R\x00V\x00"))

	// TargetInfo: len در 40..41، آفست در 44..47، بدنه در 48..55
	data[40] = 8
	data[44] = 48
	copy(data[48:56], []byte{1, 0, 4, 0, 'a', 'b', 'c', 'd'})

	ch, err := ParseNTLMChallenge(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ch.TargetName != "SERV" {
		t.Fatalf("TargetName = %q, want %q", ch.TargetName, "SERV")
	}
	if len(ch.TargetInfo) != 8 {
		t.Fatalf("TargetInfo len = %d, want 8", len(ch.TargetInfo))
	}
}
