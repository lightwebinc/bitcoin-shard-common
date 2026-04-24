package frame

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func makeFrame(txidByte0 byte, payload []byte) *Frame {
	f := &Frame{Payload: payload}
	f.TxID[0] = txidByte0
	return f
}

// ── Constants ─────────────────────────────────────────────────────────────────

func TestHeaderSize(t *testing.T) {
	if HeaderSize != 92 {
		t.Errorf("HeaderSize = %d, want 92", HeaderSize)
	}
}

func TestHeaderSizeLegacy(t *testing.T) {
	if HeaderSizeLegacy != 44 {
		t.Errorf("HeaderSizeLegacy = %d, want 44", HeaderSizeLegacy)
	}
}

func TestFrameVerV1(t *testing.T) {
	if FrameVerV1 != 0x01 {
		t.Errorf("FrameVerV1 = 0x%02X, want 0x01", FrameVerV1)
	}
}

func TestFrameVerBRC122(t *testing.T) {
	if FrameVerBRC122 != 0x02 {
		t.Errorf("FrameVerBRC122 = 0x%02X, want 0x02", FrameVerBRC122)
	}
}

// ── Round-trip (all fields) ───────────────────────────────────────────────────

func TestRoundTrip(t *testing.T) {
	payload := []byte("fake-bsv-tx-payload")
	f := &Frame{
		Payload:     payload,
		ShardSeqNum: 0x01020304,
		SequenceID:  0xAABBCCDD,
		SenderID:    0x11223344,
	}
	f.TxID[0] = 0xAB
	for i := range f.SubtreeID {
		f.SubtreeID[i] = byte(i + 1)
	}

	buf := make([]byte, HeaderSize+len(payload))
	n, err := Encode(f, buf)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if n != HeaderSize+len(payload) {
		t.Fatalf("Encode returned %d bytes, want %d", n, HeaderSize+len(payload))
	}

	got, err := Decode(buf[:n])
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.TxID != f.TxID {
		t.Errorf("TxID mismatch: got %x, want %x", got.TxID, f.TxID)
	}
	if got.ShardSeqNum != f.ShardSeqNum {
		t.Errorf("ShardSeqNum = %d, want %d", got.ShardSeqNum, f.ShardSeqNum)
	}
	if got.SubtreeID != f.SubtreeID {
		t.Errorf("SubtreeID mismatch")
	}
	if got.SenderID != f.SenderID {
		t.Errorf("SenderID mismatch: got %x, want %x", got.SenderID, f.SenderID)
	}
	if got.SequenceID != f.SequenceID {
		t.Errorf("SequenceID = %d, want %d", got.SequenceID, f.SequenceID)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("Payload mismatch: got %q, want %q", got.Payload, payload)
	}
}

func TestRoundTripWithSenderID(t *testing.T) {
	payload := []byte("tx-with-sender")
	f := &Frame{
		Payload:     payload,
		ShardSeqNum: 42,
		SequenceID:  0x11223344,
		SenderID:    0xAABBCCDD,
	}
	f.TxID[0] = 0xCC

	buf := make([]byte, HeaderSize+len(payload))
	if _, err := Encode(f, buf); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.SenderID != f.SenderID {
		t.Errorf("SenderID mismatch: got %x, want %x", got.SenderID, f.SenderID)
	}
	if got.SequenceID != f.SequenceID {
		t.Errorf("SequenceID mismatch: got %d, want %d", got.SequenceID, f.SequenceID)
	}
}

// ── Field offsets ─────────────────────────────────────────────────────────────

func TestFieldOffsets(t *testing.T) {
	f := &Frame{
		SenderID:    0xAABBCCDD,
		SequenceID:  0x12345678,
		ShardSeqNum: 0xDEADBEEF,
	}
	f.TxID[0] = 0x11
	for i := range f.SubtreeID {
		f.SubtreeID[i] = 0xCC
	}
	f.Payload = []byte{0xFF}

	buf := make([]byte, HeaderSize+5) // Extra space for payload checks
	if _, err := Encode(f, buf); err != nil {
		t.Fatal(err)
	}

	if buf[6] != FrameVerBRC122 {
		t.Errorf("buf[6] (FrameVer) = 0x%02X, want 0x%02X", buf[6], FrameVerBRC122)
	}
	if buf[7] != 0 {
		t.Errorf("buf[7] (Reserved) = 0x%02X, want 0x00", buf[7])
	}
	if buf[8] != 0x11 {
		t.Errorf("buf[8] (TxID[0]) = 0x%02X, want 0x11", buf[8])
	}
	if binary.BigEndian.Uint32(buf[40:44]) != 0xAABBCCDD {
		t.Errorf("buf[40:44] (SenderID) mismatch")
	}
	if binary.BigEndian.Uint32(buf[44:48]) != 0x12345678 {
		t.Errorf("buf[44:48] (SequenceID) mismatch")
	}
	if binary.BigEndian.Uint32(buf[48:52]) != 0xDEADBEEF {
		t.Errorf("buf[48:52] (ShardSeqNum) mismatch")
	}
	if buf[52] != 0x00 || buf[53] != 0x00 || buf[54] != 0x00 || buf[55] != 0x00 {
		t.Errorf("buf[52:56] (Reserved) should be zero")
	}
	if buf[56] != 0xCC {
		t.Errorf("buf[56] (SubtreeID[0]) = 0x%02X, want 0xCC", buf[56])
	}
	payLen := binary.BigEndian.Uint32(buf[88:92])
	if payLen != 1 {
		t.Errorf("buf[88:92] (PayLen) = %d, want 1", payLen)
	}
	if buf[HeaderSize] != 0xFF {
		t.Errorf("buf[%d] (Payload[0]) = 0x%02X, want 0xFF", HeaderSize, buf[HeaderSize])
	}
}

// ── Empty payload ─────────────────────────────────────────────────────────────

func TestEmptyPayload(t *testing.T) {
	f := makeFrame(0x77, []byte{})
	buf := make([]byte, HeaderSize+8) // Extra space for copy operation
	n, err := Encode(f, buf)
	if err != nil {
		t.Fatalf("Encode empty payload: %v", err)
	}
	if n != HeaderSize {
		t.Errorf("n = %d, want %d", n, HeaderSize)
	}
	got, err := Decode(buf[:n])
	if err != nil {
		t.Fatalf("Decode empty payload: %v", err)
	}
	if len(got.Payload) != 0 {
		t.Errorf("Payload len = %d, want 0", len(got.Payload))
	}
}

// ── v1 frame decode ───────────────────────────────────────────────────────────

// buildV1Frame assembles a minimal valid v1 datagram.
func buildV1Frame(txidByte byte, payload []byte) []byte {
	buf := make([]byte, HeaderSizeLegacy+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV1
	// buf[7] = 0x00 (reserved)
	buf[8] = txidByte
	binary.BigEndian.PutUint32(buf[40:44], uint32(len(payload)))
	copy(buf[44:], payload)
	return buf
}

func TestDecodeV1Basic(t *testing.T) {
	payload := []byte("v1-tx-payload")
	raw := buildV1Frame(0xAB, payload)
	f, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode v1: %v", err)
	}
	if f.Version != FrameVerV1 {
		t.Errorf("Version = 0x%02X, want 0x%02X", f.Version, FrameVerV1)
	}
	if f.TxID[0] != 0xAB {
		t.Errorf("TxID[0] = 0x%02X, want 0xAB", f.TxID[0])
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("Payload mismatch: got %q, want %q", f.Payload, payload)
	}
}

func TestDecodeV1ZeroedBRC122Fields(t *testing.T) {
	raw := buildV1Frame(0x01, nil)
	f, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode v1: %v", err)
	}
	if f.ShardSeqNum != 0 {
		t.Errorf("ShardSeqNum = %d, want 0", f.ShardSeqNum)
	}
	if f.SubtreeID != ([32]byte{}) {
		t.Error("SubtreeID should be all zeros for v1")
	}
	if f.SenderID != 0 {
		t.Errorf("SenderID = %d, want 0", f.SenderID)
	}
	if f.SequenceID != 0 {
		t.Errorf("SequenceID = %d, want 0", f.SequenceID)
	}
}

func TestDecodeV1EmptyPayload(t *testing.T) {
	raw := buildV1Frame(0x77, nil)
	f, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode v1 empty payload: %v", err)
	}
	if len(f.Payload) != 0 {
		t.Errorf("Payload len = %d, want 0", len(f.Payload))
	}
}

func TestDecodeV1Truncated(t *testing.T) {
	raw := buildV1Frame(0x01, []byte("hello"))
	_, err := Decode(raw[:len(raw)-1])
	if err != io.ErrUnexpectedEOF {
		t.Errorf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

// ── Error paths ───────────────────────────────────────────────────────────────

func TestDecodeErrTooShort(t *testing.T) {
	// Shorter than even the v1 header
	_, err := Decode(make([]byte, HeaderSizeLegacy-1))
	if err != ErrTooShort {
		t.Errorf("want ErrTooShort, got %v", err)
	}
}

func TestDecodeBRC122ErrTooShort(t *testing.T) {
	// Long enough for v1 but not BRC-122
	buf := make([]byte, HeaderSizeLegacy)
	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	buf[6] = FrameVerBRC122
	_, err := Decode(buf)
	if err != ErrTooShort {
		t.Errorf("want ErrTooShort for BRC-122 with only %d bytes, got %v", HeaderSizeLegacy, err)
	}
}

func TestDecodeErrBadMagic(t *testing.T) {
	buf := make([]byte, HeaderSize)
	_, err := Decode(buf)
	if err == nil {
		t.Fatal("want error for bad magic, got nil")
	}
}

func TestDecodeErrBadVer(t *testing.T) {
	buf := make([]byte, HeaderSize)
	buf[0], buf[1], buf[2], buf[3] = 0xE3, 0xE1, 0xF3, 0xE8
	buf[6] = 0xFF
	_, err := Decode(buf)
	if err == nil {
		t.Fatal("want error for bad frame version, got nil")
	}
}

func TestDecodeErrTruncated(t *testing.T) {
	f := makeFrame(0x01, []byte("payload"))
	buf := make([]byte, HeaderSize+len(f.Payload)) // Payload starts at offset HeaderSize
	n, _ := Encode(f, buf)
	_, err := Decode(buf[:n-1])
	if err != io.ErrUnexpectedEOF {
		t.Errorf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestEncodeBufferTooSmall(t *testing.T) {
	f := makeFrame(0x01, []byte("payload"))
	_, err := Encode(f, make([]byte, 1))
	if err == nil {
		t.Fatal("want error for buffer too small, got nil")
	}
}
