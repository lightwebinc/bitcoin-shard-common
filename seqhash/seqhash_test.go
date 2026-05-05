package seqhash

import (
	"testing"
)

func TestHashDeterministic(t *testing.T) {
	var ip [16]byte
	copy(ip[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24})

	h1 := Hash(ip, 0, 1)
	h2 := Hash(ip, 0, 1)
	if h1 != h2 {
		t.Errorf("Hash not deterministic: %x != %x", h1, h2)
	}
}

func TestHashDifferentCounters(t *testing.T) {
	var ip [16]byte
	copy(ip[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24})

	h1 := Hash(ip, 0, 1)
	h2 := Hash(ip, 0, 2)
	if h1 == h2 {
		t.Errorf("Hash(counter=1) == Hash(counter=2): collision at %x", h1)
	}
}

func TestHashDifferentGroups(t *testing.T) {
	var ip [16]byte
	copy(ip[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24})

	h1 := Hash(ip, 0, 1)
	h2 := Hash(ip, 1, 1)
	if h1 == h2 {
		t.Errorf("Hash(group=0) == Hash(group=1): collision at %x", h1)
	}
}

func TestHashDifferentSenders(t *testing.T) {
	var ip1, ip2 [16]byte
	copy(ip1[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24})
	copy(ip2[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x25})

	h1 := Hash(ip1, 0, 1)
	h2 := Hash(ip2, 0, 1)
	if h1 == h2 {
		t.Errorf("Hash(sender1) == Hash(sender2): collision at %x", h1)
	}
}

func TestHashChainProperty(t *testing.T) {
	var ip [16]byte
	copy(ip[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	cur1 := Hash(ip, 0, 1)
	cur2 := Hash(ip, 0, 2)
	cur3 := Hash(ip, 0, 3)

	if cur1 == cur2 || cur2 == cur3 || cur1 == cur3 {
		t.Error("hash chain produced duplicate values")
	}
	t.Logf("chain: %x -> %x -> %x", cur1, cur2, cur3)
}

func BenchmarkHash(b *testing.B) {
	var ip [16]byte
	copy(ip[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24})
	b.ResetTimer()
	for i := range b.N {
		_ = Hash(ip, 0, uint64(i)+1)
	}
}
