package wiresocket

import (
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// cookieRotation is how often the server's cookie secret is rotated.
const cookieRotation = 2 * time.Minute

// cookieManager generates and verifies WireGuard-style DoS-mitigation cookies.
//
// cookie = MAC(BLAKE2s(key = cookie_secret, data = client_addr))
//
// The secret rotates every cookieRotation.  Each CookieReply is encrypted
// with XChaCha20-Poly1305 keyed by the client's MAC1.
type cookieManager struct {
	staticPub [32]byte

	mu      sync.Mutex
	secret  [32]byte    // current cookie secret
	prev    [32]byte    // previous cookie secret (for grace period)
	rotated time.Time   // when current was last rotated
}

func newCookieManager(staticPub [32]byte) *cookieManager {
	cm := &cookieManager{staticPub: staticPub}
	_ = randBytes(cm.secret[:])
	cm.rotated = time.Now()
	return cm
}

func (cm *cookieManager) rotate() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if time.Since(cm.rotated) >= cookieRotation {
		cm.prev = cm.secret
		_ = randBytes(cm.secret[:])
		cm.rotated = time.Now()
	}
}

// makeCookie derives a 16-byte cookie for addrStr (e.g. "1.2.3.4:5678").
func (cm *cookieManager) makeCookie(addrStr string) [16]byte {
	cm.rotate()
	cm.mu.Lock()
	secret := cm.secret
	cm.mu.Unlock()

	// cookie_key = BLAKE2s(key=secret, "cookie--" || static_pub)
	cookieKey := mac(secret, append([]byte(labelCookie), cm.staticPub[:]...))
	// cookie = MAC(cookie_key, client_addr)
	full := mac(cookieKey, []byte(addrStr))
	var out [16]byte
	copy(out[:], full[:16])
	return out
}

// BuildCookieReply constructs a CookieReply for the given initiator.
// mac1 is the MAC1 value from the HandshakeInit — it serves as the
// XChaCha20 encryption key so only the real initiator can decrypt it.
func (cm *cookieManager) BuildCookieReply(receiverIndex uint32, mac1 [16]byte, addrStr string) (*CookieReply, error) {
	cookie := cm.makeCookie(addrStr)

	// Derive a 32-byte XChaCha20 key from mac1 (zero-extended).
	var key [32]byte
	copy(key[:], mac1[:])

	// Random 24-byte nonce for XChaCha20-Poly1305.
	var nonce [24]byte
	if err := randBytes(nonce[:]); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	encrypted := aead.Seal(nil, nonce[:], cookie[:], nil)

	reply := &CookieReply{ReceiverIndex: receiverIndex}
	copy(reply.Nonce[:], nonce[:])
	copy(reply.EncryptedCookie[:], encrypted) // 16 + 16-byte tag = 32 bytes
	return reply, nil
}

// ConsumeCookieReply decrypts a CookieReply using the local mac1 that was
// sent in the original HandshakeInit.  Returns the 16-byte cookie.
func ConsumeCookieReply(reply *CookieReply, mac1 [16]byte) ([16]byte, error) {
	var key [32]byte
	copy(key[:], mac1[:])

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return [16]byte{}, err
	}
	plain, err := aead.Open(nil, reply.Nonce[:], reply.EncryptedCookie[:], nil)
	if err != nil {
		return [16]byte{}, err
	}
	var cookie [16]byte
	copy(cookie[:], plain)
	return cookie, nil
}

// computeMAC2 computes MAC2 from a cookie over a message body.
func computeMAC2(cookie [16]byte, msgBody []byte) [16]byte {
	var k [32]byte
	copy(k[:], cookie[:])
	full := mac(k, msgBody)
	var out [16]byte
	copy(out[:], full[:16])
	return out
}
