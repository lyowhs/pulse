package fndsa

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	sha3 "golang.org/x/crypto/sha3"
	"testing"
)

func TestFNDSA_Self(t *testing.T) {
	for logn := uint(2); logn <= uint(10); logn++ {
		fmt.Printf("[%d]", logn)
		for i := 0; i < 10; i++ {
			sk, vk, err := KeyGen(logn, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(sk) != SigningKeySize(logn) {
				t.Fatalf("wrong signing key size (logn=%d): %d\n",
					logn, len(sk))
			}
			if len(vk) != VerifyingKeySize(logn) {
				t.Fatalf("wrong verifying key size (logn=%d): %d\n",
					logn, len(vk))
			}
			data := []byte("test")
			var sig []byte
			if logn <= 8 {
				sig, err = SignWeak(nil, sk, DOMAIN_NONE, 0, data)
			} else {
				sig, err = Sign(nil, sk, DOMAIN_NONE, 0, data)
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(sig) != SignatureSize(logn) {
				t.Fatalf("wrong signature size (logn=%d): %d\n",
					logn, len(sig))
			}
			var r bool
			if logn <= 8 {
				r = VerifyWeak(vk, DOMAIN_NONE, 0, data, sig)
			} else {
				r = Verify(vk, DOMAIN_NONE, 0, data, sig)
			}
			if !r {
				t.Fatalf("signature verification failed (logn=%d)\n", logn)
			}
			fmt.Print(".")
		}
	}
	fmt.Println()
}

// Test vectors:
// kat_n[] contains 10 vectors for n = 2^logn
// For test vector kat_n[j]:
//
//	Let seed1 = 0x00 || logn || j
//	Let seed2 = 0x01 || logn || j
//	(logn over one byte, j over 4 bytes, little-endian)
//	seed1 is used with FakeRng1 in keygen.
//	seed2 is used with FakeRng2 for signing.
//	A key pair (sk, vk) is generated. A message is signed:
//	    domain context: "domain" (6 bytes)
//	    message: "message" (7 bytes)
//	    if n is odd, message is pre-hashed with SHA3-256; raw otherwise
//	KAT_n[j] is SHA3-256(sk || vk || sig)
var kat_4 = []string{
	"517e169d05b8cd4b6afa81847d5f1ed47309650a9ccff39c4445ae57914a2058",
	"ce8f23924e463c769cedbd034eb0f11574c1cb8a453949c6c36b34e09e41d06c",
	"65c2b2a6f2054faf7dbe97454d68b66768ca2ca5f65e7cbea5a91cdc1c6549a4",
	"568e6ad817ba21b555808255db94a710ebbd5005284585365dc5308046e23d66",
	"8ec696eaee01f9ec43bdb04d9dab7ff43d8bd80c7081134b9863f7c6ebbbe284",
	"96e95da3c03426bbb3448084cbb54d83392acae745e3781f890dcddb030572cb",
	"469be4112615d98308ef9df8cb8b0f3da1ca2558d79b7a867530de7d4000fb9b",
	"80d7cc5c779ae2a590249169e10e935a1e8bf481d1c8babf3487acc0838b99d1",
	"faac905c850eeb978e776f1e7fb1bf7ad40dd9618792f25fc3fae9ee47d8ce15",
	"fc484c374ab40a4dbb5ea62b04a10f0c945105cddd48c4a90e729fc07680e88b",
}
var kat_8 = []string{
	"bef4b8dc62d8e0b5eca9bc09366b1dcf7327dfbac10042406cc2217e9d0791f5",
	"f75a3392c69345b6f5355d104305efae9a9d90fd5dfaa03120a12e02356b34fd",
	"e3c8a660f6ab7102d9a975c94d6c0206e0835cc88ab36dd63556540c15b32ac3",
	"1cd5bcadfc883540211d7803a2d6ff47474e4d5bc8a42b79ff97327f6e75b574",
	"671b901f1535f58e198eab7fb9e84525f4315337abe30f902e6c0305501b0709",
	"680d8b79f8d91ce1ae6a070baebd8f3f99472efe1c14efa35e1a653472ac98c2",
	"3d9c77564d8ac733fd20bbff61d078c0ee094dc50ef2a0d8b53238263bd9f0d9",
	"5b96561ca0cb41b1c09dc569ee48e596067df5a287a838f88b98e2375880d053",
	"b306079cd1f2f4029cee72988ace631572ad7f2620e020cf5ad4b1ae598424e1",
	"9a8cf1dc6b62c9f8b7790943ca9e48beef24aa8326b9002146e1858bc61103d2",
}
var kat_16 = []string{
	"e3f4742be370ea418feab49c3fee6a98ac52c1f1cb39138a90092449595b3f81",
	"d6659d9895e4b59c1001bf8354319889ef89f9c42570147dc86d615db94ade09",
	"f4b95d6d27a64fbd303a7091625bd8daf61c3301376d512203c2fb53fb726317",
	"8c94c3df7eb93a31ce32b756ed0279c8c36e8cbe9a76901823d61f64244be8a9",
	"c2ff7bff549c1f050c81dc3ca6ccd0537f0345b304f9271457405ac5b0ff1bb6",
	"d03a17462c30a7bd7d594cd0ac209d4f3704a96934e0c12e31010e8bcd58f472",
	"e694f16019b9ed9afa360db94a29bf5036ef88fb4ff5fe8315bcb0cfd9b65bad",
	"89cd099d215ed66c93586484c48994e3d772511768561e0465c74852ff921ac0",
	"366844a98fa179f96019f6f930829c960990ac438da24a945f40791b4ab3771c",
	"736d879d25597e39878548a2efc2b37d7d48744cf621803a97fa84d1337d8478",
}
var kat_32 = []string{
	"f13154701ddb47458310e09b3bd20350fc8ec13b42dfb2f3414fe49dc21054e5",
	"dccc7800c714f9b1e28f6f414ad0760619bf19d319eee3e7a2f7cbae16ec44f4",
	"0a7c0f023c83e81fce3aa8737aa999131f9b1c78db813c8471af2bf41af34959",
	"65afc54bf77ab9a82c306d15e66a993e4af999a9edb08d822cc70e05d4d73866",
	"b05a93ffe94fb3ea4da3430929ea577310c748744e0b9595bd8c4243ac8ffe7a",
	"7ef713863e94b608f95cf4bb63214fb2fd23812d98d88cd06213e2d9d9dce4c0",
	"39a2b9a5411ae63a80a75725abaab5191d394229d2dd44c2476bc2fee88a29b6",
	"354bd2ccf6b8c814bfa644e4bc9e5610d42d1516e3fe342d9878ba7d03033a5c",
	"9e93e4e05072a624170bccb231caacf69faaaaced8b636eed522ac031eb1e25d",
	"104a62c58b72b70f1fe0eac8ca4b8775ddcbd2ec62f07f91e6b54dd578c1a65c",
}
var kat_64 = []string{
	"7a65360991f32d38d8267e9b8fa29f21f59923efa27a39214abb3412d316cf13",
	"13c0a7f42988e36cc0440f056341791fab717a0b1f9a62954489388a77c1447f",
	"5aef7941bda5f7ec4b12141eaf09dcafe741e4aac536f232e167b7c154196999",
	"60a910388695d6aa8d1194e70fa7a502e21e98f50017b8282cab0c6c18e82c62",
	"304ffc725fc4b6515f3ca5b45dc7b86155cab3de57657efe9c647643d93e0d69",
	"e2ce9a2d7acdb4d0cf906e1d072d4448537fa42ac2f3e0d0531a6e6336196eee",
	"081848b14fc7dd83df56c2f2379bdb20266241c428ce09cee65c3b4dd1965989",
	"4c9066103f99d6aaac3dbe5be9ef0dd06f090a8479e458aa3e83e6b26c6d19f3",
	"ac6fb3acbae450b3d75927532a462fadd64a1c0f025b1c416f27b2f41f945567",
	"65190b3eb43adbaa09d9bf2ccf971b70fb382c56e8676dc4a579f8d666f953c2",
}
var kat_128 = []string{
	"4850dc7976386e64a98cdbbb8a886e6d8cdb52c496e9d626f4c8fdd915658494",
	"9d17107e409910f16a43ac73068c2d656db2ca684ba86c0ad7a4cb14ca1bf931",
	"64adc2f8d3594064a32cb1f00ab8ddcfbad33fde6d2398f829c1923cb38d52c5",
	"edad1b81ff0a71bd76ed7984450030ac9cc861e62d432f85ed0ed83b2d463c8a",
	"9d9ae5f83c1a768eb8cd3b3a09aa5d8ba9d659c43fbf00892f0c32b0ead076c2",
	"f27c0674120eace270ae47852a38596ed1867727f6748cd7128682574d4b3a05",
	"d2ee57706149d6838df63dda7b122e32445f0ed2b495fd336c46ce3384a3c0ee",
	"3774f7f8c948792aa4c480d3b9300b5cb91cbb619327a18ee66a89511cad2d92",
	"b915349483e3a85db14fa612327b7eaa1ab201f47d0795a05d06bd5b2d92def2",
	"daed7bab12476abb916a22f092ba52a93da5540506188fb982f538ad98d3db11",
}
var kat_256 = []string{
	"1c3196947f64e22696a151f75ce97f67626ffc089abc4681adc2caf3c4828b1a",
	"2749938e3936a4ffb83583da86f3506a2a88f73248e80f14c50c8c92cd9d4ede",
	"8884f415f33b2d6a91a12b8d4fa0f9641178b62f2a623ff2f9cdff74cf88cf87",
	"8129eb52137edc7c56accf0b9d273b29085f77548693596075db48106c550c0a",
	"2f1b7292868b1e10cceca079f60a065431f1381ce5046d9f6ae7191822110c40",
	"b040ff3ec202020a879c69fc6f51c350d256fb02691aeaa77b1abfd9df6af42b",
	"0f3c4a77457d920a0c87cf5dbfef8899a67aabda08ed5d8f2c5c5e9eb99fff41",
	"1c51ce7bb6fa8b37a3c5ee99a09138bf9fd8310071d8adb91cd692d34e212daf",
	"c3de8a295ef2ed1dfdc4c6a21f6c989c55435890d40e2706424660cb798befdb",
	"230f62ab8fc0d086140584fc8977597f2c591da1f9627aef502c9e9eee9f4abc",
}
var kat_512 = []string{
	"53748d0bda7a655b160d1237687f606fc6d85a768af7e52accb320cdc02fea56",
	"566ff306b9e7a8509252fcbd315faa1c7d9a99e90a6e5a1e211dca0492fd2422",
	"3927502da6d66d09c71baad0fb307e767287bca9defd3e5658093758dd6f4eb6",
	"7d00e218c02ca8e2b0b475c67f06b544d74b24a0c79e775066f6d35b85bba168",
	"5c7e80b3b95bbb04272cf6cb5482f98c5f48303119be7c1864fda7d183cf8dd2",
	"8f8238dc09555fb6a06505af7d08ea909829bab3443c651791e91444d4f9ea29",
	"27dc1593aea3529c25112b536ba38bf7ff26796f7199aff8597db61c013316c4",
	"92770a08ede1e89721661b8812879ab2c1cae3ffe66056fa23e2ac4cc984998b",
	"31e9907ba30080033d48535b1ecbc3e25e6b6b450fb1b310935e8b278654700e",
	"779fb106eb89f09e1d09a7c3c3295d8b63fa93ca3e59de9a9adcc1eb3f392c0c",
}
var kat_1024 = []string{
	"c04a645eb9e60d117d29fe4a0d5314bedf1392cbad20bb15f9cc88ac25cd78e2",
	"1f0e8af75f9abfed60ddafda6286c6fb27395188d3191763eedb05c00c908b39",
	"669de6300e9fa19fbb9675769525d1f68d166297f6a67753c4dda74927c83286",
	"d3990a8b5790cf298949bfae84f0fdee9898c95e56d5c54a8a315b81f521ac41",
	"579d09da76792fcd7047cd3a271b3bddca1f8f0e753b1064466af4c297ca82aa",
	"b0154f77732cf43763902e15e6683525841438343e4423f038990d923ee5e9a8",
	"ece2780b43ae0744b5269730688d41871e5280c2ec6ed66535d9b0ece4a3aca5",
	"51ca0dc5ccae2abb38e39eb2fa8bbc1bbfa46e4dca62bf6bd9666fe1eeb22803",
	"8ae1591a9827357670f983a22cca71e754ede9ccae51f9a2f4bff89354903d0f",
	"cde3f08ca0f7dcf93398bcbed80575c114dc1ddc046cb989385149e6a5deba13",
}

func TestFNDSA_KAT(t *testing.T) {
	testFNDSA_KAT_inner(t, 2, kat_4)
	testFNDSA_KAT_inner(t, 3, kat_8)
	testFNDSA_KAT_inner(t, 4, kat_16)
	testFNDSA_KAT_inner(t, 5, kat_32)
	testFNDSA_KAT_inner(t, 6, kat_64)
	testFNDSA_KAT_inner(t, 7, kat_128)
	testFNDSA_KAT_inner(t, 8, kat_256)
	testFNDSA_KAT_inner(t, 9, kat_512)
	testFNDSA_KAT_inner(t, 10, kat_1024)
	fmt.Println()
}

func testFNDSA_KAT_inner(t *testing.T, logn uint, kat []string) {
	fmt.Printf("[%d]", logn)
	for j := 0; j < len(kat); j++ {
		var seed [6]byte
		seed[0] = 0x00
		seed[1] = byte(logn)
		seed[2] = byte(j)
		seed[3] = byte(j >> 8)
		seed[4] = byte(j >> 16)
		seed[5] = byte(j >> 24)

		var seed_kgen [32]byte
		sh := sha3.NewShake256()
		sh.Write(seed[:])
		sh.Read(seed_kgen[:])
		skey, vkey, err := KeyGen(logn, bytes.NewReader(seed_kgen[:]))
		if err != nil {
			t.Fatal(err)
		}

		seed[0] = 0x01
		ctx := DomainContext([]byte("domain"))
		var id crypto.Hash
		msg := []byte("message")
		if (j & 1) == 0 {
			id = 0
		} else {
			id = crypto.SHA3_256
			hv := sha3.Sum256(msg)
			msg = hv[:]
		}
		sig, err := sign_inner_seeded(logn, logn, seed[:], skey, ctx, id, msg)
		if err != nil {
			t.Fatal(err)
		}
		var r bool
		if logn <= 8 {
			r = VerifyWeak(vkey, ctx, id, msg, sig)
		} else {
			r = Verify(vkey, ctx, id, msg, sig)
		}
		if !r {
			t.Fatalf("signature verification failed (logn=%d, j=%d)", logn, j)
		}

		sc := sha3.New256()
		sc.Write(skey)
		sc.Write(vkey)
		sc.Write(sig)
		tmp := sc.Sum(nil)
		ref, _ := hex.DecodeString(kat[j])
		if !bytes.Equal(tmp, ref) {
			t.Fatalf("KAT failed (logn=%d, j=%d): wrong hash\n", logn, j)
		}

		fmt.Print(".")
	}
}

func BenchmarkKeyGen512(b *testing.B) {
	bench_keygen_inner(b, 9)
}

func BenchmarkKeyGen1024(b *testing.B) {
	bench_keygen_inner(b, 10)
}

func bench_keygen_inner(b *testing.B, logn uint) {
	for i := 0; i < b.N; i++ {
		KeyGen(logn, nil)
	}
}

func BenchmarkSign512(b *testing.B) {
	bench_sign_inner(b, 9)
}

func BenchmarkSign1024(b *testing.B) {
	bench_sign_inner(b, 10)
}

func bench_sign_inner(b *testing.B, logn uint) {
	// Make a key pair.
	sk, vk, _ := KeyGen(logn, nil)

	// Data is a raw message, not pre-hashed, and context is empty.
	data := []byte("test")

	// A few blank signatures for "warm-up".
	for i := 0; i < 10; i++ {
		sig, err := Sign(nil, sk, DOMAIN_NONE, 0, data)
		if err != nil {
			b.Fatalf("failure, err = %v", err)
		}
		if !Verify(vk, DOMAIN_NONE, 0, data, sig) {
			b.Fatalf("ERR: signature verification failed")
		}
		data = sig[len(sig)-32:]
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, _ := Sign(nil, sk, DOMAIN_NONE, 0, data)
		data = sig[len(sig)-32:]
	}
}

func BenchmarkVerify512(b *testing.B) {
	bench_verify_inner(b, 9)
}

func BenchmarkVerify1024(b *testing.B) {
	bench_verify_inner(b, 10)
}

func bench_verify_inner(b *testing.B, logn uint) {
	// Make a key pair.
	sk, vk, _ := KeyGen(logn, nil)

	// Data is a raw message, not pre-hashed, and context is empty.
	data := []byte("test")

	// Compute some signatures.
	var sigs [10][]byte
	for i := 0; i < 10; i++ {
		sigs[i], _ = Sign(nil, sk, DOMAIN_NONE, 0, data)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(vk, DOMAIN_NONE, 0, data, sigs[i%len(sigs)]) {
			b.Fatal("signature verification failed")
		}
	}
}
