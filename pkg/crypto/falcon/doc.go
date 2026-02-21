// This package implements the FN-DSA signature algorithm.
//
// WARNING: FN-DSA is currently being specified by NIST, based on the
// Falcon algorithm submitted to the [PQC project]. This implementation
// is a prospective guess on what FN-DSA will look like. When the (draft)
// standard is published, this code will be adjusted, very probably
// breaking backward compatibility. As such, this code should right now
// be used only for tests and concept/prototype purposes.
//
// FN-DSA key pairs and signatures are characterized by a degree, which is
// a power of two. Standard degrees are 512 and 1024, corresponding to two
// formal "security levels" (both are unbreakable right now and in the
// foreseeable future). This implementation also supports lower degrees
// 4 to 256, which do not provide sufficient security but are convenient for
// some research and test purposes; however, the use of these lower degrees
// is segregated at the API level, and thus must be explicitly allowed by
// the calling application.
//
// When the degree must be provided at the API level, it is specified
// logarithmically, as a parameter called "logn" ranging from 2 to 10
// (values 9 and 10 correspond to degrees 512 and 1024, respectively).
//
// A key pair consists of a signing key (private) and a verifying key
// (public). Each key is exchanged in an encoded format which has a fixed
// size (for a given degree); the [SigningKeySize] and [VerifyingKeySize]
// functions return that size. A new key pair is created with the [KeyGen]
// function, which takes as parameter the degree (logn) and a source of
// randomness. The random source MUST be cryptographically secure. If the
// source is nil, then the operating system's RNG is used (through
// crypto/rand.Reader).
//
// A signature is generated using a signing key, and over a message to
// sign. Signatures have a fixed size for a given degree; the
// [SignatureSize] function returns that size. The message is
// "pre-hashed" and provided as three elements: a domain separation
// context string, an identifier for the pre-hash function, and the
// pre-hashed data itself. The context string is an arbitrary
// (non-secret) sequence of up to 255 bytes. The identifier is one of
// the [crypto/hash.Hash] constants such as SHA3_256; value 0 can be
// used to indicate a "raw" message, i.e. not actually pre-hashed, in
// which case the pre-hashed data is the message itself. The signing
// call is made with either [Sign] (for standard degrees 512 and 1024)
// or [SignWeak] (for test/research degrees 4 to 256). As for key pair
// generation, signing uses a cryptographically secure random source,
// which is usually left to nil to make it use the system's RNG.
//
// Signature verification is performed with the [Verify] or [VerifyWeak]
// functions (again segregated by degree); the verifying key, pre-hashed
// message (along with the domain context string and the pre-hash
// function identifier), and the signature are provided, and the output
// is Boolean.
//
// [PQC project]: https://www.nist.gov/pqcrypto
package fndsa
