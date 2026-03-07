# Sovereign Sockets

## What is a Sovereign Socket?

A sovereign socket is a network endpoint whose identity is a cryptographic keypair, not a domain name, not an IP address, not a certificate issued by a third party. It is self-generated, self-authenticating, and unforgeable. No registry, certificate authority, or DNS authority can revoke it, reassign it, or impersonate it. The socket owns itself.

Traditional sockets derive their identity from infrastructure you don't control. A TCP socket is identified by an IP address assigned by your ISP and a port managed by your OS. A WebSocket endpoint is identified by a URL, a domain name registered through ICANN, resolved by third-party DNS servers, and authenticated by a certificate signed by a certificate authority. At every layer, someone else holds the keys to your identity.

A sovereign socket inverts this. Identity is a 32-byte public key that you generate locally. You prove ownership by completing a cryptographic handshake, not by presenting a certificate signed by a trusted third party, but by demonstrating knowledge of the corresponding private key. The network address (IP and port) is a transport detail, like a phone number. It can change. The identity cannot be taken from you.

If you use Nostr, you already understand this concept at the application layer. Your nsec is yours. Your npub is your identity. No one issued it to you, and no one can revoke it. A sovereign socket extends that same principle down to the transport layer. The connection itself is authenticated by keys you own, through a protocol that requires no third-party infrastructure to establish trust.

Instead of connecting to `wss://relay.example.com`, you connect to:

```
wire://wpub1rkljs3eq0zxqt8g6dmv7pcnw5afy29hejud5hsfcxpl84rg3ty9kwn66zf@95.217.5.195:55900
```

The public key is the identity. The IP address is just a hint for how to reach it.

## The Current Nostr Stack and Its Trust Dependencies

When a Nostr client connects to a relay, the application layer is beautifully sovereign, events are signed by the user's key, verifiable by anyone, censorable by no one who doesn't control the relay itself. But the transport layer underneath tells a different story. Consider what actually happens when your client opens `wss://relay.example.com`:

**DNS resolution.** Your client asks a DNS resolver (often your ISP's, or Google's, or Cloudflare's) to translate `relay.example.com` into an IP address. That domain name is registered through ICANN's hierarchical system, a registrar, a registry, a TLD operator. Any of these entities can seize, suspend, or redirect the domain. Your DNS resolver sees which relay you're connecting to and when. If the domain is seized, the relay's identity is gone.

**TLS certificate.** WebSocket Secure requires the relay to present a TLS certificate signed by a certificate authority. The CA system is a trust hierarchy rooted in a few dozen organizations whose root certificates are bundled into your operating system. CAs can be compelled by governments to issue fraudulent certificates. CAs can revoke a relay's certificate, making it unreachable to clients that perform revocation checks. The certificate itself is logged in public Certificate Transparency logs, creating a permanent public record of the relay's domain.

**TCP connection.** The WebSocket runs over TCP, a connection-oriented protocol designed in 1981. TCP connections have state that middleboxes, firewalls, ISP equipment, censorship infrastructure, can track and manipulate. A TCP connection can be reset by injecting a RST packet. It suffers from head-of-line blocking: a single lost packet stalls all data behind it, even if that data is unrelated.

**WebSocket framing.** On top of TCP and TLS, the WebSocket protocol adds its own framing layer. This exists primarily for browser compatibility, it was designed to tunnel bidirectional communication through HTTP infrastructure. It adds overhead and complexity that serves no purpose outside the browser.

**Relay identity = domain name.** The relay's identity in the Nostr ecosystem is its WebSocket URL. If the operator loses the domain, through seizure, expiration, or registrar dispute, the relay loses its identity, its reputation, its place in clients' relay lists. The operator never truly owned the endpoint. The registrar did.

The dependency chain looks like this:

```
Your Nostr event (sovereign, signed by your key)
    ↓
WebSocket frame (browser compatibility layer)
    ↓
TLS (certificate authority trust hierarchy)
    ↓
TCP (stateful, injectable, blockable)
    ↓
DNS (ICANN, registrars, resolvers, all third parties)
    ↓
IP (assigned by ISP/hosting provider)
```

Your signed event at the top is sovereign. Everything beneath it is not.

## How Wiresocket Replaces This Stack

Wiresocket is a UDP-based event-stream protocol that uses the Noise IK handshake pattern (the same cryptographic framework used by WireGuard) to establish encrypted, mutually authenticated sessions between peers identified solely by their public keys. Here is how it maps to each layer of the current stack:

**DNS → out-of-band key exchange.** A wiresocket relay's identity is its X25519 public key, 32 bytes. This key can be shared through any channel: a Nostr event, a QR code, a text message, a printed string. The client needs the relay's public key and an IP address (or any route to the relay). No registrar is involved. No one can seize a public key.

Where today a relay publishes `wss://relay.example.com`, a wiresocket relay publishes:

```
wire://wpub1j83kf5n4vhx20gwsm6ct9raz7elpq8yd3uf0nw2xk5rcjg7et4qhaysmv@203.0.113.42:9000
```

That string contains everything a client needs to connect: the relay's permanent identity and a current network address. If the relay moves to a new host, only the address after the `@` changes. The identity before it stays forever.

**TLS/CAs → Noise IK handshake.** Wiresocket authenticates both peers using a two-message Noise IK handshake. The client already knows the relay's public key and proves it during the first message. The relay decrypts the client's public key from that same message and can authenticate the client directly, by public key, not by session cookie or OAuth token. No certificate authority is consulted. No certificate is presented. Trust is established solely between the two keypairs.

**TCP → UDP.** Wiresocket runs over UDP. There is no connection state for middleboxes to track or inject into. No three-way handshake to block. No RST packets to forge. Wiresocket handles reliability at the application layer where it's needed, per-channel, using selective acknowledgments, avoiding TCP's head-of-line blocking where a lost packet in one stream stalls all others.

**WebSocket → wiresocket frames.** Wiresocket's binary frame format is purpose-built for event streaming. Each frame carries one or more events, each with a type byte and a binary payload. A single connection supports up to 65,535 multiplexed logical channels. Fragmentation, reassembly, and optional per-channel reliability are built into the protocol. There is no HTTP upgrade negotiation, no text/binary mode distinction, no masking overhead.

**Domain-based identity → key-based identity.** When a relay moves to a new IP address, new hosting provider, new country, new network, its identity doesn't change. The public key is the identity. Clients that know the relay's key can reconnect to the new address. There is no DNS propagation delay, no certificate reissuance, no downtime while the world's DNS caches expire.

The new stack:

```
Your Nostr event (sovereign, signed by your key)
    ↓
Wiresocket frame (binary event-stream, multiplexed channels)
    ↓
Noise IK encryption (mutual auth by keypair, no CAs)
    ↓
UDP (stateless, no connection tracking)
    ↓
IP hint (transport detail, not identity)
```

Every layer is either sovereign or a stateless transport detail.

## Privacy Benefits

The trust dependencies in the current stack are not just points of failure, they are points of surveillance. Each one leaks metadata about who is communicating with whom.

**No DNS lookups.** When you connect to `wss://relay.example.com`, your DNS resolver sees the relay's domain name. Your ISP logs it. DNS-level censorship and surveillance systems record it. With wiresocket, you connect to an IP address directly. No domain name is resolved. No relay identity is leaked to any resolver. Your client connects to `wire://wpub1j83kf5...@203.0.113.42:9000` and the only thing your network sees is a UDP packet to `203.0.113.42`.

**No SNI metadata.** TLS, despite encrypting application data, transmits the server's hostname in plaintext during the handshake via the Server Name Indication (SNI) extension. This is visible to every network observer between client and server. It is the primary mechanism by which nation-state firewalls identify and block specific services. Wiresocket's Noise IK handshake contains no hostname, no server identifier, no plaintext metadata. An observer sees UDP packets to an IP address, nothing more.

**Encrypted from the first byte.** In the Noise IK handshake, the client's static public key is encrypted in the very first message. The server's identity is never transmitted at all, the client already knows it. There is no plaintext certificate chain, no negotiation of cipher suites, no protocol version advertisement. The handshake is indistinguishable from random data to a passive observer.

**No certificate transparency logs.** Every TLS certificate issued by a public CA is logged in Certificate Transparency logs, public, append-only ledgers that anyone can search. This means that every domain a relay operator registers is publicly discoverable, permanently. Sovereign sockets have no certificates. There is nothing to log.

**IP address decoupling.** Because identity is key-based, a relay can change IP addresses freely, moving between hosting providers, rotating through Tor exit nodes, or operating behind a shifting set of addresses. Clients reconnect by public key, not by address. The relay's network location becomes fluid while its identity remains fixed. A relay that was at `wire://wpub1j83kf5...@203.0.113.42:9000` can move to `wire://wpub1j83kf5...@198.51.100.7:9000` and clients recognize it as the same relay, because it is.

**Mutual authentication without identity servers.** In the current stack, if a relay wants to know who you are (NIP-42 AUTH), it must implement an authentication flow over the already-established WebSocket, a protocol exchange on top of an unrelated transport layer. With wiresocket, the relay receives your public key during the handshake itself, encrypted and authenticated. Authentication is not a feature bolted on top, it is the handshake. No OAuth endpoints, no login forms, no session cookies, no additional round trips.

**No protocol fingerprint.** WebSocket connections begin with an HTTP upgrade request, a distinctive pattern that deep packet inspection (DPI) systems can easily identify and block. TLS handshakes have their own fingerprint (JA3/JA4). Wiresocket's UDP packets carry no distinguishing protocol markers visible to passive observers.

## What This Means for Nostr

**Relay sovereignty.** A relay operator generates a keypair and that keypair is the relay's permanent identity. The operator can move between hosting providers, change IP addresses, operate from multiple locations simultaneously, the identity follows the key, not the infrastructure. No domain registrar can seize it. No certificate authority can revoke it. No hosting provider can deplatform the identity itself, only the current IP, which can be replaced.

**Client sovereignty.** Clients authenticate to relays during the handshake using their own keypair. This is not an application-layer bolt-on like NIP-42, it is part of establishing the connection. The relay knows the client's public key before any Nostr event is exchanged. Access control, rate limiting, and paid relay authorization can all be implemented at the transport layer, based on cryptographic identity rather than IP addresses or bearer tokens.

**Censorship resistance.** The DNS→CA→TCP dependency chain is a series of chokepoints, each controlled by a small number of entities, each subject to legal and extralegal pressure. Remove them and the only thing an adversary can target is the IP address itself. IP addresses can be changed, tunneled through VPNs or Tor, multiplexed across CDNs, or distributed through gossip. The relay's identity survives all of these transitions because it was never coupled to the network location in the first place.

**Lighter infrastructure.** Running a Nostr relay today requires: a domain name (annual renewal), TLS certificates (Let's Encrypt automation, renewal cron jobs), a reverse proxy for TLS termination (nginx, caddy), and the relay software itself. With wiresocket, the relay software opens a UDP socket with its private key. That's it. No certificate management, no reverse proxy, no domain registration. The barrier to running a relay drops to: a machine with a public IP and a keypair.

**Multiplexed channels.** A single wiresocket connection supports 65,535 logical channels. A relay could dedicate separate channels to different subscription filters, separate channels for ephemeral versus persistent events, a channel for binary blob transfer (images, video segments), a channel for real-time presence or typing indicators, all over one encrypted connection, without the overhead of opening and managing multiple WebSocket connections.

**Built-in DoS mitigation.** Wiresocket implements WireGuard's cookie mechanism for handshake flood protection. Under load, the server responds with a cookie reply that requires the client to prove IP address ownership, without the server maintaining any per-client state. This is fundamentally more efficient than TCP SYN flood mitigation, which requires kernel-level intervention or specialized hardware.

## The Path Forward

Sovereign sockets do not replace Nostr's application-layer protocol. Events are still signed with your nsec. Filters still work. NIPs still define the vocabulary. What changes is the transport layer beneath, the part that currently depends on DNS, certificate authorities, and TCP.

A relay's identity would become its public key, optionally accompanied by one or more IP address hints, similar to how Lightning Network nodes are identified by a public key plus a network address. Where today a client's relay list contains WebSocket URLs:

```
wss://relay.example.com
wss://nostr.otherdomain.io
wss://paid-relay.site/ws
```

It would instead contain sovereign socket addresses:

```
wire://wpub1rkljs3eq0zxqt8g6dmv7pcnw5afy29hejud5hsfcxpl84rg3ty9kwn66zf@95.217.5.195:55900
wire://wpub1j83kf5n4vhx20gwsm6ct9raz7elpq8yd3uf0nw2xk5rcjg7et4qhaysmv@203.0.113.42:9000
wire://wpub1n60sw2xk5fvpj83hqetcraz7l4gmyd3u09nw28k5rcjg7elmq4tqka43gh@198.51.100.7:4433
```

No domains. No certificates. Just keys and addresses.

Client libraries would need a wiresocket transport adapter alongside their existing WebSocket transport. Relay software could adopt wiresocket as an alternative listener, running both transports simultaneously during any transition period. A NIP could formalize the `wire://` URI scheme and define how relay public keys are published in kind-10002 relay list events.

The application layer stays sovereign. The transport layer becomes sovereign too.
