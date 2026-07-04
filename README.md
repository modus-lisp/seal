# seal

**A TLS 1.3 client in pure Common Lisp.** Clean-room — no OpenSSL, no cl+ssl, no
ironclad, no FFI to any C crypto library. The only platform dependency is SBCL's
own `sb-bsd-sockets` for the default TCP transport. A seal closes a channel.

seal takes a hostname and gives you an authenticated-encryption byte channel: the
whole stack, from the AES / ChaCha20 / SHA-2 / X25519 primitives through the
TLS 1.3 handshake and record layer, implemented from scratch. It is the secure
transport for [`weft`](https://github.com/modus-lisp) (a pure-CL web engine) but
stands alone.

> ⚠️ **Security status: from-scratch, unaudited, research/educational.** This is
> not a hardened TLS stack. It is **not constant-time** and makes **no claim of
> side-channel resistance**. By default it performs **no certificate
> validation** — see [Certificate validation](#certificate-validation) below.
> **Without certificate validation there is no protection against a
> man-in-the-middle.** Do not use it to protect anything you cannot afford to
> lose.

## What works

| Layer | Coverage |
|---|---|
| **Handshake** | TLS 1.3 full 1-RTT (RFC 8446), X25519 key exchange, SNI, ALPN |
| **Cipher suites** | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` |
| **Key schedule** | HKDF-Expand-Label traffic secrets, handshake + application keys, Finished verify |
| **Record layer** | AEAD record protection, fragmentation, `close_notify` |
| **Certificates** | X.509 DER parsing: subject, issuer, validity, subjectAltName, SubjectPublicKeyInfo |
| **Transport** | pluggable; default TCP over `sb-bsd-sockets` |
| **Stream** | Gray-stream wrapper — reads/writes like an ordinary binary stream |

Not implemented: client certificates, PSK / session resumption / 0-RTT, TLS 1.2
fallback, key update, groups other than X25519, certificate **chain**
validation.

## Correctness

Every cryptographic primitive is checked against official test vectors
(`inspect/vectors.lisp`) — all must match exactly:

- **AES-128/256** — FIPS-197 known-answer blocks
- **AES-GCM** — McGrew–Viega / NIST GCM Test Cases 3 & 4 (ciphertext + tag, and round-trip)
- **SHA-256/384/512** — FIPS 180-4 (`""` and `"abc"`)
- **HMAC-SHA256/384** — RFC 4231
- **HKDF** — RFC 5869
- **ChaCha20-Poly1305 / Poly1305** — RFC 8439 §2.5.2, §2.8.2
- **X25519** — RFC 7748 §5.2 (both scalar/u vectors and the Diffie-Hellman test)

The handshake is checked live against real servers (`inspect/live.lisp`):
`example.com`, `www.google.com`, `en.wikipedia.org`, `news.ycombinator.com`,
`www.cloudflare.com`, `github.com` — each completes a handshake and returns a
valid HTTP status line.

## Quick start

```lisp
(require :asdf)
(push #p"/path/to/seal/" asdf:*central-registry*)
(asdf:load-system :seal)

(in-package :seal)

;; one-shot: open, GET, print status, close
(with-connection (conn "example.com" 443)
  (tls-send conn (format nil "GET / HTTP/1.1~c~cHost: example.com~c~cConnection: close~c~c~c~c"
                         #\return #\newline #\return #\newline
                         #\return #\newline #\return #\newline))
  (let ((resp (tls-recv conn)))
    (write-string (map 'string #'code-char resp))))
```

As an ordinary Lisp stream:

```lisp
(let* ((conn (connect "example.com" 443))
       (s (make-tls-stream conn)))
  (write-sequence (map 'vector #'char-code "GET / HTTP/1.1...") s)
  (force-output s)
  (read-byte s)          ; ... etc; close flushes + tears down TLS
  (close s))
```

## API

Connection lifecycle:

- `(connect host port &key verify timeout transport alpn early-data)` → a `tls-connection`
- `(tls-send conn data)` — `data` a byte vector or string
- `(tls-recv conn)` — next application-data chunk, or `nil` at end of stream
- `(tls-close conn)` — send `close_notify`, close the transport
- `(with-connection (var host port ...) body...)` — open / run / close

Introspection:

- `(tls-connection-cipher conn)` — negotiated suite name
- `(tls-connection-alpn conn)` — negotiated ALPN protocol
- `(tls-connection-peer-certificates conn)` — list of parsed `certificate`s
- `certificate-subject`, `certificate-issuer`, `certificate-not-before`,
  `certificate-not-after`, `certificate-subject-alt-names`,
  `certificate-public-key-info`, `certificate-raw`

Stream: `(make-tls-stream conn)` → a `tls-stream` (bidirectional binary Gray stream).

Transport (pluggable): a `transport` bundles three closures — `transport-send`,
`transport-recv`, `transport-close`. `make-socket-transport` is the default TCP
backend; pass your own via `:transport` to run seal over a different stack (e.g.
a bare-metal TCP/IP implementation).

The crypto primitives are exported too and usable on their own: `sha256`,
`sha384`, `sha512`, `hmac-sha256`, `hmac-sha384`, `hkdf-extract`, `hkdf-expand`,
`aes-gcm-encrypt`/`-decrypt`, `chacha20-poly1305-encrypt`/`-decrypt`, `x25519`,
`x25519-public-key`, `secure-random-bytes`.

## Certificate validation

seal **parses** the server's certificate chain and exposes it, and offers a
`:verify` hook on `connect`:

- `:verify nil` (default) — **no authentication at all.** The channel is
  encrypted but **not authenticated**: a man-in-the-middle who can intercept the
  TCP connection can present any certificate and seal will proceed. Use only
  against hosts you already trust by other means.
- `:verify :hostname` — checks that the **leaf** certificate presents a name
  (subjectAltName dNSName, or CN) matching `host`, with single-label wildcard
  support (RFC 6125). **This is a name check only.** It does **not** build or
  validate the chain to a trusted CA, does **not** check the CA signatures, and
  does **not** check expiry or revocation — so on its own it does **not** stop a
  MITM who can obtain any certificate for the name.
- `:verify <function>` — your own `(certificates host) → generalized-boolean`;
  return false (or signal) to reject. Use this to plug in real chain validation.

**What is validated today:** the server's Finished (transcript MAC), i.e. that
the peer holds the negotiated handshake keys. **What is deferred:** X.509 chain
building, CA-signature verification against a trust store, validity-period and
revocation checks, and the CertificateVerify signature. Full authentication is a
future milestone; until then, treat seal as providing confidentiality against a
passive eavesdropper only.

## Randomness

Ephemeral keys and nonces come from `secure-random-bytes`, which reads
`/dev/urandom`. If that is unavailable it falls back to the (non-cryptographic)
Lisp PRNG and emits a warning — a bare-metal or restricted host should supply a
real CSPRNG.

## Tests

```lisp
(asdf:test-system :seal)          ; crypto vectors + one live handshake
```

or from a shell:

```sh
sbcl --script inspect/run.lisp    ; all vectors + all live hosts; non-zero exit on failure
```

## License

MIT. See `LICENSE`.
