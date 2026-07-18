# seal

**A TLS 1.3 client in pure Common Lisp** — with a TLS 1.2 fallback and a **DTLS 1.2**
client (for WebRTC). Clean-room — no OpenSSL, no cl+ssl, no
ironclad, no FFI to any C crypto library. The symmetric and curve primitives come
from its pure-CL sibling [`natrium`](https://github.com/modus-lisp/natrium)
(constant-time SHA-2 / HMAC / HKDF / ChaCha20-Poly1305 / X25519 / Ed25519,
RFC/NIST/Wycheproof-gated); seal implements the rest itself — AES-GCM, bignum, RSA
and ECDSA. The only platform dependency is SBCL's own `sb-bsd-sockets` for the
default TCP transport. A seal closes a channel.

seal takes a hostname and gives you an authenticated-encryption byte channel: the
whole stack, from the AEAD / signature / curve primitives through the TLS 1.3
handshake and record layer, implemented from scratch across seal and natrium. It
is the secure transport for [`weft`](https://github.com/modus-lisp) (a pure-CL web
engine) but stands alone.

> ⚠️ **Security status: from-scratch, unaudited, research/educational.** This is
> not a hardened TLS stack. It is **not constant-time** and makes **no claim of
> side-channel resistance**. It now performs **full certificate validation by
> default** (`:verify t`: chain to a trusted CA + signatures + validity dates +
> hostname + CertificateVerify — see [Certificate validation](#certificate-validation)),
> but it has **not been audited**, and revocation (OCSP/CRL), name constraints,
> and full policy/EKU processing are **not** implemented. Do not use it to
> protect anything you cannot afford to lose.

## What works

| Layer | Coverage |
|---|---|
| **Handshake** | TLS 1.3 full 1-RTT (RFC 8446), X25519 key exchange, SNI, ALPN; TLS 1.2 fallback (RFC 5246, ECDHE) |
| **DTLS 1.2** | client (RFC 6347) for WebRTC: record/flight/cookie layer + **mutual auth** (client Certificate + CertificateVerify) over the TLS 1.2 schedule — verified against aiortc |
| **Cipher suites** | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` |
| **Key schedule** | HKDF-Expand-Label traffic secrets, handshake + application keys, Finished verify |
| **Record layer** | AEAD record protection, fragmentation, `close_notify` |
| **Certificates** | X.509 DER parsing: subject, issuer, validity, subjectAltName, SubjectPublicKeyInfo, basicConstraints, keyUsage |
| **Cert validation** | **Full chain to a trusted CA**, signatures, validity dates, hostname, CertificateVerify — fails closed |
| **Signatures** | RSA PKCS#1-v1.5 & PSS (SHA-256/384/512), ECDSA P-256 & P-384, Ed25519 — pure CL, verification |
| **Trust store** | system CA bundle (Linux/macOS) or a bundled/one-off PEM, configurable per `connect` |
| **Transport** | pluggable; default TCP over `sb-bsd-sockets` |
| **Stream** | Gray-stream wrapper — reads/writes like an ordinary binary stream |

Not implemented: TLS client certificates (the **DTLS** client does mutual auth), PSK /
session resumption / 0-RTT, key update, groups other than X25519, and — within certificate
validation — **revocation (OCSP/CRL), name constraints, and full policy/EKU
enforcement** (see [Certificate validation](#certificate-validation)).

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
- **RSA PKCS#1-v1.5 & PSS** — SHA-256/384/512 known-answer signatures (2048-bit key)
- **ECDSA P-256 / P-384** — RFC 6979 known-answer signatures
- **Ed25519** — RFC 8032 §7.1 test vectors

Certificate validation is checked two ways. Live, full validation (`:verify t`)
succeeds against real servers (`inspect/live.lisp`) spanning both signature
families — `www.google.com` (RSA leaf), `www.cloudflare.com` / `github.com` /
`example.com` (ECDSA leaves), `news.ycombinator.com` / `en.wikipedia.org`
(ECDSA/SHA-384) — each building and verifying a chain to a system-trusted root.
And offline, an adversarial suite (`inspect/negatives.lisp`) proves seal **fails
closed**: a self-signed cert, a chain to an unknown root, an expired cert, a
wrong-hostname cert, a tampered signature, and a non-CA issuer are each
**rejected** with the appropriate `tls-certificate-error` subclass.

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

- `(connect host port &key verify trust-store timeout transport alpn early-data)` → a `tls-connection`
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
  `certificate-public-key-info`, `certificate-raw`, `certificate-ca-p`,
  `certificate-sig-scheme`, `certificate-sig-hash`

Stream: `(make-tls-stream conn)` → a `tls-stream` (bidirectional binary Gray stream).

Transport (pluggable): a `transport` bundles three closures — `transport-send`,
`transport-recv`, `transport-close`. `make-socket-transport` is the default TCP
backend; pass your own via `:transport` to run seal over a different stack (e.g.
a bare-metal TCP/IP implementation).

The crypto primitives are exported too and usable on their own: `sha256`,
`sha384`, `sha512`, `hmac-sha256`, `hmac-sha384`, `hkdf-extract`, `hkdf-expand`,
`aes-gcm-encrypt`/`-decrypt`, `chacha20-poly1305-encrypt`/`-decrypt`, `x25519`,
`x25519-public-key`, `secure-random-bytes`, and the signature verifiers
`rsa-pkcs1-verify`, `rsa-pss-verify`, `ecdsa-verify`, `ed25519-verify`.

## Certificate validation

`connect` takes a `:verify` policy (default `t`) and a `:trust-store`:

- `:verify t` **(default)** — **full authentication**, and the value to use for
  real work. seal builds the certificate chain the server sent, verifies each
  link's signature under its issuer's public key, anchors the chain to a **CA in
  the trust store**, checks every certificate's **validity window**
  (notBefore/notAfter), requires intermediates to be marked `CA:TRUE`, checks
  the **hostname** against the leaf's subjectAltName/CN (RFC 6125 single-label
  wildcards), and verifies the server's **CertificateVerify** signature (proof
  that the peer holds the leaf's private key). Any failure signals a specific
  `tls-certificate-error` subclass — it never connects on a bad certificate.
- `:verify :hostname` — leaf-name check + CertificateVerify only; **no** chain to
  a CA. Weaker; does not stop a MITM who can obtain any valid-looking cert.
- `:verify nil` — **no authentication at all.** Encrypted but unauthenticated;
  a MITM can present any certificate. Use only against hosts trusted by other means.
- `:verify <function>` — your own `(certificates host) → generalized-boolean`.

The trust anchors come from `:trust-store`:

- `:system` (default) — the OS CA bundle (`/etc/ssl/certs/ca-certificates.crt`
  and other well-known Linux/macOS paths).
- a pathname/string — a bundled or one-off PEM file of trusted roots.
- a `trust-store` object — build one with `make-trust-store-from-pem`.

```lisp
(connect "example.com" 443)                         ; full validation, system roots
(connect "internal.host" 443 :trust-store #p"my-ca.pem")
(connect "localhost" 8443 :verify nil)              ; opt out (unauthenticated)
```

Failures are discriminable conditions, all subclasses of `tls-certificate-error`
(itself a `tls-verify-error`): `tls-certificate-untrusted-error`,
`tls-certificate-expired-error`, `tls-certificate-hostname-error`,
`tls-certificate-bad-signature-error`.

**What is validated:** chain to a trusted CA; RSA (PKCS#1-v1.5 and PSS) and
ECDSA (P-256/P-384) and Ed25519 signatures on every link and on
CertificateVerify; validity dates; basicConstraints `CA:TRUE` on issuers;
hostname; and the server's Finished (transcript MAC).

**What is NOT validated (deferred):** certificate **revocation** (OCSP / CRL),
**name constraints**, and full certificate-**policy / extended-key-usage**
processing. seal's own primitives (AES-GCM, RSA, ECDSA) are **not constant-time**
and the whole is **unaudited** — research-grade. (The primitives it delegates to
`natrium` — ChaCha20-Poly1305, X25519, Ed25519 — are written in a constant-time
discipline.)

## Randomness

Ephemeral keys and nonces come from `secure-random-bytes`, which delegates to
natrium's `random-bytes` — an HMAC-DRBG (NIST SP 800-90A) seeded from the OS
entropy source (`/dev/urandom` by default, overridable on a bare-metal host).
Unlike a bare `/dev/urandom` read it **fails closed** rather than falling back to
a non-cryptographic PRNG.

## Tests

```lisp
(asdf:test-system :seal)          ; crypto vectors + negative cert tests + one live handshake
```

or from a shell:

```sh
sbcl --script inspect/run.lisp    ; all vectors + negative cert suite + all live hosts; non-zero exit on failure
```

## License

MIT. See `LICENSE`.
