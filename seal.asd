;;;; seal.asd — a pure-Common-Lisp TLS 1.3 client.
(asdf:defsystem :seal
  :description "A clean-room TLS 1.3 client in pure Common Lisp (with a TLS 1.2
fallback and a DTLS 1.2 client for WebRTC): AES-GCM, HKDF, the TLS 1.3 handshake +
record layer, and X.509 validation, over a pluggable
transport. Symmetric/curve crypto (SHA-2, HMAC, ChaCha20-Poly1305, X25519,
Ed25519, CSPRNG) comes from the sibling `natrium` library; seal keeps only what
natrium does not provide (AES-GCM, bignum, RSA, ECDSA). No OpenSSL, no ironclad,
no cl+ssl; platform dependency is SBCL's own sb-bsd-sockets."
  :version "0.0.1"
  :author "ynniv"
  :license "MIT"
  :depends-on ("sb-bsd-sockets" "natrium")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "packages")
     (:file "conditions")
     (:module "crypto"
      :serial t
      :components
      ((:file "natrium-bridge")   ; SHA-2/HMAC/ChaCha20-Poly1305/X25519/Ed25519/CSPRNG -> natrium
       (:file "sha1")            ; legacy hash (interop; not in natrium)
       (:file "des")             ; legacy block cipher (interop: VNC auth); not in natrium
       (:file "hkdf")
       (:file "aes")
       (:file "gcm")
       (:file "bigint")
       (:file "rsa")
       (:file "ecdsa")))
     (:file "x509")
     (:file "verify")
     (:file "transport")
     (:file "tls13")
     (:file "tls12")
     (:file "dtls")            ; DTLS 1.2 client (WebRTC) — reuses the tls12 schedule
     (:file "stream"))))
  :in-order-to ((asdf:test-op (asdf:test-op :seal/test))))

(asdf:defsystem :seal/http
  :description "An HTTP/1.1 client on seal's TLS: URLs, headers, chunked and
Content-Length bodies, and 3xx redirect following.  Separate from :seal on
purpose — seal is a TLS implementation, and a socket carrying some other protocol
should not have to drag an HTTP parser along with it.  Deliberately no cookies,
no charset decoding and no Content-Encoding: those are browser concerns, and
weft.fetch layers them on top of exactly this."
  :version "0.0.1"
  :author "ynniv"
  :license "MIT"
  :depends-on ("seal" "sb-bsd-sockets")
  :serial t
  :components ((:module "src" :serial t :components ((:file "http")))))

(asdf:defsystem :seal/websocket
  :description "An RFC 6455 WebSocket client on seal's TLS.  The framing half is
transport-independent and exported as such, so a caller with its own sockets can
keep the protocol and bring its own transport; CONNECT is the hosted convenience.
Separate from :seal for the same reason :seal/http is."
  :version "0.0.1"
  :author "ynniv"
  :license "MIT"
  :depends-on ("seal" "sb-bsd-sockets")
  :serial t
  :components ((:module "src" :serial t :components ((:file "websocket")))))

(asdf:defsystem :seal/test
  :depends-on ("seal")
  :components
  ((:module "inspect"
    :serial t
    :components
    ((:file "util")
     (:file "vectors")
     (:file "negatives")
     (:file "tls12")
     (:file "live")
     (:file "self-test"))))
  :perform (asdf:test-op (o c)
             (declare (ignore o c))
             (funcall (read-from-string "seal::run-self-test"))))
