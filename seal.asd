;;;; seal.asd — a pure-Common-Lisp TLS 1.3 client.
(asdf:defsystem :seal
  :description "A clean-room TLS 1.3 client in pure Common Lisp: AES-GCM,
ChaCha20-Poly1305, SHA-2, HKDF, X25519 and the TLS 1.3 handshake + record
layer, over a pluggable transport. No OpenSSL, no ironclad, no cl+ssl — the
only platform dependency is SBCL's own sb-bsd-sockets."
  :version "0.0.1"
  :author "ynniv"
  :license "MIT"
  :depends-on ("sb-bsd-sockets")
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
      ((:file "sha256")
       (:file "sha512")
       (:file "hmac")
       (:file "hkdf")
       (:file "aes")
       (:file "gcm")
       (:file "chacha20")
       (:file "poly1305")
       (:file "aead")
       (:file "x25519")
       (:file "bigint")
       (:file "rsa")
       (:file "ecdsa")
       (:file "ed25519")
       (:file "entropy")))
     (:file "x509")
     (:file "verify")
     (:file "transport")
     (:file "tls13")
     (:file "stream"))))
  :in-order-to ((asdf:test-op (asdf:test-op :seal/test))))

(asdf:defsystem :seal/test
  :depends-on ("seal")
  :components
  ((:module "inspect"
    :serial t
    :components
    ((:file "util")
     (:file "vectors")
     (:file "negatives")
     (:file "live")
     (:file "self-test"))))
  :perform (asdf:test-op (o c)
             (declare (ignore o c))
             (funcall (read-from-string "seal::run-self-test"))))
