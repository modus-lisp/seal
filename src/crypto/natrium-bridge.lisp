;;;; natrium-bridge.lisp — seal's leaf crypto primitives, delegated to natrium.
;;;;
;;;; seal used to carry its own SHA-2, HMAC, ChaCha20-Poly1305, X25519, Ed25519
;;;; and CSPRNG.  Those now live once, in the modus-lisp `natrium` library
;;;; (dependency-free, constant-time, RFC/NIST/Wycheproof-gated), so seal keeps
;;;; only the primitives natrium does not provide — AES-GCM, bignum, RSA and
;;;; ECDSA — and delegates the rest here.  This file preserves seal's public
;;;; crypto names and calling conventions, so the TLS and X.509 layers are
;;;; untouched; it merely maps them onto natrium (adjusting the couple of places
;;;; where the two APIs differ).

(in-package #:seal)

(declaim (inline %u8v))
(defun %u8v (x)
  "Coerce X to a simple (unsigned-byte 8) vector (a no-op when it already is one,
   so no copy)."
  (coerce x '(simple-array (unsigned-byte 8) (*))))

;;; Low-level word-masking helpers that lived in the old sha modules and are
;;; still referenced elsewhere in seal (e.g. tls12 sequence-number arithmetic).
(declaim (inline u32 u64))
(defun u32 (x) (logand x #xffffffff))
(defun u64 (x) (logand x #xffffffffffffffff))

;;; --- hashing (natrium SHA-2) ---------------------------------------------
(defun sha256 (message) (natrium:sha256 (%u8v message)))
(defun sha384 (message) (natrium:sha384 (%u8v message)))
(defun sha512 (message) (natrium:sha512 (%u8v message)))

;;; --- HMAC ----------------------------------------------------------------
(defun hmac-sha256 (key message) (natrium:hmac-sha256 (%u8v key) (%u8v message)))
(defun hmac-sha384 (key message) (natrium:hmac-sha384 (%u8v key) (%u8v message)))

;;; --- ChaCha20-Poly1305 AEAD ----------------------------------------------
;;; seal's contract: encrypt returns (ciphertext . tag); decrypt returns the
;;; plaintext, or NIL on authentication failure.  natrium returns (values ct
;;; tag) and plaintext/NIL respectively.
(defun chacha20-poly1305-encrypt (key nonce plaintext &optional aad)
  (multiple-value-bind (ct tag)
      (natrium:chacha20-poly1305-encrypt (%u8v key) (%u8v nonce) (%u8v plaintext)
                                         (%u8v (or aad #())))
    (cons ct tag)))

(defun chacha20-poly1305-decrypt (key nonce ciphertext tag &optional aad)
  (natrium:chacha20-poly1305-decrypt (%u8v key) (%u8v nonce) (%u8v ciphertext)
                                     (%u8v tag) (%u8v (or aad #()))))

;; The one-time Poly1305 authenticator, exposed for the self-test's RFC 8439 KAT.
(defun poly1305-mac (key message) (natrium:poly1305-mac (%u8v key) (%u8v message)))

;;; --- X25519 --------------------------------------------------------------
(defun x25519 (scalar u) (natrium:x25519 (%u8v scalar) (%u8v u)))
(defun x25519-public-key (scalar) (natrium:x25519-base (%u8v scalar)))

;;; --- Ed25519 verify ------------------------------------------------------
;;; seal's argument order is (public-key signature message); natrium's is
;;; (public-key message signature).
(defun ed25519-verify (public-key signature message)
  (natrium:ed25519-verify (%u8v public-key) (%u8v message) (%u8v signature)))

;;; --- CSPRNG --------------------------------------------------------------
;;; natrium's random-bytes is an HMAC-DRBG seeded from the OS entropy source;
;;; it fails hard rather than falling back to a non-cryptographic PRNG.
(defun secure-random-bytes (n) (natrium:random-bytes n))
