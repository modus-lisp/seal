;;;; ehbp.lisp — Encrypted HTTP Body Protocol (EHBP) framing on top of HPKE.
;;;;
;;;; This is the wire format Tinfoil's inference enclaves speak (the `ehbp` JS
;;;; package, v0.3.2, is the reference). Only the body is encrypted; headers
;;;; route the request.
;;;;
;;;;   Request:
;;;;     header  Ehbp-Encapsulated-Key: hex(enc)
;;;;     body    u32be(len) || AEAD(seq 0, aad "", ct)        ; SetupBaseS, info "ehbp request"
;;;;   Response:
;;;;     header  Ehbp-Response-Nonce: hex(32 bytes)
;;;;     body    repeated [ u32be(len) || AEAD(seq n, aad "", ct) ]
;;;;             where secret = Export("ehbp response", 32), salt = enc || nonce,
;;;;             prk = Extract(salt, secret), key = Expand(prk,"key",32),
;;;;             nonce_base = Expand(prk,"nonce",12), nonce_n = nonce_base XOR n.
;;;;             A zero-length frame is skipped, as the reference does.

(in-package #:seal)

(defparameter +ehbp-request-info+ "ehbp request")
(defparameter +ehbp-response-label+ "ehbp response")
(defconstant +ehbp-response-nonce-len+ 32)
(defconstant +ehbp-max-chunk+ (* 64 1024 1024))

(defstruct ehbp-request
  "Result of EHBP-SEAL-REQUEST: the enc to send as a header, the framed body, and
the HPKE sender context needed to derive the response keys."
  enc
  body
  context)

(defun %u32be (n)
  (%hpke-i2osp n 4))

(defun ehbp-seal-request (pk-r plaintext)
  "Encrypt PLAINTEXT to the enclave's public key PK-R (32 bytes). Returns an EHBP-REQUEST."
  (multiple-value-bind (ctx enc)
      (hpke-setup-sender pk-r (%hpke-ascii +ehbp-request-info+))
    (let* ((ct (hpke-seal ctx plaintext))
           (body (%hpke-bytes (%u32be (length ct)) ct)))
      (make-ehbp-request :enc enc :body body :context ctx))))

(defun ehbp-response-keys (ctx enc response-nonce)
  "Derive the response AEAD key and nonce base from the request's HPKE context.
Returns (values key nonce-base)."
  (unless (= (length response-nonce) +ehbp-response-nonce-len+)
    (error "EHBP: response nonce must be ~a bytes" +ehbp-response-nonce-len+))
  (let* ((secret (hpke-export ctx (%hpke-ascii +ehbp-response-label+) 32))
         (salt (%hpke-bytes enc response-nonce))
         (prk (hkdf-extract salt secret :sha256))
         (key (hkdf-expand prk (%hpke-ascii "key") 32 :sha256))
         (nonce-base (hkdf-expand prk (%hpke-ascii "nonce") 12 :sha256)))
    (values key nonce-base)))

;;; Key configuration (RFC 9458 section 3, media type application/ohttp-keys), as
;;; served at /.well-known/hpke-keys.  One KeyConfig:
;;;   key_id u8 | kem_id u16 | public_key (Npk bytes) | symmetric_algorithms (u16 len,
;;;   then (kdf_id u16, aead_id u16) pairs)
(defstruct ehbp-key-config key-id kem-id public-key symmetric)

(defun ehbp-parse-key-config (octets)
  "Parse one application/ohttp-keys KeyConfig. Signals an error on any malformed or
trailing bytes. Returns an EHBP-KEY-CONFIG whose SYMMETRIC is a list of (kdf . aead)."
  (let* ((v (coerce octets '(simple-array (unsigned-byte 8) (*))))
         (n (length v)))
    (labels ((u8 (p) (aref v p))
             (u16 (p) (logior (ash (aref v p) 8) (aref v (1+ p)))))
      (when (< n 3) (error "EHBP key config: too short"))
      (let* ((key-id (u8 0))
             (kem (u16 1))
             (npk 32))
        (unless (= kem #x0020)
          (error "EHBP key config: unsupported KEM 0x~4,'0x (need 0x0020)" kem))
        (when (< n (+ 3 npk 2)) (error "EHBP key config: truncated public key"))
        (let* ((pk (subseq v 3 (+ 3 npk)))
               (slen (u16 (+ 3 npk)))
               (sstart (+ 3 npk 2)))
          (unless (= n (+ sstart slen))
            (error "EHBP key config: length mismatch (~a bytes, expected ~a)" n (+ sstart slen)))
          (unless (and (plusp slen) (zerop (mod slen 4)))
            (error "EHBP key config: malformed symmetric algorithm list"))
          (make-ehbp-key-config
           :key-id key-id :kem-id kem :public-key pk
           :symmetric (loop for p from sstart below n by 4
                            collect (cons (u16 p) (u16 (+ p 2))))))))))

(defun ehbp-select-suite (config)
  "Return the CONFIG's symmetric pair for this project's suite (HKDF-SHA256, AES-256-GCM),
or signal an error if it is not offered."
  (or (find-if (lambda (s) (and (= (car s) #x0001) (= (cdr s) #x0002)))
               (ehbp-key-config-symmetric config))
      (error "EHBP key config: server does not offer HKDF-SHA256 + AES-256-GCM")))

(defun %ehbp-nonce (nonce-base seq)
  "nonce_base XOR seq, with seq big-endian in the last 8 bytes."
  (let ((n (copy-seq nonce-base)))
    (dotimes (i 8 n)
      (setf (aref n (- 11 i)) (logxor (aref n (- 11 i)) (ldb (byte 8 (* 8 i)) seq))))))

(defun ehbp-open-response (key nonce-base framed)
  "Decrypt a complete framed EHBP response body (the bytes after the headers).
Returns the plaintext as one byte vector. Errors on a bad tag or truncated frame."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
        (pos 0) (seq 0) (n (length framed)))
    (loop while (< pos n) do
      (when (> (+ pos 4) n) (error "EHBP: truncated chunk header"))
      (let ((len (logior (ash (aref framed pos) 24) (ash (aref framed (+ pos 1)) 16)
                         (ash (aref framed (+ pos 2)) 8) (aref framed (+ pos 3)))))
        (incf pos 4)
        (when (> len +ehbp-max-chunk+) (error "EHBP: chunk exceeds maximum size"))
        (cond
          ((zerop len) nil)            ; skipped, as the reference does
          (t
           (when (> (+ pos len) n) (error "EHBP: truncated encrypted chunk"))
           (let* ((ct (subseq framed pos (+ pos len)))
                  (nonce (%ehbp-nonce nonce-base seq))
                  (ct-body (subseq ct 0 (- len 16)))
                  (tag (subseq ct (- len 16)))
                  (pt (aes-gcm-decrypt key nonce ct-body #() tag)))
             (unless pt (error "EHBP: decryption failed at chunk ~a" seq))
             (loop for b across pt do (vector-push-extend b out))
             (incf seq))
           (incf pos len)))))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))
