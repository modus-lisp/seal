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
