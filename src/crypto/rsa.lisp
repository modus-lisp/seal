;;;; rsa.lisp — RSASSA signature *verification* (RFC 8017 / PKCS#1 v2.2).
;;;;
;;;; Verification only: given a public key (n, e) and a message, confirm a
;;;; signature. Both classic RSASSA-PKCS1-v1_5 (used by most CA certificate
;;;; signatures) and RSASSA-PSS (used by TLS 1.3 CertificateVerify and by
;;;; PSS-signed certificates) are supported, over SHA-256/384/512.
;;;;
;;;; No private-key operations, no key generation — a TLS client never needs
;;;; them. This is not constant-time; verification handles only public data.

(in-package #:seal)

(defstruct (rsa-public-key (:conc-name rsa-)) n e)

(defun rsa-modulus-length (key)
  "Byte length k of the modulus."
  (ceiling (integer-length (rsa-n key)) 8))

;;; ---- DigestInfo prefixes for EMSA-PKCS1-v1_5 (RFC 8017 §9.2, notes) --------
;;; Fixed DER encoding of  SEQUENCE { SEQUENCE { hashAlg, NULL }, OCTET STRING }
;;; with an empty (zero-filled) digest, i.e. everything up to the digest bytes.

(defparameter *pkcs1-digestinfo-prefix*
  '((:sha256 . #(#x30 #x31 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01 #x65 #x03
                 #x04 #x02 #x01 #x05 #x00 #x04 #x20))
    (:sha384 . #(#x30 #x41 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01 #x65 #x03
                 #x04 #x02 #x02 #x05 #x00 #x04 #x30))
    (:sha512 . #(#x30 #x51 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01 #x65 #x03
                 #x04 #x02 #x03 #x05 #x00 #x04 #x40))))

(defun rsavp1 (key signature)
  "RSAVP1 (RFC 8017 §5.2.2): the public-key primitive s^e mod n, as an integer.
Rejects out-of-range signatures."
  (let ((s (os2ip signature))
        (n (rsa-n key)))
    (when (or (< s 0) (>= s n))
      (error 'tls-error :message "RSA signature representative out of range"))
    (mod-expt s (rsa-e key) n)))

(defun rsa-pkcs1-verify (key hash-alg message signature)
  "Verify an RSASSA-PKCS1-v1_5 SIGNATURE over MESSAGE. Returns T / NIL."
  (let* ((k (rsa-modulus-length key)))
    (unless (= (length signature) k) (return-from rsa-pkcs1-verify nil))
    (let* ((m (handler-case (rsavp1 key signature)
                (tls-error () (return-from rsa-pkcs1-verify nil))))
           (em (i2osp m k))
           (prefix (cdr (assoc hash-alg *pkcs1-digestinfo-prefix*)))
           (digest (digest-hash hash-alg message))
           (tlen (+ (length prefix) (length digest))))
      (unless prefix (return-from rsa-pkcs1-verify nil))
      ;; EM = 0x00 0x01 PS 0x00 T, PS = 0xff*, at least 8 bytes; total = k.
      (when (< k (+ tlen 11)) (return-from rsa-pkcs1-verify nil))
      (unless (and (= (aref em 0) #x00) (= (aref em 1) #x01))
        (return-from rsa-pkcs1-verify nil))
      (let ((i 2))
        (loop while (and (< i k) (= (aref em i) #xff)) do (incf i))
        (unless (and (>= (- i 2) 8)              ; >= 8 padding bytes
                     (< i k) (= (aref em i) #x00))
          (return-from rsa-pkcs1-verify nil))
        (incf i)                                  ; step over the 0x00 separator
        ;; The remainder must be exactly DigestInfo (prefix || digest).
        (unless (= (- k i) tlen) (return-from rsa-pkcs1-verify nil))
        (and (loop for j below (length prefix)
                   always (= (aref em (+ i j)) (aref prefix j)))
             (loop for j below (length digest)
                   always (= (aref em (+ i (length prefix) j)) (aref digest j))))))))

;;; ---- MGF1 and PSS ----------------------------------------------------------

(defun mgf1 (seed length hash-alg)
  "MGF1 mask generation (RFC 8017 §B.2.1)."
  (let ((mask (make-array length :element-type '(unsigned-byte 8)))
        (hlen (hash-length hash-alg))
        (pos 0)
        (counter 0))
    (loop while (< pos length) do
      (let* ((c (i2osp counter 4))
             (block (digest-hash hash-alg (concatenate '(vector (unsigned-byte 8))
                                                       seed c)))
             (take (min hlen (- length pos))))
        (replace mask block :start1 pos :end2 take)
        (incf pos take)
        (incf counter)))
    mask))

(defun rsa-pss-verify (key hash-alg message signature &optional salt-length)
  "Verify an RSASSA-PSS SIGNATURE over MESSAGE (EMSA-PSS, RFC 8017 §8.1.2 /
§9.1.2). SALT-LENGTH defaults to the hash length, matching TLS 1.3. T / NIL."
  (let* ((k (rsa-modulus-length key)))
    (unless (= (length signature) k) (return-from rsa-pss-verify nil))
    (let* ((hlen (hash-length hash-alg))
           (slen (or salt-length hlen))
           (mhash (digest-hash hash-alg message))
           (embits (1- (integer-length (rsa-n key))))
           (emlen (ceiling embits 8))
           (m (handler-case (rsavp1 key signature)
                (tls-error () (return-from rsa-pss-verify nil))))
           (em (i2osp m emlen)))
      ;; §9.1.2 EMSA-PSS-VERIFY
      (when (< emlen (+ hlen slen 2)) (return-from rsa-pss-verify nil))
      (unless (= (aref em (1- emlen)) #xbc) (return-from rsa-pss-verify nil))
      (let* ((db-len (- emlen hlen 1))
             (masked-db (subseq em 0 db-len))
             (h (subseq em db-len (+ db-len hlen)))
             (top-bits (- (* 8 emlen) embits)))
        ;; leftmost top-bits of maskedDB must be zero
        (unless (zerop (logand (aref masked-db 0)
                               (if (>= top-bits 8) #xff
                                   (ash #xff (- 8 top-bits)))))
          (return-from rsa-pss-verify nil))
        (let* ((db-mask (mgf1 h db-len hash-alg))
               (db (make-array db-len :element-type '(unsigned-byte 8))))
          (dotimes (i db-len)
            (setf (aref db i) (logxor (aref masked-db i) (aref db-mask i))))
          ;; clear the leftmost top-bits of DB
          (setf (aref db 0) (logand (aref db 0) (ash #xff (- top-bits))))
          ;; DB = PS (zeros) || 0x01 || salt
          (let ((ps-end (- db-len slen 1)))
            (unless (loop for i below ps-end always (zerop (aref db i)))
              (return-from rsa-pss-verify nil))
            (unless (= (aref db ps-end) #x01) (return-from rsa-pss-verify nil))
            (let* ((salt (subseq db (1+ ps-end)))
                   (m-prime (concatenate '(vector (unsigned-byte 8))
                                         #(0 0 0 0 0 0 0 0) mhash salt))
                   (h-prime (digest-hash hash-alg m-prime)))
              (equalp h h-prime))))))))
