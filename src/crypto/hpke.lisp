;;;; hpke.lisp — HPKE (RFC 9180) base mode, for the one suite Tinfoil's EHBP uses:
;;;;
;;;;   KEM  DHKEM(X25519, HKDF-SHA256)  0x0020
;;;;   KDF  HKDF-SHA256                 0x0001
;;;;   AEAD AES-256-GCM                 0x0002
;;;;
;;;; Only base mode (mode 0), no PSK, no authentication.  Built on seal's own
;;;; HKDF and AES-GCM, and natrium's X25519.

(in-package #:seal)

(defconstant +hpke-kem-id+ #x0020)
(defconstant +hpke-kdf-id+ #x0001)
(defconstant +hpke-aead-id+ #x0002)   ; AES-256-GCM (Tinfoil); #x0001 = AES-128-GCM
(defconstant +hpke-nk+ 32)            ; AES-256 key length (16 for AES-128-GCM)
(defconstant +hpke-nn+ 12)      ; GCM nonce
(defconstant +hpke-nh+ 32)      ; SHA-256 output
(defconstant +hpke-nsecret+ 32) ; DHKEM(X25519) shared secret
(defconstant +hpke-npk+ 32)     ; X25519 public key / enc

(defun %hpke-bytes (&rest parts)
  "Concatenate byte-vector PARTS into a fresh (unsigned-byte 8) vector."
  (let* ((n (reduce #'+ parts :key #'length))
         (out (make-array n :element-type '(unsigned-byte 8)))
         (pos 0))
    (dolist (p parts out)
      (replace out p :start1 pos)
      (incf pos (length p)))))

(defun %hpke-ascii (s)
  (map '(vector (unsigned-byte 8)) #'char-code s))

(defun %hpke-i2osp (n len)
  "Big-endian encoding of integer N in LEN bytes."
  (let ((out (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (i len out)
      (setf (aref out (- len 1 i)) (ldb (byte 8 (* 8 i)) n)))))

(defun %hpke-kem-suite-id ()
  (%hpke-bytes (%hpke-ascii "KEM") (%hpke-i2osp +hpke-kem-id+ 2)))

(defvar *hpke-aead-id* +hpke-aead-id+
  "AEAD id used by the key schedule. Bound to 1 only by the AES-128 RFC vector test.")
(defvar *hpke-nk* +hpke-nk+)

(defun %hpke-suite-id ()
  (%hpke-bytes (%hpke-ascii "HPKE") (%hpke-i2osp +hpke-kem-id+ 2)
               (%hpke-i2osp +hpke-kdf-id+ 2) (%hpke-i2osp *hpke-aead-id* 2)))

(defun %hpke-labeled-extract (suite-id salt label ikm)
  (hkdf-extract salt
                (%hpke-bytes (%hpke-ascii "HPKE-v1") suite-id (%hpke-ascii label) ikm)
                :sha256))

(defun %hpke-labeled-expand (suite-id prk label info length)
  (hkdf-expand prk
               (%hpke-bytes (%hpke-i2osp length 2) (%hpke-ascii "HPKE-v1") suite-id
                            (%hpke-ascii label) info)
               length :sha256))

(defun hpke-generate-keypair ()
  "X25519 keypair for HPKE. Returns (values private-scalar public-key), 32 bytes each."
  (let ((sk (secure-random-bytes 32)))
    (values sk (x25519-public-key sk))))

(defun %hpke-kem-shared-secret (dh kem-context)
  (%hpke-labeled-expand (%hpke-kem-suite-id)
                        (%hpke-labeled-extract (%hpke-kem-suite-id) #() "eae_prk" dh)
                        "shared_secret" kem-context +hpke-nsecret+))

(defun hpke-encap (pk-r)
  "DHKEM encapsulation to recipient public key PK-R. Returns (values shared-secret enc)."
  (multiple-value-bind (sk-e enc) (hpke-generate-keypair)
    (let* ((dh (x25519 sk-e pk-r)))
      (values (%hpke-kem-shared-secret dh (%hpke-bytes enc pk-r)) enc))))

(defun hpke-decap (enc sk-r pk-r)
  "DHKEM decapsulation: recover the shared secret from ENC with recipient key SK-R."
  (let ((dh (x25519 sk-r enc)))
    (%hpke-kem-shared-secret dh (%hpke-bytes enc pk-r))))

(defstruct hpke-context
  key        ; 32-byte AES-256 key
  base-nonce ; 12 bytes
  (seq 0))   ; message counter

(defun %hpke-key-schedule (shared-secret info)
  "RFC 9180 KeySchedule for base mode. Returns an HPKE-CONTEXT."
  (let* ((suite (%hpke-suite-id))
         (psk-id-hash (%hpke-labeled-extract suite #() "psk_id_hash" #()))
         (info-hash (%hpke-labeled-extract suite #() "info_hash" info))
         (ksc (%hpke-bytes (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)
                           psk-id-hash info-hash))
         (secret (%hpke-labeled-extract suite shared-secret "secret" #()))
         (key (%hpke-labeled-expand suite secret "key" ksc *hpke-nk*))
         (base-nonce (%hpke-labeled-expand suite secret "base_nonce" ksc +hpke-nn+)))
    (make-hpke-context :key key :base-nonce base-nonce :seq 0)))

(defun hpke-setup-sender (pk-r info)
  "SetupBaseS. Returns (values context enc)."
  (multiple-value-bind (shared-secret enc) (hpke-encap pk-r)
    (values (%hpke-key-schedule shared-secret (or info #())) enc)))

(defun hpke-setup-recipient (enc sk-r pk-r info)
  "SetupBaseR. Returns the context."
  (%hpke-key-schedule (hpke-decap enc sk-r pk-r) (or info #())))

(defun %hpke-nonce (ctx)
  (let ((n (copy-seq (hpke-context-base-nonce ctx)))
        (seq (%hpke-i2osp (hpke-context-seq ctx) +hpke-nn+)))
    (dotimes (i +hpke-nn+ n)
      (setf (aref n i) (logxor (aref n i) (aref seq i))))))

(defun hpke-seal (ctx plaintext &optional aad)
  "Seal PLAINTEXT with the next nonce. Returns ciphertext || tag (16 bytes)."
  (let* ((nonce (%hpke-nonce ctx))
         (ct+tag (aes-gcm-encrypt (hpke-context-key ctx) nonce plaintext (or aad #()))))
    (incf (hpke-context-seq ctx))
    (%hpke-bytes (car ct+tag) (cdr ct+tag))))

(defun hpke-open (ctx ciphertext &optional aad)
  "Open CIPHERTEXT (ciphertext || tag). Returns the plaintext, or NIL on tag failure."
  (let* ((n (- (length ciphertext) 16)))
    (when (< n 0) (return-from hpke-open nil))
    (let* ((nonce (%hpke-nonce ctx))
           (pt (aes-gcm-decrypt (hpke-context-key ctx) nonce
                                (subseq ciphertext 0 n) (or aad #())
                                (subseq ciphertext n))))
      (when pt (incf (hpke-context-seq ctx)))
      pt)))

(defun hpke-base-seal (pk-r info plaintext &optional aad)
  "One-shot HPKE base-mode seal. Returns (values enc ciphertext)."
  (multiple-value-bind (ctx enc) (hpke-setup-sender pk-r info)
    (values enc (hpke-seal ctx plaintext aad))))
