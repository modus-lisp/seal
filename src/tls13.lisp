;;;; tls13.lisp — TLS 1.3 client (RFC 8446).
;;;;
;;;; Full 1-RTT handshake over X25519 key exchange, with AES-128-GCM-SHA256,
;;;; AES-256-GCM-SHA384, and ChaCha20-Poly1305-SHA256. No client certificates,
;;;; no PSK/session resumption. Runs over any TRANSPORT (see transport.lisp).

(in-package #:seal)

;;; ---- constants -------------------------------------------------------------

(defconstant +content-change-cipher-spec+ 20)
(defconstant +content-alert+ 21)
(defconstant +content-handshake+ 22)
(defconstant +content-application-data+ 23)

(defconstant +hs-client-hello+ 1)
(defconstant +hs-server-hello+ 2)
(defconstant +hs-new-session-ticket+ 4)
(defconstant +hs-encrypted-extensions+ 8)
(defconstant +hs-certificate+ 11)
(defconstant +hs-certificate-verify+ 15)
(defconstant +hs-finished+ 20)

(defconstant +ext-server-name+ 0)
(defconstant +ext-supported-groups+ 10)
(defconstant +ext-ec-point-formats+ 11)
(defconstant +ext-signature-algorithms+ 13)
(defconstant +ext-alpn+ 16)
(defconstant +ext-encrypt-then-mac+ 22)
(defconstant +ext-extended-master-secret+ 23)
(defconstant +ext-session-ticket+ 35)
(defconstant +ext-supported-versions+ 43)
(defconstant +ext-psk-key-exchange-modes+ 45)
(defconstant +ext-key-share+ 51)

(defconstant +cs-aes-128-gcm-sha256+ #x1301)
(defconstant +cs-aes-256-gcm-sha384+ #x1302)
(defconstant +cs-chacha20-poly1305-sha256+ #x1303)

(defconstant +group-x25519+ 29)
(defconstant +version-12+ #x0303)
(defconstant +version-13+ #x0304)

(defconstant +max-fragment+ 16384)

;;; ---- cipher-suite properties ----------------------------------------------

(defun cipher-hash (cipher)
  (if (= cipher +cs-aes-256-gcm-sha384+) :sha384 :sha256))
(defun cipher-key-length (cipher)
  (if (= cipher +cs-aes-128-gcm-sha256+) 16 32))
(defun cipher-aead-encrypt (cipher key nonce plaintext aad)
  (if (= cipher +cs-chacha20-poly1305-sha256+)
      (chacha20-poly1305-encrypt key nonce plaintext aad)
      (aes-gcm-encrypt key nonce plaintext aad)))
(defun cipher-aead-decrypt (cipher key nonce ciphertext aad tag)
  (if (= cipher +cs-chacha20-poly1305-sha256+)
      (chacha20-poly1305-decrypt key nonce ciphertext tag aad)
      (aes-gcm-decrypt key nonce ciphertext aad tag)))

;;; ---- connection state ------------------------------------------------------

(defstruct (tls-connection (:conc-name tls-))
  transport
  (state :init)
  cipher
  host
  client-random server-random
  client-private-key client-public-key server-public-key
  handshake-secret master-secret
  client-hs-secret server-hs-secret
  client-handshake-key client-handshake-iv
  server-handshake-key server-handshake-iv
  client-app-key client-app-iv
  server-app-key server-app-iv
  (client-seq 0) (server-seq 0)
  (transcript nil)
  (recv-buffer #())
  early-data
  (peer-certificates nil)
  (verify nil)
  (cert-verify-ok :not-checked)
  alpn)

(defun tls-connection-cipher-name (conn)
  (let ((c (tls-cipher conn)))
    (cond ((null c) nil)
          ((= c +cs-aes-128-gcm-sha256+) "TLS_AES_128_GCM_SHA256")
          ((= c +cs-aes-256-gcm-sha384+) "TLS_AES_256_GCM_SHA384")
          ((= c +cs-chacha20-poly1305-sha256+) "TLS_CHACHA20_POLY1305_SHA256")
          (t (format nil "0x~4,'0x" c)))))

(defun conn-hash (conn) (cipher-hash (tls-cipher conn)))

;;; Public read-only accessors.
(defun tls-connection-cipher (conn) (tls-connection-cipher-name conn))
(defun tls-connection-alpn (conn) (tls-alpn conn))
(defun tls-connection-peer-certificates (conn) (tls-peer-certificates conn))

;;; ---- little-endian / big-endian helpers -----------------------------------

(defun u16be (n) (list (logand (ash n -8) #xff) (logand n #xff)))

(defun bytes-u16 (data pos) (logior (ash (aref data pos) 8) (aref data (1+ pos))))
(defun bytes-u24 (data pos)
  (logior (ash (aref data pos) 16) (ash (aref data (+ pos 1)) 8) (aref data (+ pos 2))))

;;; ---- record & handshake framing -------------------------------------------

(defun make-record (content-type payload)
  (let* ((len (length payload))
         (record (make-array (+ 5 len) :element-type '(unsigned-byte 8))))
    (setf (aref record 0) content-type
          (aref record 1) #x03 (aref record 2) #x03
          (aref record 3) (logand (ash len -8) #xff)
          (aref record 4) (logand len #xff))
    (replace record payload :start1 5)
    record))

(defun make-handshake (msg-type payload)
  (let* ((len (length payload))
         (msg (make-array (+ 4 len) :element-type '(unsigned-byte 8))))
    (setf (aref msg 0) msg-type
          (aref msg 1) (logand (ash len -16) #xff)
          (aref msg 2) (logand (ash len -8) #xff)
          (aref msg 3) (logand len #xff))
    (replace msg payload :start1 4)
    msg))

(defun build-extension (ext-type data)
  (let* ((len (length data))
         (ext (make-array (+ 4 len) :element-type '(unsigned-byte 8))))
    (setf (aref ext 0) (logand (ash ext-type -8) #xff)
          (aref ext 1) (logand ext-type #xff)
          (aref ext 2) (logand (ash len -8) #xff)
          (aref ext 3) (logand len #xff))
    (replace ext data :start1 4)
    ext))

(defun bv (&rest bytes) (make-array (length bytes) :element-type '(unsigned-byte 8)
                                    :initial-contents bytes))

;;; ---- ClientHello extensions ------------------------------------------------

(defun ext-supported-versions ()
  (build-extension +ext-supported-versions+ (bv 2 #x03 #x04)))

(defun ext-supported-groups ()
  (build-extension +ext-supported-groups+ (bv 0 2 0 29)))   ; x25519 only

(defun ext-signature-algorithms ()
  (build-extension +ext-signature-algorithms+
                   (bv 0 18
                       #x04 #x03 #x05 #x03 #x06 #x03   ; ecdsa sha256/384/512
                       #x08 #x04 #x08 #x05 #x08 #x06   ; rsa_pss_rsae sha256/384/512
                       #x04 #x01 #x05 #x01 #x06 #x01)))  ; rsa_pkcs1 sha256/384/512

(defun ext-key-share (public-key)
  (let ((data (make-array 38 :element-type '(unsigned-byte 8))))
    (setf (aref data 0) 0 (aref data 1) 36   ; client_shares length = 36
          (aref data 2) 0 (aref data 3) 29   ; group x25519
          (aref data 4) 0 (aref data 5) 32)  ; key length
    (replace data public-key :start1 6)
    (build-extension +ext-key-share+ data)))

(defun ext-server-name (hostname)
  (let* ((name-len (length hostname))
         (list-len (+ 3 name-len))
         (data (make-array (+ 2 list-len) :element-type '(unsigned-byte 8))))
    (setf (aref data 0) (logand (ash list-len -8) #xff)
          (aref data 1) (logand list-len #xff)
          (aref data 2) 0
          (aref data 3) (logand (ash name-len -8) #xff)
          (aref data 4) (logand name-len #xff))
    (dotimes (i name-len) (setf (aref data (+ 5 i)) (char-code (char hostname i))))
    (build-extension +ext-server-name+ data)))

(defun ext-alpn (protocols)
  "PROTOCOLS is a list of protocol-name strings."
  (let* ((body (apply #'concatenate '(vector (unsigned-byte 8))
                      (mapcar (lambda (p)
                                (concatenate '(vector (unsigned-byte 8))
                                             (vector (length p))
                                             (map 'vector #'char-code p)))
                              protocols)))
         (data (concatenate '(vector (unsigned-byte 8)) (u16be (length body)) body)))
    (build-extension +ext-alpn+ data)))

(defun ext-psk-key-exchange-modes () (build-extension +ext-psk-key-exchange-modes+ (bv 1 1)))
(defun ext-session-ticket () (build-extension +ext-session-ticket+ #()))
(defun ext-ec-point-formats () (build-extension +ext-ec-point-formats+ (bv 3 0 1 2)))
(defun ext-encrypt-then-mac () (build-extension +ext-encrypt-then-mac+ #()))
(defun ext-extended-master-secret () (build-extension +ext-extended-master-secret+ #()))

;;; ---- ClientHello -----------------------------------------------------------

(defun build-client-hello (conn hostname alpn-protocols)
  (let* ((client-random (secure-random-bytes 32))
         (private-key (secure-random-bytes 32))
         (public-key (x25519-public-key private-key)))
    (setf (tls-client-random conn) client-random
          (tls-client-private-key conn) private-key
          (tls-client-public-key conn) public-key)
    (let* ((extensions
             (concatenate 'vector
                          (if hostname (ext-server-name hostname) #())
                          (ext-ec-point-formats)
                          (ext-supported-groups)
                          (ext-session-ticket)
                          (if alpn-protocols (ext-alpn alpn-protocols) #())
                          (ext-encrypt-then-mac)
                          (ext-extended-master-secret)
                          (ext-signature-algorithms)
                          (ext-supported-versions)
                          (ext-psk-key-exchange-modes)
                          (ext-key-share public-key)))
           (ext-len (length extensions))
           (session-id (secure-random-bytes 32))
           (body (make-array (+ 2 32 1 32 2 6 2 2 ext-len)
                             :element-type '(unsigned-byte 8)))
           (pos 0))
      (flet ((put (b) (setf (aref body pos) b) (incf pos)))
        (put #x03) (put #x03)                     ; legacy_version TLS 1.2
        (dotimes (i 32) (put (aref client-random i)))
        (put 32) (dotimes (i 32) (put (aref session-id i)))
        ;; cipher_suites (3 suites)
        (put 0) (put 6)
        (put #x13) (put #x01) (put #x13) (put #x02) (put #x13) (put #x03)
        ;; compression: null only
        (put 1) (put 0)
        ;; extensions
        (put (logand (ash ext-len -8) #xff)) (put (logand ext-len #xff))
        (dotimes (i ext-len) (put (aref extensions i))))
      (make-handshake +hs-client-hello+ body))))

;;; ---- ServerHello -----------------------------------------------------------

(defun parse-server-hello (conn data)
  (when (< (length data) 38)
    (error 'tls-error :message "ServerHello too short"))
  (let ((pos 2))                                  ; skip legacy_version
    (setf (tls-server-random conn) (subseq data pos (+ pos 32)))
    (incf pos 32)
    (incf pos (1+ (aref data pos)))               ; skip session id echo
    (let ((cipher (bytes-u16 data pos)))
      (unless (member cipher (list +cs-aes-128-gcm-sha256+ +cs-aes-256-gcm-sha384+
                                   +cs-chacha20-poly1305-sha256+))
        (error 'tls-error :message (format nil "unsupported cipher suite 0x~4,'0x" cipher)))
      (setf (tls-cipher conn) cipher)
      (incf pos 2))
    (incf pos)                                     ; compression method (0)
    (when (>= (length data) (+ pos 2))
      (let* ((ext-len (bytes-u16 data pos))
             (ext-end (+ pos 2 ext-len)))
        (incf pos 2)
        (loop while (< pos ext-end) do
          (let ((ext-type (bytes-u16 data pos))
                (ext-data-len (bytes-u16 data (+ pos 2))))
            (incf pos 4)
            (cond
              ((= ext-type +ext-key-share+)
               (let ((group (bytes-u16 data pos))
                     (key-len (bytes-u16 data (+ pos 2))))
                 (when (and (= group +group-x25519+) (= key-len 32))
                   (setf (tls-server-public-key conn) (subseq data (+ pos 4) (+ pos 4 32))))))
              ((= ext-type +ext-supported-versions+)
               (unless (= (bytes-u16 data pos) +version-13+)
                 (error 'tls-error :message "server did not select TLS 1.3"))))
            (incf pos ext-data-len)))))
    (unless (tls-server-public-key conn)
      (error 'tls-error :message "ServerHello without an x25519 key_share"))
    t))

;;; ---- key schedule ----------------------------------------------------------

(defun transcript-hash (conn)
  (digest-hash (conn-hash conn)
               (apply #'concatenate 'vector (reverse (tls-transcript conn)))))

(defun add-to-transcript (conn msg) (push msg (tls-transcript conn)))

(defun derive-traffic-keys (conn secret)
  "Return (values key iv) for a traffic SECRET."
  (let ((which (conn-hash conn)))
    (values (tls13-hkdf-expand-label secret "key" #() (cipher-key-length (tls-cipher conn)) which)
            (tls13-hkdf-expand-label secret "iv" #() 12 which))))

(defun derive-handshake-keys (conn)
  "Derive handshake traffic secrets/keys after ServerHello (RFC 8446 §7.1)."
  (let* ((which (conn-hash conn))
         (hash-len (hash-length which))
         (shared (x25519 (tls-client-private-key conn) (tls-server-public-key conn)))
         (zero (make-array hash-len :element-type '(unsigned-byte 8) :initial-element 0))
         (empty-hash (digest-hash which #()))
         (early-secret (hkdf-extract zero zero which))
         (derived (tls13-derive-secret early-secret "derived" empty-hash which))
         (handshake-secret (hkdf-extract derived shared which))
         (th (transcript-hash conn))
         (c-hs (tls13-derive-secret handshake-secret "c hs traffic" th which))
         (s-hs (tls13-derive-secret handshake-secret "s hs traffic" th which))
         (derived2 (tls13-derive-secret handshake-secret "derived" empty-hash which))
         (master (hkdf-extract derived2 zero which)))
    (setf (tls-handshake-secret conn) handshake-secret
          (tls-master-secret conn) master
          (tls-client-hs-secret conn) c-hs
          (tls-server-hs-secret conn) s-hs)
    (multiple-value-bind (k iv) (derive-traffic-keys conn c-hs)
      (setf (tls-client-handshake-key conn) k (tls-client-handshake-iv conn) iv))
    (multiple-value-bind (k iv) (derive-traffic-keys conn s-hs)
      (setf (tls-server-handshake-key conn) k (tls-server-handshake-iv conn) iv))))

(defun derive-application-keys (conn transcript-hash)
  (let* ((which (conn-hash conn))
         (master (tls-master-secret conn))
         (c-ap (tls13-derive-secret master "c ap traffic" transcript-hash which))
         (s-ap (tls13-derive-secret master "s ap traffic" transcript-hash which)))
    (multiple-value-bind (k iv) (derive-traffic-keys conn c-ap)
      (setf (tls-client-app-key conn) k (tls-client-app-iv conn) iv))
    (multiple-value-bind (k iv) (derive-traffic-keys conn s-ap)
      (setf (tls-server-app-key conn) k (tls-server-app-iv conn) iv))
    (setf (tls-client-seq conn) 0 (tls-server-seq conn) 0)))

(defun finished-verify-data (conn secret)
  (let* ((which (conn-hash conn))
         (finished-key (tls13-hkdf-expand-label secret "finished" #() (hash-length which) which)))
    (if (eq which :sha384)
        (hmac-sha384 finished-key (transcript-hash conn))
        (hmac-sha256 finished-key (transcript-hash conn)))))

;;; ---- record protection -----------------------------------------------------

(defun build-nonce (iv seq)
  (let ((nonce (copy-seq iv)))
    (dotimes (i 8)
      (setf (aref nonce (- 11 i))
            (logxor (aref nonce (- 11 i)) (logand (ash seq (* -8 i)) #xff))))
    nonce))

(defun encrypt-record (conn plaintext content-type &key app)
  (let* ((cipher (tls-cipher conn))
         (key (if app (tls-client-app-key conn) (tls-client-handshake-key conn)))
         (iv (if app (tls-client-app-iv conn) (tls-client-handshake-iv conn)))
         (seq (tls-client-seq conn))
         (nonce (build-nonce iv seq))
         (inner (concatenate '(vector (unsigned-byte 8)) plaintext (vector content-type)))
         (ct-len (+ (length inner) 16))
         (aad (make-array 5 :element-type '(unsigned-byte 8))))
    (setf (aref aad 0) +content-application-data+ (aref aad 1) #x03 (aref aad 2) #x03
          (aref aad 3) (logand (ash ct-len -8) #xff) (aref aad 4) (logand ct-len #xff))
    (let* ((result (cipher-aead-encrypt cipher key nonce inner aad))
           (ciphertext (car result))
           (tag (cdr result))
           (record (make-array (+ 5 (length ciphertext) 16) :element-type '(unsigned-byte 8))))
      (setf (tls-client-seq conn) (1+ seq))
      (replace record aad)
      (replace record ciphertext :start1 5)
      (replace record tag :start1 (+ 5 (length ciphertext)))
      record)))

(defun decrypt-record (conn record &key app)
  (when (< (length record) 21) (return-from decrypt-record nil))
  (let* ((cipher (tls-cipher conn))
         (key (if app (tls-server-app-key conn) (tls-server-handshake-key conn)))
         (iv (if app (tls-server-app-iv conn) (tls-server-handshake-iv conn)))
         (seq (tls-server-seq conn))
         (nonce (build-nonce iv seq))
         (aad (subseq record 0 5))
         (body (subseq record 5))
         (ct-len (- (length body) 16))
         (ct (subseq body 0 ct-len))
         (tag (subseq body ct-len))
         (inner (cipher-aead-decrypt cipher key nonce ct aad tag)))
    (unless inner (return-from decrypt-record nil))
    (setf (tls-server-seq conn) (1+ seq))
    (let ((end (1- (length inner))))
      (loop while (and (> end 0) (zerop (aref inner end))) do (decf end))
      (list (aref inner end) (subseq inner 0 end)))))

;;; ---- record buffering ------------------------------------------------------

(defun buffer-append (a b)
  (cond ((or (null a) (zerop (length a))) b)
        ((or (null b) (zerop (length b))) a)
        (t (concatenate 'vector a b))))

(defun extract-record (buffer)
  "Return (values record remaining) or NIL if BUFFER holds no full record."
  (when (or (null buffer) (< (length buffer) 5)) (return-from extract-record nil))
  (let ((total (+ 5 (bytes-u16 buffer 3))))
    (when (< (length buffer) total) (return-from extract-record nil))
    (values (subseq buffer 0 total)
            (if (> (length buffer) total) (subseq buffer total) #()))))

;;; ---- Certificate message parsing ------------------------------------------

(defun parse-certificate-message (conn hs-msg)
  "Extract and parse the peer certificate chain from a Certificate handshake."
  (let* ((body-start 4)                            ; skip handshake header
         (ctx-len (aref hs-msg body-start))
         (pos (+ body-start 1 ctx-len))
         (list-len (bytes-u24 hs-msg pos))
         (list-end (+ pos 3 list-len))
         (certs nil))
    (incf pos 3)
    (loop while (< pos list-end) do
      (let* ((cert-len (bytes-u24 hs-msg pos))
             (cert-der (subseq hs-msg (+ pos 3) (+ pos 3 cert-len)))
             (ext-len (bytes-u16 hs-msg (+ pos 3 cert-len))))
        (push (handler-case (parse-certificate cert-der)
                (error () (make-certificate :raw cert-der)))
              certs)
        (incf pos (+ 3 cert-len 2 ext-len))))
    (setf (tls-peer-certificates conn) (nreverse certs))))

;;; ---- CertificateVerify (RFC 8446 §4.4.3) ----------------------------------

(defun tls-signature-scheme (code)
  "Map a TLS 1.3 SignatureScheme code to (values scheme hash salt).
Returns NIL for schemes seal cannot verify (so they fail closed)."
  (case code
    (#x0401 (values :rsa-pkcs1 :sha256 nil))
    (#x0501 (values :rsa-pkcs1 :sha384 nil))
    (#x0601 (values :rsa-pkcs1 :sha512 nil))
    (#x0403 (values :ecdsa :sha256 nil))         ; ecdsa_secp256r1_sha256
    (#x0503 (values :ecdsa :sha384 nil))         ; ecdsa_secp384r1_sha384
    (#x0804 (values :rsa-pss :sha256 nil))       ; rsa_pss_rsae_sha256
    (#x0805 (values :rsa-pss :sha384 nil))
    (#x0806 (values :rsa-pss :sha512 nil))
    (#x0809 (values :rsa-pss :sha256 nil))       ; rsa_pss_pss_sha256
    (#x080a (values :rsa-pss :sha384 nil))
    (#x080b (values :rsa-pss :sha512 nil))
    (#x0807 (values :ed25519 nil nil))
    (t (values nil nil nil))))

(defparameter +certificate-verify-context+
  (concatenate '(vector (unsigned-byte 8))
               (make-array 64 :element-type '(unsigned-byte 8) :initial-element #x20)
               (map 'vector #'char-code "TLS 1.3, server CertificateVerify")
               #(0)))

(defun verify-certificate-verify (conn hs-msg)
  "Verify the server's CertificateVerify signature over the handshake transcript
with the leaf certificate's public key. Raises on failure."
  (let* ((code (bytes-u16 hs-msg 4))
         (sig-len (bytes-u16 hs-msg 6))
         (signature (subseq hs-msg 8 (+ 8 sig-len)))
         ;; transcript hash covers ClientHello .. Certificate (this message is
         ;; not yet in the transcript).
         (th (transcript-hash conn))
         (signed (concatenate '(vector (unsigned-byte 8))
                              +certificate-verify-context+ th))
         (leaf (first (tls-peer-certificates conn))))
    (multiple-value-bind (scheme hash salt) (tls-signature-scheme code)
      (unless (and scheme leaf (certificate-spki leaf))
        (error 'tls-certificate-bad-signature-error
               :message (format nil "unsupported CertificateVerify scheme 0x~4,'0x" code)))
      (unless (verify-signature (certificate-spki leaf) scheme hash salt signed signature)
        (error 'tls-certificate-bad-signature-error
               :message "CertificateVerify signature did not verify"))
      (setf (tls-cert-verify-ok conn) t))))

;;; ---- the handshake ---------------------------------------------------------

(defun process-encrypted-handshake (conn plaintext)
  "Walk the decrypted handshake messages; return T once Finished is seen."
  (let ((pos 0) (finished nil))
    (loop while (< pos (length plaintext)) do
      (when (< (- (length plaintext) pos) 4) (return))
      (let* ((hs-type (aref plaintext pos))
             (hs-len (bytes-u24 plaintext (+ pos 1)))
             (hs-end (+ pos 4 hs-len)))
        (when (> hs-end (length plaintext)) (return))
        (let ((hs-msg (subseq plaintext pos hs-end)))
          (cond
            ((= hs-type +hs-encrypted-extensions+)
             (parse-encrypted-extensions conn hs-msg)
             (add-to-transcript conn hs-msg))
            ((= hs-type +hs-certificate+)
             (parse-certificate-message conn hs-msg)
             (add-to-transcript conn hs-msg))
            ((= hs-type +hs-certificate-verify+)
             ;; Proof of possession: verify before folding it into the
             ;; transcript (the signature covers CH..Certificate). Only when the
             ;; caller asked for authentication.
             (when (tls-verify conn)
               (verify-certificate-verify conn hs-msg))
             (add-to-transcript conn hs-msg))
            ((= hs-type +hs-finished+)
             ;; verify server Finished before adding it to the transcript
             (let ((expected (finished-verify-data conn (tls-server-hs-secret conn)))
                   (got (subseq hs-msg 4)))
               (unless (equalp expected got)
                 (error 'tls-error :message "server Finished verify_data mismatch")))
             (add-to-transcript conn hs-msg)
             (setf finished t))
            ((= hs-type +hs-new-session-ticket+) nil)  ; ignored
            (t nil))
          (setf pos hs-end))))
    finished))

(defun parse-encrypted-extensions (conn hs-msg)
  "Pull the negotiated ALPN protocol out of EncryptedExtensions, if any."
  (when (> (length hs-msg) 6)
    (let ((ext-len (bytes-u16 hs-msg 4)) (pos 6))
      (loop while (< pos (min (+ 6 ext-len) (length hs-msg))) do
        (let ((ext-type (bytes-u16 hs-msg pos))
              (ext-data-len (bytes-u16 hs-msg (+ pos 2))))
          (when (= ext-type +ext-alpn+)
            (let ((proto-len (aref hs-msg (+ pos 6))))
              (setf (tls-alpn conn)
                    (map 'string #'code-char (subseq hs-msg (+ pos 7) (+ pos 7 proto-len))))))
          (incf pos (+ 4 ext-data-len)))))))

(defun handshake (conn hostname alpn-protocols)
  "Run the TLS 1.3 client handshake. Returns CONN or signals a TLS-ERROR."
  (let ((transport (tls-transport conn))
        (recv-buffer #()))
    ;; 1. ClientHello
    (let ((ch (build-client-hello conn hostname alpn-protocols)))
      (add-to-transcript conn ch)
      (unless (transport-send transport (make-record +content-handshake+ ch))
        (error 'tls-error :message "failed to send ClientHello")))
    ;; 2. ServerHello
    (let ((data (transport-recv transport)))
      (unless data (error 'tls-error :message "no response to ClientHello"))
      (setf recv-buffer data))
    (multiple-value-bind (record remaining) (extract-record recv-buffer)
      (unless record (error 'tls-error :message "incomplete ServerHello record"))
      (setf recv-buffer remaining)
      (let ((ctype (aref record 0)))
        (when (= ctype +content-alert+)
          (error 'tls-alert :level (aref record 5) :description (aref record 6)))
        (unless (= ctype +content-handshake+)
          (error 'tls-error :message (format nil "expected handshake, got record type ~d" ctype)))
        (let ((hs (subseq record 5)))
          (unless (= (aref hs 0) +hs-server-hello+)
            (error 'tls-error :message (format nil "expected ServerHello, got ~d" (aref hs 0))))
          (let ((msg-len (bytes-u24 hs 1)))
            (parse-server-hello conn (subseq hs 4 (+ 4 msg-len)))
            (add-to-transcript conn (subseq hs 0 (+ 4 msg-len)))))))
    ;; 3. handshake keys
    (derive-handshake-keys conn)
    ;; 4. encrypted handshake flight
    (let ((finished nil))
      (loop
        ;; Once the server Finished is processed the handshake is complete; any
        ;; further records already buffered are app-keyed (a pipelined
        ;; NewSessionTicket) and must not be decrypted with the handshake key.
        (when finished (return))
        (multiple-value-bind (record remaining) (extract-record recv-buffer)
          (unless record
            (when finished (return))
            (let ((more (transport-recv transport)))
              (unless more (error 'tls-error :message "timed out awaiting handshake flight"))
              (setf recv-buffer (buffer-append recv-buffer more))
              (multiple-value-setq (record remaining) (extract-record recv-buffer))))
          (when record
            (setf recv-buffer remaining)
            (let ((rtype (aref record 0)))
              (cond
                ((= rtype +content-change-cipher-spec+) nil)
                ((= rtype +content-application-data+)
                 (let ((dec (decrypt-record conn record)))
                   (unless dec (error 'tls-error :message "handshake record decryption failed"))
                   (unless (= (first dec) +content-handshake+)
                     (error 'tls-error :message
                            (format nil "unexpected inner content type ~d" (first dec))))
                   (when (process-encrypted-handshake conn (second dec))
                     (setf finished t))))
                (t (error 'tls-error :message
                          (format nil "unexpected record type ~d in handshake" rtype))))))))
      (unless finished (error 'tls-error :message "server Finished not received"))
      ;; Preserve any records the server pipelined after Finished (a NewSessionTicket,
      ;; already app-keyed) so tls-recv processes them with the app key and the server
      ;; sequence stays in sync with the response that follows.
      (setf (tls-recv-buffer conn) recv-buffer))
    ;; 5. client Finished (+ CCS for middlebox compatibility) then app keys
    (let* ((th (transcript-hash conn))
           (verify (finished-verify-data conn (tls-client-hs-secret conn)))
           (finished-msg (make-handshake +hs-finished+ verify))
           (encrypted (encrypt-record conn finished-msg +content-handshake+))
           (ccs (bv 20 3 3 0 1 1)))
      (derive-application-keys conn th)
      (let ((early (tls-early-data conn)))
        (if early
            (let ((app (encrypt-record conn early +content-application-data+ :app t)))
              (transport-send transport (concatenate 'vector ccs encrypted app)))
            (transport-send transport (concatenate 'vector ccs encrypted)))))
    (setf (tls-state conn) :established)
    conn))

;;; ---- application data ------------------------------------------------------

(defun tls-send (conn data)
  "Send application DATA (a byte vector or string) over an established CONN."
  (let ((data (if (stringp data) (map '(vector (unsigned-byte 8)) #'char-code data) data))
        (transport (tls-transport conn)))
    (let ((len (length data)) (offset 0))
      (loop while (< offset len) do
        (let* ((chunk-size (min +max-fragment+ (- len offset)))
               (chunk (subseq data offset (+ offset chunk-size)))
               (record (encrypt-record conn chunk +content-application-data+ :app t)))
          (unless (transport-send transport record)
            (return-from tls-send nil))
          (incf offset chunk-size)))
      t)))

(defun tls-recv (conn)
  "Receive the next chunk of application data. Returns a byte vector, or NIL at
end of stream."
  (let ((transport (tls-transport conn))
        (recv-buffer (or (tls-recv-buffer conn) #())))
    (loop
      (multiple-value-bind (record remaining) (extract-record recv-buffer)
        (unless record
          (let ((more (transport-recv transport)))
            (unless more
              (setf (tls-recv-buffer conn) recv-buffer)
              (return-from tls-recv nil))
            (setf recv-buffer (buffer-append recv-buffer more))
            (multiple-value-setq (record remaining) (extract-record recv-buffer))))
        (when record
          (setf recv-buffer remaining)
          (let ((rtype (aref record 0)))
            (cond
              ((= rtype +content-application-data+)
               (let ((dec (decrypt-record conn record :app t)))
                 (unless dec
                   (setf (tls-recv-buffer conn) recv-buffer)
                   (return-from tls-recv nil))
                 (let ((ctype (first dec)) (plaintext (second dec)))
                   (cond
                     ((= ctype +content-application-data+)
                      (setf (tls-recv-buffer conn) recv-buffer)
                      (return-from tls-recv plaintext))
                     ((= ctype +content-handshake+) nil)  ; NewSessionTicket etc.
                     ((= ctype +content-alert+)
                      (setf (tls-recv-buffer conn) recv-buffer)
                      (return-from tls-recv nil))))))
              (t (setf (tls-recv-buffer conn) recv-buffer)
                 (return-from tls-recv nil)))))))))

(defun tls-close (conn)
  "Send a close_notify alert and close the underlying transport."
  (ignore-errors
    (when (eq (tls-state conn) :established)
      (transport-send (tls-transport conn)
                      (encrypt-record conn (bv 1 0) +content-alert+ :app t))))
  (transport-close (tls-transport conn))
  (setf (tls-state conn) :closed)
  nil)

;;; ---- verification ----------------------------------------------------------

(defun run-verification (conn verify host trust-store)
  "Apply the VERIFY policy against CONN's peer certificates.
VERIFY may be:
  T          full validation: chain to a trusted CA + validity dates + hostname
             + the CertificateVerify signature (the secure default);
  :hostname  leaf-cert name match only, plus CertificateVerify (no chain);
  NIL        no authentication whatsoever (see the README);
  a function of (certificates host) returning a generalized boolean."
  (let ((certs (tls-peer-certificates conn)))
    (cond
      ((null verify) t)
      ((eq verify t)
       (unless certs
         (error 'tls-certificate-error :message "server presented no certificates"))
       ;; CertificateVerify was checked during the handshake; make sure of it.
       (unless (eq (tls-cert-verify-ok conn) t)
         (error 'tls-certificate-bad-signature-error
                :message "CertificateVerify was not established"))
       (validate-chain certs (resolve-trust-store trust-store) host)
       t)
      ((eq verify :hostname)
       (unless (and certs (certificate-matches-host-p (first certs) host))
         (error 'tls-certificate-hostname-error
                :message (format nil "no certificate name matches ~a" host)))
       t)
      ((functionp verify)
       (unless (funcall verify certs host)
         (error 'tls-verify-error :message "verify function rejected the certificate"))
       t)
      (t (error 'tls-error :message "invalid :verify option")))))

;;; ---- public entry point ----------------------------------------------------

(defun connect (host port &key (verify t) (timeout 30) transport
                              (trust-store :system)
                              (alpn '("http/1.1")) early-data)
  "Open a TLS 1.3 connection to HOST:PORT and complete the handshake.

  :verify      authentication policy, T by default (the secure default for real
               use): build and verify the certificate chain to a trusted CA,
               check validity dates and hostname, and verify the server's
               CertificateVerify signature. Other values: :hostname (name match
               only), NIL (no authentication — see the README), or a function
               (certificates host) -> generalized-boolean.
  :trust-store with :verify T, the CA trust anchors: a TRUST-STORE, :system
               (default; the OS CA bundle), or a pathname/string to a PEM file.
  :timeout     per-receive socket timeout, seconds.
  :transport   a pre-built TRANSPORT; if NIL, a TCP transport is opened to HOST:PORT.
  :alpn        list of ALPN protocol names to advertise (NIL to omit).
  :early-data  optional application bytes sent alongside the client Finished.

Returns a TLS-CONNECTION, or signals a TLS-ERROR / TLS-CERTIFICATE-ERROR."
  (let* ((tp (or transport (make-socket-transport host port :timeout timeout)))
         (conn (make-tls-connection :transport tp
                                    :host (and (stringp host) host)
                                    :verify verify
                                    :early-data early-data)))
    (handler-case
        (progn
          (handshake conn (and (stringp host) host) alpn)
          (run-verification conn verify host trust-store)
          conn)
      (error (e)
        (ignore-errors (transport-close tp))
        (error e)))))

(defmacro with-connection ((var host port &rest options) &body body)
  "Open a TLS connection bound to VAR, run BODY, and close it afterward."
  `(let ((,var (connect ,host ,port ,@options)))
     (unwind-protect (progn ,@body)
       (tls-close ,var))))
