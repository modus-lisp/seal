;;;; tls12.lisp — TLS 1.2 client (RFC 5246), ECDHE key exchange over X25519.
;;;;
;;;; A fallback path for servers that do not offer TLS 1.3. The ClientHello
;;;; (built in tls13.lisp) offers both versions and both cipher-suite families;
;;;; parse-server-hello records the negotiated version, and handshake branches
;;;; here when the server chose 0x0303. Only forward-secret AEAD suites are
;;;; supported: ECDHE_{RSA,ECDSA} with AES-128-GCM (RFC 5288) or
;;;; ChaCha20-Poly1305 (RFC 7905). No CBC, no static-RSA key transport.

(in-package #:seal)

;;; ---- PRF (RFC 5246 §5) -----------------------------------------------------
;;; For every SHA-256 suite here the PRF is P_SHA256.

(defun tls12-p-sha256 (secret seed length)
  "P_SHA256(secret, seed) truncated to LENGTH bytes. A(0)=seed,
A(i)=HMAC(secret,A(i-1)); output = HMAC(secret,A(i)||seed) concatenated."
  (let ((out (make-array length :element-type '(unsigned-byte 8)))
        (pos 0)
        (a (hmac-sha256 secret seed)))          ; A(1)
    (loop while (< pos length) do
      (let* ((block (hmac-sha256 secret (concatenate '(vector (unsigned-byte 8)) a seed)))
             (take (min (length block) (- length pos))))
        (replace out block :start1 pos :end2 take)
        (incf pos take)
        (setf a (hmac-sha256 secret a))))        ; A(i+1)
    out))

(defun tls12-prf (secret label seed length)
  "TLS 1.2 PRF with the SHA-256 P_hash: PRF(secret, label, seed)."
  (tls12-p-sha256 secret
                  (concatenate '(vector (unsigned-byte 8))
                               (map '(vector (unsigned-byte 8)) #'char-code label)
                               seed)
                  length))

;;; ---- cipher-suite properties -----------------------------------------------

(defun tls12-cipher-params (cipher)
  "Return (values mode key-length iv-length) for a TLS 1.2 AEAD CIPHER suite.
MODE is :gcm or :chacha; IV-LENGTH is the fixed (implicit) nonce length."
  (cond
    ((or (= cipher +cs-ecdhe-rsa-chacha20-poly1305-sha256+)
         (= cipher +cs-ecdhe-ecdsa-chacha20-poly1305-sha256+))
     (values :chacha 32 12))
    ((or (= cipher +cs-ecdhe-rsa-aes128-gcm-sha256+)
         (= cipher +cs-ecdhe-ecdsa-aes128-gcm-sha256+))
     (values :gcm 16 4))
    (t (error 'tls-error
              :message (format nil "unsupported TLS 1.2 cipher 0x~4,'0x" cipher)))))

;;; ---- record protection (RFC 5288 / RFC 7905) -------------------------------

(defun u64be (n)
  "N as an 8-byte big-endian vector."
  (let ((v (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 v) (setf (aref v i) (logand (ash n (* -8 (- 7 i))) #xff)))))

(defun tls12-aad (seq content-type plaintext-len)
  "Additional data for a TLS 1.2 AEAD record:
seq_num(8) || type(1) || version(2) || plaintext_length(2)."
  (let ((aad (make-array 13 :element-type '(unsigned-byte 8))))
    (replace aad (u64be seq))
    (setf (aref aad 8) content-type
          (aref aad 9) #x03 (aref aad 10) #x03
          (aref aad 11) (logand (ash plaintext-len -8) #xff)
          (aref aad 12) (logand plaintext-len #xff))
    aad))

(defun tls12-chacha-nonce (iv seq)
  "RFC 7905 nonce: the 12-byte write IV XOR (4 zero bytes || seq as 8-byte BE)."
  (let ((nonce (copy-seq iv)))
    (dotimes (i 8 nonce)
      (setf (aref nonce (- 11 i))
            (logxor (aref nonce (- 11 i)) (logand (ash seq (* -8 i)) #xff))))))

(defun tls12-encrypt-record (conn content-type plaintext)
  "Encrypt PLAINTEXT as a TLS 1.2 record of CONTENT-TYPE and return the record."
  (multiple-value-bind (mode key-len iv-len) (tls12-cipher-params (tls-cipher conn))
    (declare (ignore key-len iv-len))
    (let* ((key (tls-t12-client-key conn))
           (iv (tls-t12-client-iv conn))
           (seq (tls-client-seq conn))
           (aad (tls12-aad seq content-type (length plaintext))))
      (setf (tls-client-seq conn) (1+ seq))
      (ecase mode
        (:chacha
         (let* ((nonce (tls12-chacha-nonce iv seq))
                (res (chacha20-poly1305-encrypt key nonce plaintext aad)))
           (make-record content-type
                        (concatenate '(vector (unsigned-byte 8)) (car res) (cdr res)))))
        (:gcm
         (let* ((explicit (u64be seq))          ; explicit nonce = record seq num
                (nonce (concatenate '(vector (unsigned-byte 8)) iv explicit))
                (res (aes-gcm-encrypt key nonce plaintext aad)))
           (make-record content-type
                        (concatenate '(vector (unsigned-byte 8))
                                     explicit (car res) (cdr res)))))))))

(defun tls12-decrypt-record (conn record)
  "Decrypt a TLS 1.2 RECORD (5-byte header + fragment). Returns (values
content-type plaintext), or NIL if the tag does not verify."
  (multiple-value-bind (mode key-len iv-len) (tls12-cipher-params (tls-cipher conn))
    (declare (ignore key-len iv-len))
    (let* ((content-type (aref record 0))
           (key (tls-t12-server-key conn))
           (iv (tls-t12-server-iv conn))
           (seq (tls-server-seq conn))
           (frag (subseq record 5)))
      (ecase mode
        (:chacha
         (let* ((ct-len (- (length frag) 16))
                (ct (subseq frag 0 ct-len))
                (tag (subseq frag ct-len))
                (nonce (tls12-chacha-nonce iv seq))
                (aad (tls12-aad seq content-type ct-len))
                (pt (chacha20-poly1305-decrypt key nonce ct tag aad)))
           (unless pt (return-from tls12-decrypt-record nil))
           (setf (tls-server-seq conn) (1+ seq))
           (values content-type pt)))
        (:gcm
         (let* ((explicit (subseq frag 0 8))    ; strip the explicit nonce
                (ct-len (- (length frag) 8 16))
                (ct (subseq frag 8 (+ 8 ct-len)))
                (tag (subseq frag (+ 8 ct-len)))
                (nonce (concatenate '(vector (unsigned-byte 8)) iv explicit))
                (aad (tls12-aad seq content-type ct-len))
                (pt (aes-gcm-decrypt key nonce ct aad tag)))
           (unless pt (return-from tls12-decrypt-record nil))
           (setf (tls-server-seq conn) (1+ seq))
           (values content-type pt)))))))

;;; ---- key derivation --------------------------------------------------------

(defun tls12-derive-keys (conn premaster)
  "Derive master_secret and the key_block from PREMASTER (RFC 5246 §6.3), then
split it into the write keys and fixed IVs (no MAC keys for AEAD suites). When
the extended_master_secret extension (RFC 7627) was negotiated, the master
secret is bound to the session_hash instead of the two randoms; the transcript
must already cover ClientHello..ClientKeyExchange."
  (let* ((cr (tls-client-random conn))
         (sr (tls-server-random conn))
         (master (if (tls-t12-ems conn)
                     (tls12-prf premaster "extended master secret"
                                (transcript-hash conn) 48)
                     (tls12-prf premaster "master secret"
                                (concatenate '(vector (unsigned-byte 8)) cr sr) 48))))
    (setf (tls-master-secret conn) master)
    (multiple-value-bind (mode key-len iv-len) (tls12-cipher-params (tls-cipher conn))
      (declare (ignore mode))
      (let* ((needed (+ (* 2 key-len) (* 2 iv-len)))
             (kb (tls12-prf master "key expansion"
                            (concatenate '(vector (unsigned-byte 8)) sr cr) needed))
             (ck 0) (sk key-len) (ci (* 2 key-len)) (si (+ (* 2 key-len) iv-len)))
        (setf (tls-t12-client-key conn) (subseq kb ck (+ ck key-len))
              (tls-t12-server-key conn) (subseq kb sk (+ sk key-len))
              (tls-t12-client-iv conn)  (subseq kb ci (+ ci iv-len))
              (tls-t12-server-iv conn)  (subseq kb si (+ si iv-len))
              (tls-client-seq conn) 0
              (tls-server-seq conn) 0)))))

(defun tls12-finished-data (conn label)
  "verify_data = PRF(master_secret, LABEL, SHA256(handshake_messages), 12)."
  (tls12-prf (tls-master-secret conn) label (transcript-hash conn) 12))

;;; ---- server-flight message parsing -----------------------------------------

(defun tls12-parse-certificate (conn hs-msg)
  "Extract the peer certificate chain from a TLS 1.2 Certificate message (no
request context, no per-certificate extensions)."
  (let* ((pos 4)
         (list-len (bytes-u24 hs-msg pos))
         (list-end (+ pos 3 list-len))
         (certs nil))
    (incf pos 3)
    (loop while (< pos list-end) do
      (let* ((cert-len (bytes-u24 hs-msg pos))
             (cert-der (subseq hs-msg (+ pos 3) (+ pos 3 cert-len))))
        (push (handler-case (parse-certificate cert-der)
                (error () (make-certificate :raw cert-der)))
              certs)
        (incf pos (+ 3 cert-len))))
    (setf (tls-peer-certificates conn) (nreverse certs))))

(defun tls12-parse-ske (hs-msg)
  "Parse an ECDHE ServerKeyExchange. Returns (values params pubkey sigalg
signature), where PARAMS is the signed ServerECDHParams byte range."
  (let* ((pos 4)
         (curve-type (aref hs-msg pos)))
    (unless (= curve-type 3)
      (error 'tls-error :message "ServerKeyExchange: expected named_curve"))
    (let ((named-curve (bytes-u16 hs-msg (+ pos 1))))
      (unless (= named-curve #x001d)             ; x25519
        (error 'tls-error
               :message (format nil "ServerKeyExchange: unsupported curve 0x~4,'0x" named-curve)))
      (let* ((pk-len (aref hs-msg (+ pos 3)))   ; curve_type(1) + named_curve(2)
             (pubkey (subseq hs-msg (+ pos 4) (+ pos 4 pk-len)))
             (params (subseq hs-msg pos (+ pos 4 pk-len)))
             (sig-pos (+ pos 4 pk-len))
             (sigalg (bytes-u16 hs-msg sig-pos))
             (sig-len (bytes-u16 hs-msg (+ sig-pos 2)))
             (signature (subseq hs-msg (+ sig-pos 4) (+ sig-pos 4 sig-len))))
        (values params pubkey sigalg signature)))))

(defun tls12-verify-ske (conn params sigalg signature)
  "Verify the ServerKeyExchange signature over
client_random || server_random || params with the leaf certificate's key. This
is TLS 1.2's proof of possession; on success mark CERT-VERIFY-OK."
  (let* ((signed (concatenate '(vector (unsigned-byte 8))
                              (tls-client-random conn) (tls-server-random conn) params))
         (leaf (first (tls-peer-certificates conn))))
    (multiple-value-bind (scheme hash salt) (tls-signature-scheme sigalg)
      (unless (and scheme leaf (certificate-spki leaf))
        (error 'tls-certificate-bad-signature-error
               :message (format nil "unsupported ServerKeyExchange scheme 0x~4,'0x" sigalg)))
      (unless (verify-signature (certificate-spki leaf) scheme hash salt signed signature)
        (error 'tls-certificate-bad-signature-error
               :message "ServerKeyExchange signature did not verify"))
      (setf (tls-cert-verify-ok conn) t))))

;;; ---- the handshake ---------------------------------------------------------

(defun tls12-server-flight (conn transport recv-buffer)
  "Complete a TLS 1.2 handshake after ServerHello. RECV-BUFFER holds any records
already read past the ServerHello. Returns CONN or signals a TLS-ERROR."
  (let ((buffer recv-buffer)
        (hs-buffer #())
        (server-done nil)
        (ske-params nil) (ske-pubkey nil) (ske-sigalg nil) (ske-sig nil))
    (labels ((next-record ()
               (loop
                 (multiple-value-bind (record remaining) (extract-record buffer)
                   (if record
                       (progn (setf buffer remaining) (return record))
                       (let ((more (transport-recv transport)))
                         (unless more
                           (error 'tls-error :message "timed out awaiting TLS 1.2 server flight"))
                         (setf buffer (buffer-append buffer more)))))))
             (drain-handshake (fragment fn)
               ;; Accumulate handshake fragments and hand each complete message
               ;; to FN. Handshake messages may span or share records.
               (setf hs-buffer (buffer-append hs-buffer fragment))
               (loop
                 (when (< (length hs-buffer) 4) (return))
                 (let* ((mlen (bytes-u24 hs-buffer 1)) (total (+ 4 mlen)))
                   (when (< (length hs-buffer) total) (return))
                   (funcall fn (subseq hs-buffer 0 total))
                   (setf hs-buffer (subseq hs-buffer total))))))
      ;; --- read Certificate, ServerKeyExchange, [CertificateRequest],
      ;;     ServerHelloDone (all plaintext handshake records).
      (loop until server-done do
        (let* ((record (next-record))
               (rtype (aref record 0)))
          (cond
            ((= rtype +content-alert+)
             (error 'tls-alert :level (aref record 5) :description (aref record 6)))
            ((= rtype +content-handshake+)
             (drain-handshake
              (subseq record 5)
              (lambda (msg)
                (let ((htype (aref msg 0)))
                  (cond
                    ((= htype +hs-certificate+) (tls12-parse-certificate conn msg))
                    ((= htype +hs-server-key-exchange+)
                     (multiple-value-setq (ske-params ske-pubkey ske-sigalg ske-sig)
                       (tls12-parse-ske msg)))
                    ((= htype +hs-server-hello-done+) (setf server-done t))
                    ;; CertificateRequest is folded into the transcript and
                    ;; declined (empty client Certificate is not sent since we
                    ;; have no client certs; servers here do not require one).
                    (t nil))
                  (add-to-transcript conn msg)))))
            (t (error 'tls-error
                      :message (format nil "unexpected record type ~d in TLS 1.2 handshake" rtype))))))
      ;; --- proof of possession.
      (unless ske-pubkey
        (error 'tls-error :message "TLS 1.2 ServerKeyExchange missing"))
      (setf (tls-server-public-key conn) ske-pubkey)
      (when (tls-verify conn)
        (tls12-verify-ske conn ske-params ske-sigalg ske-sig))
      ;; --- ClientKeyExchange (our X25519 public key, reused from the key_share).
      ;;     It is folded into the transcript before deriving keys so that the
      ;;     extended_master_secret session_hash covers it.
      (let* ((pub (tls-client-public-key conn))
             (cke (make-handshake +hs-client-key-exchange+
                                  (concatenate '(vector (unsigned-byte 8))
                                               (vector (length pub)) pub))))
        (add-to-transcript conn cke)
        (transport-send transport (make-record +content-handshake+ cke)))
      ;; --- shared secret + record keys.
      (tls12-derive-keys conn (x25519 (tls-client-private-key conn) ske-pubkey))
      ;; --- ChangeCipherSpec, then the encrypted client Finished.
      (transport-send transport (bv +content-change-cipher-spec+ 3 3 0 1 1))
      (let ((fin (make-handshake +hs-finished+
                                 (tls12-finished-data conn "client finished"))))
        (add-to-transcript conn fin)
        (transport-send transport (tls12-encrypt-record conn +content-handshake+ fin)))
      ;; --- server flight 2: optional NewSessionTicket (plaintext handshake),
      ;;     ChangeCipherSpec, then the encrypted server Finished.
      (let ((got-ccs nil) (got-finished nil) (nst-buffer #()))
        (loop until got-finished do
          (let* ((record (next-record))
                 (rtype (aref record 0)))
            (cond
              ((= rtype +content-change-cipher-spec+) (setf got-ccs t))
              ((= rtype +content-alert+)
               (error 'tls-alert :level (aref record 5) :description (aref record 6)))
              ((and (= rtype +content-handshake+) (not got-ccs))
               ;; NewSessionTicket precedes ChangeCipherSpec and is covered by the
               ;; server Finished; fold it into the transcript.
               (setf nst-buffer (buffer-append nst-buffer (subseq record 5)))
               (loop
                 (when (< (length nst-buffer) 4) (return))
                 (let* ((mlen (bytes-u24 nst-buffer 1)) (total (+ 4 mlen)))
                   (when (< (length nst-buffer) total) (return))
                   (add-to-transcript conn (subseq nst-buffer 0 total))
                   (setf nst-buffer (subseq nst-buffer total)))))
              ((= rtype +content-handshake+)   ; encrypted Finished
               (multiple-value-bind (ctype pt) (tls12-decrypt-record conn record)
                 (declare (ignore ctype))
                 (unless pt (error 'tls-error :message "server Finished decryption failed"))
                 (let ((expected (tls12-finished-data conn "server finished"))
                       (got (subseq pt 4)))
                   (unless (equalp expected got)
                     (error 'tls-error :message "server Finished verify_data mismatch"))
                   (setf got-finished t))))
              (t (error 'tls-error
                        :message (format nil "unexpected record type ~d awaiting server Finished" rtype)))))))
      ;; Any bytes past the server Finished belong to the app stream.
      (setf (tls-recv-buffer conn) buffer)
      (setf (tls-state conn) :established)
      conn)))

;;; ---- application data ------------------------------------------------------

(defun tls12-recv (conn)
  "Receive the next chunk of TLS 1.2 application data. Returns a byte vector, or
NIL at end of stream."
  (let ((transport (tls-transport conn))
        (recv-buffer (or (tls-recv-buffer conn) #())))
    (loop
      (multiple-value-bind (record remaining) (extract-record recv-buffer)
        (unless record
          (let ((more (transport-recv transport)))
            (unless more
              (setf (tls-recv-buffer conn) recv-buffer)
              (return-from tls12-recv nil))
            (setf recv-buffer (buffer-append recv-buffer more))
            (multiple-value-setq (record remaining) (extract-record recv-buffer))))
        (when record
          (setf recv-buffer remaining)
          (let ((rtype (aref record 0)))
            (cond
              ((= rtype +content-application-data+)
               (multiple-value-bind (ctype pt) (tls12-decrypt-record conn record)
                 (declare (ignore ctype))
                 (unless pt
                   (setf (tls-recv-buffer conn) recv-buffer)
                   (return-from tls12-recv nil))
                 (when (plusp (length pt))
                   (setf (tls-recv-buffer conn) recv-buffer)
                   (return-from tls12-recv pt))))
              ((= rtype +content-handshake+) nil)   ; late ticket / renegotiation
              (t                                     ; alert (incl. close_notify)
               (setf (tls-recv-buffer conn) recv-buffer)
               (return-from tls12-recv nil)))))))))
