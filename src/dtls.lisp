;;;; dtls.lisp — DTLS 1.2 client (RFC 6347), the datagram profile of TLS 1.2.
;;;;
;;;; seal already carries a complete TLS 1.2 client (tls12.lisp): the PRF, the
;;;; master-secret / key-block schedule, AES-128-GCM record protection, and the
;;;; ServerHello / Certificate / ServerKeyExchange parsers.  DTLS reuses all of
;;;; that arithmetic verbatim; what differs is only the *framing* — an explicit
;;;; record layer with epoch + 48-bit sequence numbers, handshake messages that
;;;; carry a message_seq + fragment offset/length and may be reassembled, a
;;;; stateless cookie exchange (HelloVerifyRequest), and flight retransmission
;;;; over an unreliable datagram transport.  This module writes that delta and
;;;; leans on tls12.lisp for the cryptography.
;;;;
;;;; It is transport-agnostic: the caller supplies a SEND-FN (a thunk of one
;;;; datagram) and drives receive by handing whole datagrams to the handshake
;;;; via a RECV-FN.  WebRTC needs mutual authentication, so unlike seal's normal
;;;; client this one also presents a client Certificate + CertificateVerify —
;;;; the certificate DER and a signing closure are supplied by the caller (which
;;;; owns key generation), keeping seal itself free of private-key operations.

(in-package #:seal)

(defvar *dtls-log* nil
  "When bound to a stream, DTLS logs handshake record flow to it (debugging).")
(defun %dlog (fmt &rest args)
  (when *dtls-log* (apply #'format *dtls-log* fmt args) (finish-output *dtls-log*)))

;;; ---- constants -------------------------------------------------------------

(defconstant +dtls-12-major+ #xfe)
(defconstant +dtls-12-minor+ #xfd)                 ; DTLS 1.2 = 0xFEFD
(defconstant +hs-hello-verify-request+ 3)

;; TLS signature-scheme codes we may name on the wire.
(defconstant +sig-rsa-pkcs1-sha256+ #x0401)
(defconstant +sig-ecdsa-secp256r1-sha256+ #x0403)

;;; ---- little byte helpers ---------------------------------------------------

(defun %db (&rest bs)
  (make-array (length bs) :element-type '(unsigned-byte 8) :initial-contents bs))
(defun %dcat (&rest seqs)
  (apply #'concatenate '(vector (unsigned-byte 8)) seqs))
(defun %d16 (n) (%db (ldb (byte 8 8) n) (ldb (byte 8 0) n)))
(defun %d24 (n) (%db (ldb (byte 8 16) n) (ldb (byte 8 8) n) (ldb (byte 8 0) n)))
(defun %d48 (n)
  (%db (ldb (byte 8 40) n) (ldb (byte 8 32) n) (ldb (byte 8 24) n)
       (ldb (byte 8 16) n) (ldb (byte 8 8) n) (ldb (byte 8 0) n)))
(defun %read-u48 (v off)
  (let ((n 0)) (dotimes (i 6 n) (setf n (logior (ash n 8) (aref v (+ off i)))))))

;;; ---- session ---------------------------------------------------------------

(defstruct (dtls-session (:conc-name dtls-))
  ;; caller-supplied identity + I/O
  send-fn                              ; (lambda (datagram-bytes) ...) -> t
  cert-der                             ; our certificate DER (byte vector)
  sign-fn                              ; (lambda (msg-bytes) -> signature) rsa_pkcs1_sha256
  (sig-scheme-code +sig-rsa-pkcs1-sha256+)
  expected-peer-fingerprint            ; colon-hex upper SHA-256, or NIL (no check)
  ;; negotiated parameters
  cipher
  client-random server-random
  eph-priv eph-pub server-eph-pub      ; X25519 ephemeral key agreement
  master-secret
  client-key server-key client-iv server-iv
  peer-cert peer-fingerprint
  cert-requested
  ;; record-layer sequence counters (monotonic per epoch; fresh on retransmit)
  (seq0 0) (seq1 0)
  ;; handshake message_seq (our outgoing) + reassembly of the peer's messages
  (msg-seq 0)
  (reasm (make-hash-table))
  (transcript (make-array 0 :element-type '(unsigned-byte 8)
                            :adjustable t :fill-pointer 0))
  (done nil))

(defun dtls-next-msgseq (s)
  (prog1 (dtls-msg-seq s) (incf (dtls-msg-seq s))))

(defun dtls-fingerprint (der)
  "The DTLS certificate fingerprint aiortc/browsers advertise in SDP: SHA-256 of
the DER, upper-case colon-hex (AA:BB:...)."
  (format nil "~{~2,'0X~^:~}" (coerce (sha256 der) 'list)))

;;; ---- record layer ----------------------------------------------------------

(defun dtls-record (type epoch seq fragment)
  "A plaintext DTLS record: type|0xFEFD|epoch(2)|seq(6)|len(2)|fragment."
  (%dcat (%db type +dtls-12-major+ +dtls-12-minor+)
         (%d16 epoch) (%d48 seq) (%d16 (length fragment)) fragment))

(defun dtls-split-records (datagram)
  "Split a UDP DATAGRAM into its concatenated DTLS records."
  (let ((out nil) (pos 0) (n (length datagram)))
    (loop while (<= (+ pos 13) n) do
      (let ((len (bytes-u16 datagram (+ pos 11))))
        (when (> (+ pos 13 len) n) (return))
        (push (subseq datagram pos (+ pos 13 len)) out)
        (setf pos (+ pos 13 len))))
    (nreverse out)))

(defun dtls-record-type (rec) (aref rec 0))
(defun dtls-record-epoch (rec) (bytes-u16 rec 3))
(defun dtls-record-seq (rec) (%read-u48 rec 5))
(defun dtls-record-fragment (rec) (subseq rec 13 (+ 13 (bytes-u16 rec 11))))

;;; ---- AEAD record protection (AES-128-GCM, RFC 5288 profiled for DTLS) ------
;;; nonce = write_iv(4) || explicit(8);  explicit = epoch(2) || seq(6).
;;; AAD   = epoch(2) || seq(6) || type(1) || 0xFEFD || plaintext_length(2).

(defun dtls-encrypt (s type plaintext &key (epoch 1))
  (let* ((seq (dtls-seq1 s))
         (expl (%dcat (%d16 epoch) (%d48 seq)))
         (nonce (%dcat (dtls-client-iv s) expl))
         (aad (%dcat (%d16 epoch) (%d48 seq)
                     (%db type +dtls-12-major+ +dtls-12-minor+)
                     (%d16 (length plaintext))))
         (res (aes-gcm-encrypt (dtls-client-key s) nonce plaintext aad))
         (fragment (%dcat expl (car res) (cdr res))))
    (incf (dtls-seq1 s))
    (dtls-record type epoch seq fragment)))

(defun dtls-decrypt (s rec)
  "Decrypt an epoch-1 record; returns (values content-type plaintext) or
(values type NIL) if the tag fails."
  (let* ((type (dtls-record-type rec))
         (epoch (dtls-record-epoch rec))
         (seq (dtls-record-seq rec))
         (frag (dtls-record-fragment rec))
         (expl (subseq frag 0 8))
         (ctlen (- (length frag) 8 16))
         (ct (subseq frag 8 (+ 8 ctlen)))
         (tag (subseq frag (+ 8 ctlen)))
         (nonce (%dcat (dtls-server-iv s) expl))
         (aad (%dcat (%d16 epoch) (%d48 seq)
                     (%db type +dtls-12-major+ +dtls-12-minor+) (%d16 ctlen))))
    (values type (aes-gcm-decrypt (dtls-server-key s) nonce ct aad tag))))

;;; ---- handshake framing + transcript ----------------------------------------

(defun dtls-handshake (type msg-seq body)
  "A DTLS handshake message as a single unfragmented fragment:
type(1)|len(3)|message_seq(2)|frag_off(3)=0|frag_len(3)=len|body.  This 12-byte
header form is also exactly what the Finished/CertificateVerify transcript hash
covers (RFC 6347 §4.2.6)."
  (let ((len (length body)))
    (%dcat (%db type) (%d24 len) (%d16 msg-seq) (%d24 0) (%d24 len) body)))

(defun dtls-add-transcript (s bytes)
  (loop for b across bytes do (vector-push-extend b (dtls-transcript s))))

(defun dtls-reset-transcript (s)
  (setf (dtls-transcript s)
        (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))

(defun dtls-transcript-bytes (s)
  (coerce (dtls-transcript s) '(simple-array (unsigned-byte 8) (*))))

(defun dtls-transcript-hash (s)
  (sha256 (dtls-transcript-bytes s)))

;;; ---- handshake reassembly --------------------------------------------------

(defun dtls-hs-fragments (rec)
  "Return the handshake fragments carried by a plaintext handshake record.
Each element is the fragment bytes starting at its msg_type."
  (let ((frag (dtls-record-fragment rec)) (out nil) (pos 0) (n 0))
    (setf n (length frag))
    (loop while (<= (+ pos 12) n) do
      (let ((flen (bytes-u24 frag (+ pos 9))))
        (when (> (+ pos 12 flen) n) (return))
        (push (subseq frag pos (+ pos 12 flen)) out)
        (setf pos (+ pos 12 flen))))
    (nreverse out)))

(defun dtls-reassemble (s frag)
  "Feed one handshake FRAGMENT; return (list type msg-seq body) once its message
is complete, else NIL."
  (let* ((type (aref frag 0))
         (len (bytes-u24 frag 1))
         (mseq (bytes-u16 frag 4))
         (foff (bytes-u24 frag 6))
         (flen (bytes-u24 frag 9))
         (body (subseq frag 12 (+ 12 flen)))
         (entry (gethash mseq (dtls-reasm s))))
    (unless entry
      (setf entry (list (make-array len :element-type '(unsigned-byte 8))
                        (make-array (max len 1) :element-type 'bit :initial-element 0)
                        type)
            (gethash mseq (dtls-reasm s)) entry))
    (destructuring-bind (buf got mtype) entry
      (declare (ignore mtype))
      (when (<= (+ foff flen) len)
        (replace buf body :start1 foff)
        (fill got 1 :start foff :end (+ foff flen)))
      (when (loop for i below len always (= (aref got i) 1))
        (remhash mseq (dtls-reasm s))
        (list type mseq buf)))))

;;; ---- ClientHello (DTLS flavour: carries a cookie) --------------------------

(defun dtls-ext (type data) (%dcat (%d16 type) (%d16 (length data)) data))

(defun dtls-client-hello-body (s cookie)
  (let* ((random (dtls-client-random s))
         ;; x25519 (used for the ECDHE key exchange) + secp256r1 (so the server's
         ;; P-256 ECDSA certificate is acceptable; OpenSSL still prefers x25519
         ;; for the actual key agreement, which is all our SKE parser handles).
         (groups (dtls-ext +ext-supported-groups+ (%db 0 4 0 #x1d 0 #x17)))
         (ecpf (dtls-ext +ext-ec-point-formats+ (%db 1 0)))                   ; uncompressed
         (sigalgs (dtls-ext +ext-signature-algorithms+
                            (%db 0 10  #x04 #x03  #x04 #x01  #x08 #x04  #x05 #x03  #x06 #x03)))
         (reneg (dtls-ext #xff01 (%db 0)))                                    ; empty renegotiation_info
         ;; use_srtp (RFC 5764): WebRTC stacks (aiortc) reject a DTLS handshake
         ;; that negotiates no DTLS-SRTP profile, even for a data-channel-only
         ;; session.  Offer the two profiles aiortc supports; empty MKI.
         (srtp (dtls-ext 14 (%db 0 4 0 1 0 7 0)))   ; SRTP_AES128_CM_SHA1_80 + SRTP_AEAD_AES_128_GCM
         (exts (%dcat groups ecpf sigalgs reneg srtp))
         (suites (%db #xc0 #x2b #xc0 #x2f)))                                  ; ECDHE_ECDSA / ECDHE_RSA + AES128-GCM
    (%dcat (%db +dtls-12-major+ +dtls-12-minor+)          ; client_version
           random                                          ; 32-byte random
           (%db 0)                                         ; session_id: empty
           (%db (length cookie)) cookie                    ; cookie
           (%d16 (length suites)) suites                   ; cipher_suites
           (%db 1 0)                                        ; compression: null
           (%d16 (length exts)) exts)))                    ; extensions

(defun dtls-build-client-hello (s cookie)
  "Build a ClientHello handshake message (assigning the next message_seq)."
  (dtls-handshake +hs-client-hello+ (dtls-next-msgseq s)
                  (dtls-client-hello-body s cookie)))

;;; ---- server-flight parsing -------------------------------------------------

(defun dtls-parse-hvr (body) (subseq body 3 (+ 3 (aref body 2))))   ; version(2) len(1) cookie

(defun dtls-parse-server-hello (s body)
  (let ((pos 2))                                          ; skip server_version
    (setf (dtls-server-random s) (subseq body pos (+ pos 32)))
    (incf pos 32)
    (incf pos (1+ (aref body pos)))                       ; skip session_id echo
    (setf (dtls-cipher s) (bytes-u16 body pos))))         ; cipher_suite

(defun dtls-parse-certificate (s body)
  (let* ((clen (bytes-u24 body 3))
         (der (subseq body 6 (+ 6 clen))))
    (setf (dtls-peer-cert s) (ignore-errors (parse-certificate der))
          (dtls-peer-fingerprint s) (dtls-fingerprint der))))

(defun dtls-handle-ske (s body)
  "Parse a ServerKeyExchange (X25519) and record the server's ephemeral key;
best-effort verification of its signature against the leaf certificate."
  (multiple-value-bind (params pubkey sigalg signature)
      (tls12-parse-ske (make-handshake +hs-server-key-exchange+ body))
    (setf (dtls-server-eph-pub s) pubkey)
    (let ((cert (dtls-peer-cert s)))
      (when (and cert (certificate-spki cert))
        (multiple-value-bind (scheme hash salt) (tls-signature-scheme sigalg)
          (when scheme
            (let ((signed (%dcat (dtls-client-random s) (dtls-server-random s) params)))
              (unless (ignore-errors
                        (verify-signature (certificate-spki cert) scheme hash salt
                                          signed signature))
                (warn "DTLS: ServerKeyExchange signature did not verify")))))))))

;;; ---- key schedule (reusing tls12.lisp's PRF) -------------------------------

(defun dtls-derive-keys (s)
  (let* ((pm (x25519 (dtls-eph-priv s) (dtls-server-eph-pub s)))
         (cr (dtls-client-random s)) (sr (dtls-server-random s))
         (master (tls12-prf pm "master secret" (%dcat cr sr) 48))
         (kb (tls12-prf master "key expansion" (%dcat sr cr) 40)))   ; 2*16 keys + 2*4 IVs
    (setf (dtls-master-secret s) master
          (dtls-client-key s) (subseq kb 0 16)
          (dtls-server-key s) (subseq kb 16 32)
          (dtls-client-iv s) (subseq kb 32 36)
          (dtls-server-iv s) (subseq kb 36 40))))

(defun dtls-finished-data (s label)
  (tls12-prf (dtls-master-secret s) label (dtls-transcript-hash s) 12))

;;; ---- our authentication flight (Certificate + CertificateVerify) -----------

(defun dtls-certificate-body (cert-der)
  (let ((entry (%dcat (%d24 (length cert-der)) cert-der)))
    (%dcat (%d24 (length entry)) entry)))

(defun dtls-certificate-verify-body (s)
  "Sign the handshake transcript so far (ClientHello..ClientKeyExchange) and wrap
it as a CertificateVerify body: SignatureAndHashAlgorithm(2) || len(2) || sig."
  (let ((sig (funcall (dtls-sign-fn s) (dtls-transcript-bytes s))))
    (%dcat (%d16 (dtls-sig-scheme-code s)) (%d16 (length sig)) sig)))

;;; ---- flight (re)transmission ----------------------------------------------
;;; A flight is a list of specs; transmitting one (re)wraps each message in a
;;; record with a *fresh* record sequence number, so retransmissions are never
;;; dropped as replays.

(defun dtls-transmit-flight (s specs)
  (let ((epoch 0))
    (dolist (spec specs)
      (ecase (car spec)
        (:plain
         (funcall (dtls-send-fn s)
                  (dtls-record +content-handshake+ 0 (prog1 (dtls-seq0 s) (incf (dtls-seq0 s)))
                               (cadr spec))))
        (:ccs
         (funcall (dtls-send-fn s)
                  (dtls-record +content-change-cipher-spec+ 0
                               (prog1 (dtls-seq0 s) (incf (dtls-seq0 s))) (%db 1)))
         (setf epoch 1))
        (:enc
         (funcall (dtls-send-fn s) (dtls-encrypt s +content-handshake+ (cadr spec) :epoch epoch)))))))

;;; ---- the client handshake --------------------------------------------------

(defun dtls-client-handshake (s recv-fn &key (timeout 1.0) (max-retries 25))
  "Drive the DTLS 1.2 client handshake to completion.  RECV-FN is called with a
timeout (seconds) and returns the next inbound datagram or NIL on timeout.
Returns S on success; signals TLS-ERROR otherwise."
  (setf (dtls-eph-priv s) (secure-random-bytes 32)
        (dtls-eph-pub s) (x25519-public-key (dtls-eph-priv s))
        (dtls-client-random s) (secure-random-bytes 32))
  (let ((cur-ch (dtls-build-client-hello s #()))       ; flight 1: ClientHello, no cookie
        (server-done nil)
        (tries 0))
    (flet ((send-ch ()
             (funcall (dtls-send-fn s)
                      (dtls-record +content-handshake+ 0
                                   (prog1 (dtls-seq0 s) (incf (dtls-seq0 s))) cur-ch))))
      ;; ----- flights 1..3: ClientHello(/cookie) then the server flight -----
      (send-ch)
      (%dlog "~&[dtls] -> ClientHello (flight 1)~%")
      (loop until server-done do
        (let ((dg (funcall recv-fn timeout)))
          (cond
            ((null dg)
             (incf tries)
             (%dlog "[dtls] recv timeout (try ~a), resending ClientHello~%" tries)
             (when (> tries max-retries)
               (error 'tls-error :message "DTLS: timed out awaiting server flight"))
             (send-ch))
            (t
             (%dlog "[dtls] <- datagram ~a bytes, ~a record(s)~%"
                    (length dg) (length (dtls-split-records dg)))
             (dolist (rec (dtls-split-records dg))
               (%dlog "[dtls]    record type=~a epoch=~a len=~a~%"
                      (dtls-record-type rec) (dtls-record-epoch rec) (length rec))
               (when (and (= (dtls-record-type rec) +content-alert+) (>= (length rec) 15))
                 (%dlog "[dtls]    !! ALERT level=~a description=~a~%"
                        (aref rec 13) (aref rec 14)))
               (when (and (= (dtls-record-type rec) +content-handshake+)
                          (= (dtls-record-epoch rec) 0))
                 (dolist (frag (dtls-hs-fragments rec))
                   (let ((msg (dtls-reassemble s frag)))
                     (when msg
                       (destructuring-bind (mtype mseq body) msg
                         (%dlog "[dtls]    hs msg type=~a seq=~a len=~a~%"
                                mtype mseq (length body))
                         (cond
                           ((= mtype +hs-hello-verify-request+)
                            ;; cookie exchange: resend ClientHello WITH the cookie,
                            ;; and (re)start the transcript at that ClientHello.
                            (clrhash (dtls-reasm s))
                            (setf cur-ch (dtls-build-client-hello s (dtls-parse-hvr body)))
                            (send-ch))
                           ((= mtype +hs-server-hello+)
                            (dtls-reset-transcript s)
                            (dtls-add-transcript s cur-ch)
                            (dtls-add-transcript s (dtls-handshake +hs-server-hello+ mseq body))
                            (dtls-parse-server-hello s body))
                           ((= mtype +hs-certificate+)
                            (dtls-parse-certificate s body)
                            (dtls-add-transcript s (dtls-handshake mtype mseq body)))
                           ((= mtype +hs-server-key-exchange+)
                            (dtls-handle-ske s body)
                            (dtls-add-transcript s (dtls-handshake mtype mseq body)))
                           ((= mtype +hs-certificate-request+)
                            (setf (dtls-cert-requested s) t)
                            (dtls-add-transcript s (dtls-handshake mtype mseq body)))
                           ((= mtype +hs-server-hello-done+)
                            (dtls-add-transcript s (dtls-handshake mtype mseq body))
                            (setf server-done t))
                           (t nil)))))))))))))
    ;; ----- fingerprint check (the actual WebRTC authentication) -----
    (let ((exp (dtls-expected-peer-fingerprint s)))
      (when (and exp (dtls-peer-fingerprint s)
                 (not (string-equal exp (dtls-peer-fingerprint s))))
        (warn "DTLS: peer certificate fingerprint ~a does not match SDP ~a"
              (dtls-peer-fingerprint s) exp)))
    (unless (dtls-server-eph-pub s)
      (error 'tls-error :message "DTLS: no ServerKeyExchange (x25519) received"))
    ;; ----- our flight: Certificate, ClientKeyExchange, CertificateVerify,
    ;;       ChangeCipherSpec, Finished -----
    (dtls-derive-keys s)
    (let* ((cert-hs (when (dtls-cert-requested s)
                      (dtls-handshake +hs-certificate+ (dtls-next-msgseq s)
                                      (dtls-certificate-body (dtls-cert-der s)))))
           (cke-hs (dtls-handshake +hs-client-key-exchange+ (dtls-next-msgseq s)
                                   (%dcat (%db 32) (dtls-eph-pub s)))))
      (when cert-hs (dtls-add-transcript s cert-hs))
      (dtls-add-transcript s cke-hs)
      (let* ((cv-hs (when (dtls-cert-requested s)
                      (dtls-handshake +hs-certificate-verify+ (dtls-next-msgseq s)
                                      (dtls-certificate-verify-body s)))))
        (when cv-hs (dtls-add-transcript s cv-hs))
        (let* ((fin-body (dtls-finished-data s "client finished"))
               (fin-hs (dtls-handshake +hs-finished+ (dtls-next-msgseq s) fin-body))
               (specs (append (when cert-hs (list (list :plain cert-hs)))
                              (list (list :plain cke-hs))
                              (when cv-hs (list (list :plain cv-hs)))
                              (list (list :ccs) (list :enc fin-hs)))))
          (dtls-add-transcript s fin-hs)           ; server Finished covers our Finished
          (let ((expected-server-fin (dtls-finished-data s "server finished")))
            ;; ----- send our flight, await the server's CCS + Finished -----
            (%dlog "[dtls] -> flight 2 (Cert/CKE/CertVerify/CCS/Finished) cipher=0x~4,'0x cert-req=~a~%"
                   (or (dtls-cipher s) 0) (dtls-cert-requested s))
            (dtls-transmit-flight s specs)
            (setf tries 0)
            (loop until (dtls-done s) do
              (let ((dg (funcall recv-fn timeout)))
                (cond
                  ((null dg)
                   (incf tries)
                   (when (> tries max-retries)
                     (error 'tls-error :message "DTLS: timed out awaiting server Finished"))
                   (dtls-transmit-flight s specs))
                  (t
                   (dolist (rec (dtls-split-records dg))
                     (when (and (= (dtls-record-type rec) +content-handshake+)
                                (= (dtls-record-epoch rec) 1))
                       (multiple-value-bind (type pt) (dtls-decrypt s rec)
                         (declare (ignore type))
                         (when (and pt (>= (length pt) 12)
                                    (= (aref pt 0) +hs-finished+))
                           (let ((got (subseq pt 12 (+ 12 (bytes-u24 pt 1)))))
                             (unless (equalp got expected-server-fin)
                               (error 'tls-error :message "DTLS: server Finished mismatch"))
                             (setf (dtls-done s) t)))))))))))))))
  s)

;;; ---- application data (for the SCTP layer that sits on top) ----------------

(defun dtls-send-app (s data)
  "Encrypt DATA as a DTLS application-data record and send it."
  (funcall (dtls-send-fn s)
           (dtls-encrypt s +content-application-data+
                         (coerce data '(simple-array (unsigned-byte 8) (*))) :epoch 1)))

(defun dtls-handle-datagram (s datagram)
  "Decrypt any application-data records in DATAGRAM; return a list of plaintext
payloads (epoch-1 appdata only).  Handshake/CCS records are ignored."
  (let ((out nil))
    (dolist (rec (dtls-split-records datagram) (nreverse out))
      (when (and (= (dtls-record-type rec) +content-application-data+)
                 (= (dtls-record-epoch rec) 1))
        (multiple-value-bind (type pt) (dtls-decrypt s rec)
          (when (and pt (= type +content-application-data+))
            (push pt out)))))))
