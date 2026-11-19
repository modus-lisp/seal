;;;; dtls-server.lisp — the DTLS 1.2 SERVER role (RFC 6347 / RFC 5246), for the WebRTC end that
;;;; offers.
;;;;
;;;; WHY A SERVER.  In WebRTC the DTLS roles come from SDP, not from who dialled: the offer says
;;;; a=setup:actpass and the ANSWERER picks.  Our box (webrtc-data's answerer) always answers
;;;; a=setup:active -- it is the DTLS client -- so whoever offers to it is the DTLS server, exactly
;;;; as a browser is when it offers to the box.  A Lisp peer that dials the box therefore needs this
;;;; half, and it is the half seal never had.
;;;;
;;;; WHAT IT NEGOTIATES is the mirror of what dtls.lisp's client offers, and no more:
;;;;   * TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (c02b) with an ECDSA certificate, or
;;;;     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (c02f) with an RSA one -- picked by the
;;;;     session's SIG-SCHEME-CODE, and only if the client offers it;
;;;;   * ECDHE over X25519 (the client must list group 0x001d);
;;;;   * mutual authentication: a CertificateRequest, then the client's Certificate and
;;;;     CertificateVerify, whose signature is checked against that certificate; trust itself is
;;;;     the SDP fingerprint (EXPECTED-PEER-FINGERPRINT), compared once the certificate is in;
;;;;   * use_srtp (RFC 5764), echoed with one profile the client offered, because WebRTC stacks
;;;;     refuse a handshake without it even for data channels -- AEAD_AES_128_GCM (7) preferred,
;;;;     else AES128_CM_HMAC_SHA1_80 (1);
;;;;   * renegotiation_info and ec_point_formats, echoed when offered.
;;;; Not done: HelloVerifyRequest (optional for a server, RFC 6347 4.2.1 -- the cookie defends
;;;; against spoofed-source amplification, and ICE has already proved the address before DTLS
;;;; starts), extended_master_secret (not echoed, so the plain master secret, which is what our
;;;; client does too), session resumption, renegotiation.
;;;;
;;;; DRIVEN, NOT RUN, as the client is: START arms it, INPUT takes one datagram, RETRANSMIT is what
;;;; a timer does, DTLS-SERVER-HANDSHAKE is those in a blocking loop.  The flights:
;;;;   <- ClientHello
;;;;   -> ServerHello, Certificate, ServerKeyExchange, CertificateRequest, ServerHelloDone
;;;;   <- Certificate, ClientKeyExchange, CertificateVerify, [CCS], Finished
;;;;   -> [CCS], Finished
;;;; A repeated ClientHello means our first flight was lost (resend it); a repeated client flight
;;;; after we finished means our Finished was lost (resend that) -- DTLS-SERVER-INPUT does both,
;;;; and keeps doing the second after the handshake, so a caller hands it any handshake record
;;;; that turns up among the application data.

(in-package #:seal)

(defun dtls-srtp-profile (s)
  "The DTLS-SRTP protection profile the server chose (7 or 1), or NIL."
  (dtls-hs-srtp s))

;;; ---- ClientHello ---------------------------------------------------------------

(defun %dtls-parse-client-hello (body)
  "Return a plist (:random :suites :exts) from a ClientHello BODY; EXTS is an alist
(type . data)."
  (let ((pos 2))                                         ; client_version
    (let ((random (subseq body pos (+ pos 32))))
      (incf pos 32)
      (incf pos (1+ (aref body pos)))                    ; session_id
      (incf pos (1+ (aref body pos)))                    ; cookie
      (let* ((slen (bytes-u16 body pos))
             (suites (loop for i from (+ pos 2) below (+ pos 2 slen) by 2
                           collect (bytes-u16 body i))))
        (incf pos (+ 2 slen))
        (incf pos (1+ (aref body pos)))                  ; compression methods
        (let ((exts '()))
          (when (<= (+ pos 2) (length body))
            (let ((end (+ pos 2 (bytes-u16 body pos))))
              (setf pos (+ pos 2))
              (loop while (<= (+ pos 4) (min end (length body)))
                    do (let ((type (bytes-u16 body pos)) (len (bytes-u16 body (+ pos 2))))
                         (push (cons type (subseq body (+ pos 4) (min (length body) (+ pos 4 len)))) exts)
                         (incf pos (+ 4 len))))))
          (list :random random :suites suites :exts (nreverse exts)))))))

(defun %dtls-u16-list (data &key (start 0) (len-bytes 2))
  "A list of u16s from a length-prefixed vector in DATA at START."
  (let* ((n (if (= len-bytes 2) (bytes-u16 data start) (aref data start)))
         (from (+ start len-bytes)))
    (loop for i from from below (min (length data) (+ from n)) by 2
          when (< (1+ i) (length data)) collect (bytes-u16 data i))))

(defun %dtls-server-hello-body (s suite exts)
  (let* ((out-exts
           (%dcat
            (if (assoc #xff01 exts) (dtls-ext #xff01 (%db 0)) (%db))
            (if (assoc +ext-ec-point-formats+ exts) (dtls-ext +ext-ec-point-formats+ (%db 1 0)) (%db))
            (if (dtls-hs-srtp s)
                (dtls-ext 14 (%dcat (%d16 2) (%d16 (dtls-hs-srtp s)) (%db 0)))
                (%db)))))
    (%dcat (%db +dtls-12-major+ +dtls-12-minor+)
           (dtls-server-random s)
           (%db 0)                                        ; session_id: none (no resumption)
           (%d16 suite)
           (%db 0)                                        ; compression: null
           (if (plusp (length out-exts)) (%dcat (%d16 (length out-exts)) out-exts) (%db)))))

(defun %dtls-ske-body (s)
  "ServerKeyExchange for ECDHE over X25519, signed (client_random || server_random || params)."
  (let* ((params (%dcat (%db 3) (%d16 #x001d) (%db 32) (dtls-eph-pub s)))
         (sig (funcall (dtls-sign-fn s)
                       (%dcat (dtls-client-random s) (dtls-server-random s) params))))
    (%dcat params (%d16 (dtls-sig-scheme-code s)) (%d16 (length sig)) sig)))

(defun %dtls-cert-request-body ()
  "CertificateRequest: ecdsa_sign(64) / rsa_sign(1); ECDSA-P256-SHA256 and RSA-PKCS1-SHA256; no
named authorities -- any certificate, trust being the SDP fingerprint."
  (%dcat (%db 2 64 1)
         (%d16 4) (%d16 +sig-ecdsa-secp256r1-sha256+) (%d16 +sig-rsa-pkcs1-sha256+)
         (%d16 0)))

(defun %dtls-server-flight-1 (s ch-mseq ch-body)
  "Answer the ClientHello (CH-MSEQ, CH-BODY): choose, build and send flight 2."
  (destructuring-bind (&key random suites exts) (%dtls-parse-client-hello ch-body)
    (let* ((want (if (= (dtls-sig-scheme-code s) +sig-rsa-pkcs1-sha256+) #xc02f #xc02b))
           (groups (let ((g (assoc +ext-supported-groups+ exts))) (and g (%dtls-u16-list (cdr g)))))
           (srtp (let ((e (assoc 14 exts))) (and e (%dtls-u16-list (cdr e))))))
      (unless (member want suites)
        (error 'tls-error :message (format nil "DTLS server: client offers no ~4,'0x suite" want)))
      (unless (member #x001d groups)
        (error 'tls-error :message "DTLS server: client does not offer X25519"))
      (setf (dtls-client-random s) random
            (dtls-cipher s) want
            (dtls-hs-srtp s) (cond ((member 7 srtp) 7) ((member 1 srtp) 1) (t nil))
            (dtls-hs-ch-body s) ch-body
            (dtls-msg-seq s) 0)
      (dtls-reset-transcript s)
      (dtls-add-transcript s (dtls-handshake +hs-client-hello+ ch-mseq ch-body))
      (let* ((msgs (list (dtls-handshake +hs-server-hello+ (dtls-next-msgseq s)
                                         (%dtls-server-hello-body s want exts))
                         (dtls-handshake +hs-certificate+ (dtls-next-msgseq s)
                                         (dtls-certificate-body (dtls-cert-der s)))
                         (dtls-handshake +hs-server-key-exchange+ (dtls-next-msgseq s)
                                         (%dtls-ske-body s))
                         (dtls-handshake +hs-certificate-request+ (dtls-next-msgseq s)
                                         (%dtls-cert-request-body))
                         (dtls-handshake +hs-server-hello-done+ (dtls-next-msgseq s) (%db)))))
        (dolist (m msgs) (dtls-add-transcript s m))
        (setf (dtls-hs-specs s) (mapcar (lambda (m) (list :plain m)) msgs)
              (dtls-hs-phase s) :client-flight
              (dtls-hs-tries s) 0
              (dtls-hs-to s) (dtls-hs-timeout s))
        (%dlog "[dtls-server] -> flight 2 (SH/Cert/SKE/CertReq/SHD) cipher=0x~4,'0x srtp=~a~%"
               want (dtls-hs-srtp s))
        (dtls-transmit-flight s (dtls-hs-specs s))))))

;;; ---- the client's second flight -------------------------------------------------

(defun %dtls-server-derive (s client-pub)
  "The client's X25519 share is in: the master secret and the key block (named for client and
server, which DTLS-ENCRYPT / -DECRYPT pick between by ROLE)."
  (setf (dtls-server-eph-pub s) client-pub)              ; the slot DTLS-DERIVE-KEYS reads
  (dtls-derive-keys s))

(defun %dtls-check-cert-verify (s body)
  "Verify the client's CertificateVerify BODY against its certificate over the transcript so far
(ClientHello .. ClientKeyExchange).  Signals TLS-ERROR on a bad signature."
  (let* ((code (bytes-u16 body 0))
         (len (bytes-u16 body 2))
         (sig (subseq body 4 (+ 4 len)))
         (cert (dtls-peer-cert s)))
    (unless (and cert (certificate-spki cert))
      (error 'tls-error :message "DTLS server: CertificateVerify without a usable certificate"))
    (multiple-value-bind (scheme hash salt) (tls-signature-scheme code)
      (unless (and scheme
                   (ignore-errors (verify-signature (certificate-spki cert) scheme hash salt
                                                    (dtls-transcript-bytes s) sig)))
        (error 'tls-error :message "DTLS server: client CertificateVerify did not verify")))))

(defun %dtls-server-finish (s)
  "The client's Finished checked: send ours (CCS + Finished) and be done."
  (let* ((fin (dtls-handshake +hs-finished+ (dtls-next-msgseq s)
                              (dtls-finished-data s "server finished"))))
    (setf (dtls-hs-specs s) (list (list :ccs) (list :enc fin))
          (dtls-done s) t
          (dtls-hs-phase s) :done)
    (%dlog "[dtls-server] -> CCS/Finished: handshake complete~%")
    (dtls-transmit-flight s (dtls-hs-specs s))))

(defun %dtls-server-record (s rec)
  "File one record of the client's second flight."
  (let ((type (dtls-record-type rec)) (epoch (dtls-record-epoch rec)))
    (cond
      ((and (= type +content-alert+) (>= (length rec) 15) (= epoch 0))
       (%dlog "[dtls-server]    !! ALERT level=~a description=~a~%" (aref rec 13) (aref rec 14)))
      ((and (= type +content-handshake+) (= epoch 0))
       (dolist (frag (dtls-hs-fragments rec))
         (let ((msg (dtls-reassemble s frag)))
           (when msg
             (destructuring-bind (mtype mseq body) msg
               (%dlog "[dtls-server]    hs msg type=~a seq=~a len=~a~%" mtype mseq (length body))
               (cond
                 ((= mtype +hs-client-hello+)        ; our flight went missing: say it again
                  (dtls-transmit-flight s (dtls-hs-specs s)))
                 ((= mtype +hs-certificate+)
                  (dtls-parse-certificate s body)
                  (let ((exp (dtls-expected-peer-fingerprint s)))
                    (when (and exp (not (string-equal exp (dtls-peer-fingerprint s))))
                      (warn "DTLS: peer certificate fingerprint ~a does not match SDP ~a"
                            (dtls-peer-fingerprint s) exp)))
                  (dtls-add-transcript s (dtls-handshake mtype mseq body)))
                 ((= mtype +hs-client-key-exchange+)
                  (unless (and (>= (length body) 33) (= (aref body 0) 32))
                    (error 'tls-error :message "DTLS server: ClientKeyExchange is not an X25519 share"))
                  (%dtls-server-derive s (subseq body 1 33))
                  (dtls-add-transcript s (dtls-handshake mtype mseq body)))
                 ((= mtype +hs-certificate-verify+)
                  (%dtls-check-cert-verify s body)
                  (dtls-add-transcript s (dtls-handshake mtype mseq body))
                  (setf (dtls-cert-requested s) :verified))))))))
      ((and (= type +content-handshake+) (= epoch 1) (dtls-master-secret s))
       (multiple-value-bind (ty pt) (dtls-decrypt s rec)
         (declare (ignore ty))
         (when (and pt (>= (length pt) 12) (= (aref pt 0) +hs-finished+))
           (let* ((len (bytes-u24 pt 1))
                  (got (subseq pt 12 (+ 12 len))))
             (unless (dtls-peer-cert s)
               (error 'tls-error :message "DTLS server: the client sent no certificate"))
             (unless (eq (dtls-cert-requested s) :verified)
               (error 'tls-error :message "DTLS server: Finished before CertificateVerify"))
             (unless (equalp got (dtls-finished-data s "client finished"))
               (error 'tls-error :message "DTLS server: client Finished mismatch"))
             (dtls-add-transcript s (dtls-handshake +hs-finished+ (bytes-u16 pt 4) got))
             (%dtls-server-finish s))))))))

;;; ---- the driven server -------------------------------------------------------------

(defun dtls-server-start (s &key (timeout 1.0) (max-timeout 8.0) (max-retries 30))
  "Arm S as a DTLS server waiting for a ClientHello: our ephemeral X25519 key and random.  Sends
nothing -- the client speaks first.  Returns the seconds until DTLS-SERVER-RETRANSMIT is due."
  (setf (dtls-role s) :server
        (dtls-eph-priv s) (secure-random-bytes 32)
        (dtls-eph-pub s) (x25519-public-key (dtls-eph-priv s))
        (dtls-server-random s) (secure-random-bytes 32)
        (dtls-hs-timeout s) timeout (dtls-hs-max-timeout s) max-timeout
        (dtls-hs-max-retries s) max-retries
        (dtls-hs-to s) timeout (dtls-hs-tries s) 0
        (dtls-hs-phase s) :client-hello)
  (dtls-hs-to s))

(defun dtls-server-timeout-seconds (s) (dtls-hs-to s))

(defun dtls-server-retransmit (s)
  "The timer fired with nothing received.  Waiting for the client's second flight, our first
went missing or theirs did: resend ours.  Waiting for a ClientHello there is nothing to resend.
Signals TLS-ERROR once MAX-RETRIES misses have passed."
  (incf (dtls-hs-tries s))
  (setf (dtls-hs-to s) (min (dtls-hs-max-timeout s) (* 2 (dtls-hs-to s))))
  (when (> (dtls-hs-tries s) (dtls-hs-max-retries s))
    (error 'tls-error :message (format nil "DTLS server: timed out (~(~a~))" (dtls-hs-phase s))))
  (when (eq (dtls-hs-phase s) :client-flight)
    (%dlog "[dtls-server] recv timeout (try ~a), resending flight 2~%" (dtls-hs-tries s))
    (dtls-transmit-flight s (dtls-hs-specs s)))
  (dtls-hs-to s))

(defun dtls-server-input (s dg)
  "Feed one inbound datagram.  Returns T once the handshake is complete (and keeps returning T).
After completion, a handshake record from the client -- its last flight again, because our
Finished was lost -- resends our Finished; application data is ignored here (DTLS-HANDLE-DATAGRAM
is its reader)."
  (setf (dtls-hs-to s) (dtls-hs-timeout s))
  (let ((recs (dtls-split-records dg)))
    (ecase (dtls-hs-phase s)
      (:client-hello
       (dolist (rec recs)
         (when (and (= (dtls-record-type rec) +content-handshake+) (= (dtls-record-epoch rec) 0))
           (dolist (frag (dtls-hs-fragments rec))
             (let ((msg (dtls-reassemble s frag)))
               (when (and msg (= (first msg) +hs-client-hello+) (eq (dtls-hs-phase s) :client-hello))
                 (%dlog "[dtls-server] <- ClientHello~%")
                 (%dtls-server-flight-1 s (second msg) (third msg))))))))
      (:client-flight
       (dolist (rec recs)
         (unless (dtls-done s) (%dtls-server-record s rec))))
      (:done
       (when (find +content-handshake+ recs :key #'dtls-record-type)
         (%dlog "[dtls-server] client flight again: resending our Finished~%")
         (dtls-transmit-flight s (dtls-hs-specs s))))))
  (dtls-done s))

(defun dtls-server-handshake (s recv-fn &key (timeout 1.0) (max-timeout 8.0) (max-retries 30))
  "Drive the DTLS 1.2 server handshake to completion on this thread.  RECV-FN is called with a
timeout (seconds) and returns the next datagram or NIL.  Returns S; signals TLS-ERROR."
  (dtls-server-start s :timeout timeout :max-timeout max-timeout :max-retries max-retries)
  (loop until (dtls-done s) do
    (let ((dg (funcall recv-fn (dtls-server-timeout-seconds s))))
      (if dg (dtls-server-input s dg) (dtls-server-retransmit s))))
  s)
