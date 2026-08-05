;;;; tls12.lisp — the TLS 1.2 ECDHE path, over every curve we advertise.
;;;;
;;;; The live suite only ever reaches TLS 1.3, because every host worth naming
;;;; speaks it.  TLS 1.2 is nonetheless the path that carries a large part of the
;;;; long tail — media CDNs in particular — and it is a genuinely different key
;;;; exchange: the server picks the group out of the supported_groups we
;;;; advertise, tells us in ServerKeyExchange, and we answer on that curve.  A
;;;; server that picks secp256r1 is ordinary, not exotic.
;;;;
;;;; So this runs a real handshake against a real peer for each curve, using
;;;; OpenSSL's s_server pinned to TLS 1.2 and to one group at a time.  It is
;;;; deterministic and needs no network beyond loopback.  The key pair is minted
;;;; fresh each run and thrown away — nothing to vendor and nothing to leak.
;;;;
;;;; A handshake that completes is a strong assertion by itself: the premaster is
;;;; the X coordinate ONLY, left-padded to the field length (RFC 4492 §5.10), and
;;;; getting that wrong does not fail loudly at the point of the mistake — it
;;;; fails as a Finished mismatch, having looked correct all the way there.
;;;; Reading back a response proves the record keys both sides derived agree.

(in-package #:seal)

(defparameter *tls12-curves*
  '(("P-256"  #x0017 "the one CDNs actually pick")
    ("P-384"  #x0018 "the other NIST curve we advertise")
    ("X25519" #x001d "the pre-existing path — this is the regression half"))
  "OpenSSL group name, its named_curve id, and why it is in the list.")

(defun openssl-available-p ()
  (ignore-errors
   (zerop (nth-value 2 (uiop:run-program '("openssl" "version")
                                         :ignore-error-status t :output nil :error-output nil)))))

(defun tls12-mint-test-key (dir)
  "A throwaway self-signed P-256 certificate for the loopback server.
Returns (values cert-path key-path)."
  (let ((cert (merge-pathnames "cert.pem" dir))
        (key (merge-pathnames "key.pem" dir)))
    (uiop:run-program (list "openssl" "req" "-x509" "-newkey" "ec"
                            "-pkeyopt" "ec_paramgen_curve:prime256v1"
                            "-keyout" (namestring key) "-out" (namestring cert)
                            "-days" "1" "-nodes" "-subj" "/CN=localhost")
                      :output nil :error-output nil)
    (values cert key)))

(defun tls12-serve (cert key group port)
  "Start an s_server pinned to TLS 1.2 and to GROUP.  Returns the process handle.
-naccept is more than one because the readiness probe below spends an accept:
pinned to exactly one, the probe would be the only client the server ever had."
  (uiop:launch-program (list "openssl" "s_server" "-tls1_2" "-groups" group
                             "-cert" (namestring cert) "-key" (namestring key)
                             "-accept" (princ-to-string port) "-www" "-naccept" "4")
                       :output nil :error-output nil))

(defun tls12-try-curve (cert key group port)
  "Handshake with a server pinned to GROUP and fetch a page.  Returns
(values ok-p detail)."
  (let ((server (tls12-serve cert key group port)))
    (unwind-protect
         (progn
           (loop repeat 50                        ; wait for the listener
                 until (ignore-errors (let ((s (make-socket-transport "127.0.0.1" port
                                                                      :timeout 1)))
                                        (transport-close s) t))
                 do (sleep 0.1))
           (handler-case
               ;; :verify NIL — the certificate is self-signed and untrusted by
               ;; construction; what is under test here is the key exchange, and
               ;; the chain validator has its own suite (negatives.lisp).
               (let ((conn (connect "127.0.0.1" port :verify nil :alpn nil)))
                 (unwind-protect
                      (progn
                        (tls-send conn (format nil "GET / HTTP/1.0~c~c~c~c"
                                               #\return #\newline #\return #\newline))
                        (let* ((resp (tls-recv conn))
                               (text (and resp (map 'string #'code-char resp))))
                          (values (and (= (tls-version conn) +version-12+)
                                       text (search "200 ok" text :test #'char-equal)
                                       t)
                                  (format nil "~a  ~a"
                                          (tls-connection-cipher conn)
                                          (if text
                                              (subseq text 0 (min 12 (length text)))
                                              "no response")))))
                   (ignore-errors (tls-close conn))))
             (error (e) (values nil (format nil "~a: ~a" (type-of e) e)))))
      (ignore-errors (uiop:terminate-process server :urgent t))
      (ignore-errors (uiop:wait-process server)))))

(defun run-tls12-offline ()
  "The checks that need no peer: the curve table, and the invalid-curve refusal.
Returns the number of failures."
  (let ((failures 0))
    (flet ((chk (name good)
             (if good (format t "  PASS ~a~%" name)
                 (progn (incf failures) (format t "  FAIL ~a~%" name)))))
      (chk "named_curve 0x001d is x25519" (eq (tls12-named-curve #x001d) :x25519))
      (chk "named_curve 0x0017 is P-256" (eq (tls12-named-curve #x0017) *p256*))
      (chk "named_curve 0x0018 is P-384" (eq (tls12-named-curve #x0018) *p384*))
      (chk "an unadvertised curve is refused, not guessed at"
           (null (tls12-named-curve #x0019)))
      ;; The invalid-curve attack: a "public key" that is not a point on the
      ;; curve puts the scalar multiplication in a different, small group, and
      ;; the resulting premaster leaks our private scalar.  Multiplying first and
      ;; asking questions later is the whole vulnerability, so this must be
      ;; refused before any arithmetic happens.
      (chk "a point that is not on the curve is refused"
           (let* ((valid (multiple-value-bind (d q) (ec-generate-key *p256*)
                           (declare (ignore d))
                           (ec-encode-point *p256* q)))
                  (bogus (copy-seq valid)))
             ;; Corrupt Y.  X stays a plausible field element, so nothing but the
             ;; curve equation can tell this apart from a real point.
             (setf (aref bogus (1- (length bogus)))
                   (logxor 1 (aref bogus (1- (length bogus)))))
             (and (nth-value 0 (ignore-errors (tls12-ecdhe-client-share *p256* valid)))
                  (typep (nth-value 1 (ignore-errors
                                       (tls12-ecdhe-client-share *p256* bogus)))
                         'tls-error)))))
    failures))

(defun run-tls12 (&key (port 14431))
  "Full TLS 1.2 check: offline unit checks, then a real handshake per curve.
Returns the number of failures."
  (format t "~%== TLS 1.2 ECDHE (the server picks the curve) ==~%")
  (let ((failures (run-tls12-offline)))
    (cond
      ((not (openssl-available-p))
       ;; Say so rather than passing quietly: a skipped interop check that looks
       ;; like a passing one is how an untested path gets shipped.
       (format t "  SKIP live curves — no openssl binary to serve against~%"))
      (t
       (let ((dir (merge-pathnames (format nil "seal-tls12-~d/" (sb-unix:unix-getpid))
                                   (uiop:temporary-directory))))
         (ensure-directories-exist dir)
         (unwind-protect
              (multiple-value-bind (cert key) (tls12-mint-test-key dir)
                (loop for (group id why) in *tls12-curves*
                      for p from port
                      do (multiple-value-bind (ok detail) (tls12-try-curve cert key group p)
                           (if ok
                               (format t "  PASS ~7a (0x~4,'0x) ~a — ~a~%" group id detail why)
                               (progn (incf failures)
                                      (format t "  FAIL ~7a (0x~4,'0x) ~a~%" group id detail))))))
           (ignore-errors (uiop:delete-directory-tree dir :validate t))))))
    (format t "==== TLS 1.2: ~d failed ====~%" failures)
    failures))
