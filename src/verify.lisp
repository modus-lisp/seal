;;;; verify.lisp — X.509 chain building, signature verification, trust store.
;;;;
;;;; This is the part that makes seal MITM-safe: it verifies that the leaf
;;;; certificate chains, by valid signatures, to a CA in a trust store, that
;;;; every certificate is within its validity window, and (via CertificateVerify
;;;; in tls13.lisp) that the peer holds the leaf's private key. Everything here
;;;; FAILS CLOSED — any gap raises a TLS-CERTIFICATE-ERROR rather than trusting.

(in-package #:seal)

;;; ---- base64 / PEM ----------------------------------------------------------

(defparameter *base64-alphabet*
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defparameter +base64-alphabet+
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun base64-encode (bytes)
  "Standard base64 (RFC 4648) with padding."
  (let* ((bytes (coerce bytes '(vector (unsigned-byte 8))))
         (len (length bytes))
         (out (make-string (* 4 (ceiling len 3)) :initial-element #\=))
         (o 0))
    (loop for i from 0 below len by 3
          for b0 = (aref bytes i)
          for b1 = (if (< (+ i 1) len) (aref bytes (+ i 1)) 0)
          for b2 = (if (< (+ i 2) len) (aref bytes (+ i 2)) 0)
          for triple = (logior (ash b0 16) (ash b1 8) b2)
          do (setf (char out o) (char +base64-alphabet+ (ldb (byte 6 18) triple)))
             (setf (char out (+ o 1)) (char +base64-alphabet+ (ldb (byte 6 12) triple)))
             (when (< (+ i 1) len)
               (setf (char out (+ o 2)) (char +base64-alphabet+ (ldb (byte 6 6) triple))))
             (when (< (+ i 2) len)
               (setf (char out (+ o 3)) (char +base64-alphabet+ (ldb (byte 6 0) triple))))
             (incf o 4))
    out))

(defun base64-decode (string)
  "Decode a standard-alphabet base64 STRING (ignoring whitespace) to bytes."
  (let ((rev (make-array 128 :initial-element -1))
        (bits 0) (nbits 0)
        (out (make-array 0 :element-type '(unsigned-byte 8)
                           :adjustable t :fill-pointer 0)))
    (dotimes (i 64) (setf (aref rev (char-code (char *base64-alphabet* i))) i))
    (loop for ch across string
          for code = (char-code ch)
          for v = (and (< code 128) (aref rev code))
          when (and v (>= v 0)) do
            ;; Only the low (nbits + 6 <= 14) bits are ever read: keep just
            ;; those.  Unmasked, BITS held the whole decoded stream -- a
            ;; 12000-bit bignum shifted once per character, quadratic, and
            ;; 11 s for the system CA bundle where bignums are slow.
            (setf bits (logand (logior (ash bits 6) v) #xffff))
            (incf nbits 6)
            (when (>= nbits 8)
              (decf nbits 8)
              (vector-push-extend (logand (ash bits (- nbits)) #xff) out)))
    (coerce out '(vector (unsigned-byte 8)))))

(defun pem-certificates (text)
  "Return a list of DER byte vectors for every CERTIFICATE block in TEXT."
  (let ((certs nil) (pos 0)
        (begin "-----BEGIN CERTIFICATE-----")
        (end "-----END CERTIFICATE-----"))
    (loop
      (let ((b (search begin text :start2 pos)))
        (unless b (return))
        (let* ((body-start (+ b (length begin)))
               (e (search end text :start2 body-start)))
          (unless e (return))
          (push (base64-decode (subseq text body-start e)) certs)
          (setf pos (+ e (length end))))))
    (nreverse certs)))

;;; ---- trust store -----------------------------------------------------------

(defstruct trust-store
  (certificates nil)
  (by-subject (make-hash-table :test 'equal)))

(defparameter *system-ca-bundles*
  '("/etc/ssl/certs/ca-certificates.crt"       ; Debian/Ubuntu/Alpine
    "/etc/pki/tls/certs/ca-bundle.crt"          ; Fedora/RHEL
    "/etc/ssl/cert.pem"                         ; OpenBSD/macOS (LibreSSL)
    "/usr/local/etc/openssl@3/cert.pem"         ; Homebrew (Apple Silicon)
    "/usr/local/etc/openssl/cert.pem"           ; Homebrew (Intel)
    "/opt/homebrew/etc/openssl@3/cert.pem"))

(defun read-file-string (path)
  (with-open-file (in path :direction :input :element-type 'character
                           :if-does-not-exist nil)
    (when in
      (let ((s (make-string (file-length in))))
        (subseq s 0 (read-sequence s in))))))

(defun trust-store-add (store der)
  "Parse a DER certificate and add it to STORE, indexed by subject DN."
  (let ((cert (ignore-errors (parse-certificate der))))
    (when cert
      (push cert (trust-store-certificates store))
      (push cert (gethash (certificate-subject cert) (trust-store-by-subject store))))))

(defun make-trust-store-from-pem (text)
  (let ((store (make-trust-store)))
    (dolist (der (pem-certificates text) store)
      (trust-store-add store der))))

(defvar *system-trust-store-cache* nil
  "(path write-date . store) of the last system bundle parsed.  Parsing ~140
   certificates on every connection is waste on any implementation and a
   visible stall on a slow one; the bundle changes on package upgrades, so the
   cache is keyed on the file's write date.")
(defvar *system-trust-store-local* nil
  "This computation's own (path write-date . store), used when the shared
   cache above could not be filled from here: on modus a thread or actor may
   read shared memory but not store its own objects into it, so a worker that
   finds the shared cache empty parses into this one instead.")
#+modus ; per computation on modus: threads and actors share no state
(let ((reg (find-symbol "REGISTER-PER-COMPUTATION-SPECIAL" "COMMON-LISP-USER")))
  (when (and reg (fboundp reg)) (funcall reg '*system-trust-store-local*)))

(defun %cached-store (cached path date)
  (and date cached (equal (first cached) path) (eql (second cached) date) (cddr cached)))

(defun load-system-trust-store ()
  "Load the first available system CA bundle (cached while the file is
   unchanged). Signals if none is found.  The parsed store is immutable, so it
   is shared when the implementation lets this thread publish it (on modus,
   the main thread) and kept per computation otherwise."
  (dolist (path *system-ca-bundles*)
    (let ((date (ignore-errors (file-write-date path))))
      (let ((hit (or (%cached-store *system-trust-store-cache* path date)
                     (%cached-store *system-trust-store-local* path date))))
        (when hit (return-from load-system-trust-store hit)))
      (let ((text (read-file-string path)))
        (when (and text (search "BEGIN CERTIFICATE" text))
          (let ((store (make-trust-store-from-pem text)))
            (when date
              (let ((entry (list* path date store)))
                (unless (ignore-errors (setf *system-trust-store-cache* entry) t)
                  (setf *system-trust-store-local* entry))))
            (return-from load-system-trust-store store))))))
  (error 'tls-certificate-error
         :message "no system CA bundle found; supply :trust-store"))

(defun resolve-trust-store (spec)
  "SPEC may be a TRUST-STORE, :system (default), or a pathname/string PEM file."
  (cond
    ((trust-store-p spec) spec)
    ((or (null spec) (eq spec :system)) (load-system-trust-store))
    ((or (stringp spec) (pathnamep spec))
     (let ((text (read-file-string spec)))
       (unless text (error 'tls-certificate-error
                           :message (format nil "cannot read CA file ~a" spec)))
       (make-trust-store-from-pem text)))
    (t (error 'tls-certificate-error :message "invalid :trust-store"))))

;;; ---- signature verification ------------------------------------------------

(defun parse-ecdsa-signature (bytes)
  "Decode a DER SEQUENCE { r INTEGER, s INTEGER } into (values r s)."
  (let* ((seq (der-read bytes 0))
         (kids (der-children seq)))
    (values (der-integer (first kids)) (der-integer (second kids)))))

(defun verify-signature (spki scheme hash salt message signature)
  "Verify SIGNATURE over MESSAGE using public key SPKI under SCHEME/HASH.
Returns T / NIL. Any unsupported combination fails closed (NIL)."
  (handler-case
      (case scheme
        (:rsa-pkcs1
         (and (eq (spki-type spki) :rsa)
              (rsa-pkcs1-verify (spki-rsa-key spki) hash message signature)))
        (:rsa-pss
         (and (eq (spki-type spki) :rsa)
              (rsa-pss-verify (spki-rsa-key spki) hash message signature salt)))
        (:ecdsa
         (and (eq (spki-type spki) :ec) (spki-ec-curve spki) (spki-ec-point spki)
              (multiple-value-bind (r s) (parse-ecdsa-signature signature)
                (ecdsa-verify (spki-ec-curve spki) (spki-ec-point spki)
                              (digest-hash hash message) r s))))
        (:ed25519
         (and (eq (spki-type spki) :ed25519)
              (ed25519-verify (spki-ed-key spki) signature message)))
        (t nil))
    (error () nil)))

(defvar *verified-signatures* nil
  "SHA-256 digests of (child TBS, child signature, parent SPKI) triples whose
   signature has verified in this computation.  A certificate signature check
   is a pure function of those bytes, so a repeat connection to the same host
   need not redo the public-key arithmetic -- dates, hostname and CA
   constraints are still checked on every connection.  Bounded at 256.")
#+modus ; per computation on modus: threads and actors share no state
(let ((reg (find-symbol "REGISTER-PER-COMPUTATION-SPECIAL" "COMMON-LISP-USER")))
  (when (and reg (fboundp reg)) (funcall reg '*verified-signatures*)))

(defun %signature-key (child parent)
  (sha256 (concatenate '(vector (unsigned-byte 8))
                       (certificate-tbs-der child)
                       (certificate-signature child)
                       (certificate-spki-bytes parent))))

(defun certificate-spki-bytes (cert)
  (spki-raw (certificate-spki cert)))

(defun verify-cert-signature (child parent)
  "True if CHILD's signature verifies under PARENT's public key."
  (let ((key (%signature-key child parent)))
    (or (and (member key *verified-signatures* :test #'equalp) t)
        (when (verify-signature (certificate-spki parent)
                                (certificate-sig-scheme child)
                                (certificate-sig-hash child)
                                (certificate-sig-salt child)
                                (certificate-tbs-der child)
                                (certificate-signature child))
          (setf *verified-signatures*
                (cons key (if (> (length *verified-signatures*) 255)
                              (subseq *verified-signatures* 0 255)
                              *verified-signatures*)))
          t))))

;;; ---- chain building & validation -------------------------------------------

(defun build-ordered-chain (certs)
  "Order CERTS leaf-first by matching each issuer DN to the next subject DN."
  (let ((chain (list (first certs)))
        (pool (rest certs)))
    (loop
      (let* ((current (car (last chain)))
             (issuer-dn (certificate-issuer current)))
        (when (string= issuer-dn (certificate-subject current)) (return)) ; self-signed
        (let ((parent (find issuer-dn pool :key #'certificate-subject :test #'string=)))
          (if parent
              (setf chain (nconc chain (list parent))
                    pool (remove parent pool))
              (return)))))
    chain))

(defun check-validity (cert now)
  (let ((nb (certificate-not-before-univ cert))
        (na (certificate-not-after-univ cert)))
    (when (or (null nb) (null na))
      (error 'tls-certificate-error
             :message (format nil "unparseable validity dates in ~a"
                              (certificate-subject cert))))
    (when (< now nb)
      (error 'tls-certificate-expired-error
             :message (format nil "certificate not yet valid: ~a"
                              (certificate-subject cert))))
    (when (> now na)
      (error 'tls-certificate-expired-error
             :message (format nil "certificate expired: ~a"
                              (certificate-subject cert))))))

(defun find-trust-anchor (top store)
  "Return a trusted root that authenticates TOP, or NIL. TOP is trusted if it is
itself present in STORE (server sent the root), or if some root whose subject is
TOP's issuer verifies TOP's signature."
  ;; 1. TOP itself is a trusted root (matched by identical SPKI + subject).
  (dolist (r (gethash (certificate-subject top) (trust-store-by-subject store)))
    (when (equalp (spki-raw (certificate-spki r)) (spki-raw (certificate-spki top)))
      (return-from find-trust-anchor r)))
  ;; 2. A trusted root signed TOP.
  (dolist (r (gethash (certificate-issuer top) (trust-store-by-subject store)))
    (when (verify-cert-signature top r)
      (return-from find-trust-anchor r)))
  nil)

(defun validate-chain (certs store host &key (now (get-universal-time)))
  "Full path validation. Signals a TLS-CERTIFICATE-ERROR subclass on any failure;
returns the ordered, verified chain on success."
  (unless certs
    (error 'tls-certificate-error :message "peer presented no certificates"))
  (let ((leaf (first certs)))
    ;; Hostname must match the leaf.
    (when host
      (unless (certificate-matches-host-p leaf host)
        (error 'tls-certificate-hostname-error
               :message (format nil "no certificate name matches ~a" host))))
    (let ((chain (build-ordered-chain certs)))
      ;; Every certificate must be within its validity window.
      (dolist (c chain) (check-validity c now))
      ;; Each link's signature must verify under its issuer's key, and every
      ;; issuer used as a CA must actually be a CA.
      (loop for (child parent) on chain while parent do
        (unless (certificate-ca-p parent)
          (error 'tls-certificate-error
                 :message (format nil "issuer is not a CA: ~a"
                                  (certificate-subject parent))))
        (unless (verify-cert-signature child parent)
          (error 'tls-certificate-bad-signature-error
                 :message (format nil "signature on ~a does not verify under ~a"
                                  (certificate-subject child)
                                  (certificate-subject parent)))))
      ;; Anchor the top of the chain to a trusted root.
      (let* ((top (car (last chain)))
             (anchor (find-trust-anchor top store)))
        (unless anchor
          (error 'tls-certificate-untrusted-error
                 :message (format nil "chain does not terminate at a trusted CA (top issuer: ~a)"
                                  (certificate-issuer top))))
        (unless (certificate-ca-p anchor)
          (error 'tls-certificate-untrusted-error
                 :message "trust anchor is not a CA"))
        (check-validity anchor now))
      chain)))
