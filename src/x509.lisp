;;;; x509.lisp — minimal DER / X.509 certificate parsing.
;;;;
;;;; Enough to expose the fields a caller needs to make a trust decision:
;;;; subject, issuer, validity window, subjectAltName dNSNames, and the raw
;;;; SubjectPublicKeyInfo. This is parsing and exposure, NOT chain validation.

(in-package #:seal)

;;; ---- DER reader ------------------------------------------------------------

(defstruct der tag constructed content children hstart start end)

(defun der-read (bytes pos)
  "Read one DER TLV at POS in BYTES. Returns (values node next-position).
HSTART records the tag byte position so callers can recover the full TLV bytes."
  (let* ((tag-byte (aref bytes pos))
         (constructed (logbitp 5 tag-byte))
         (p (1+ pos))
         (len-byte (aref bytes p))
         (len 0))
    (incf p)
    (if (< len-byte #x80)
        (setf len len-byte)
        (dotimes (i (logand len-byte #x7f))
          (setf len (logior (ash len 8) (aref bytes p)))
          (incf p)))
    (let* ((content-start p)
           (content-end (+ p len))
           (node (make-der :tag tag-byte :constructed constructed
                           :hstart pos :start content-start :end content-end)))
      (if constructed
          (let ((children nil) (cp content-start))
            (loop while (< cp content-end) do
              (multiple-value-bind (child next) (der-read bytes cp)
                (push child children)
                (setf cp next)))
            (setf (der-children node) (nreverse children)))
          (setf (der-content node) (subseq bytes content-start content-end)))
      (values node content-end))))

;;; ---- helpers ---------------------------------------------------------------

(defun der-oid-string (content)
  "Decode OID content bytes to a dotted-decimal string."
  (when (plusp (length content))
    (let ((parts (list (mod (aref content 0) 40) (floor (aref content 0) 40)))
          (val 0))
      (loop for i from 1 below (length content)
            for b = (aref content i) do
              (setf val (logior (ash val 7) (logand b #x7f)))
              (unless (logbitp 7 b)
                (push val parts)
                (setf val 0)))
      (format nil "~{~d~^.~}" (nreverse parts)))))

(defun der-string (node)
  "Decode a printable/UTF-8/IA5 string node to a Lisp string."
  (map 'string #'code-char (der-content node)))

(defparameter *dn-attr-names*
  '(("2.5.4.3" . "CN") ("2.5.4.6" . "C") ("2.5.4.7" . "L") ("2.5.4.8" . "ST")
    ("2.5.4.10" . "O") ("2.5.4.11" . "OU")))

(defun der-name-string (name-node)
  "Render an X.509 Name (SEQUENCE OF RDN) as e.g. \"CN=example.com,O=Foo\"."
  (let ((attrs nil))
    (dolist (rdn (der-children name-node))            ; each RDN is a SET
      (dolist (atv (der-children rdn))                ; each ATV is a SEQUENCE
        (let* ((oid (der-oid-string (der-content (first (der-children atv)))))
               (val (der-string (second (der-children atv))))
               (label (or (cdr (assoc oid *dn-attr-names* :test #'string=)) oid)))
          (push (format nil "~a=~a" label val) attrs))))
    (format nil "~{~a~^,~}" (nreverse attrs))))

(defun der-integer (node)
  "Decode a DER INTEGER node as a nonnegative integer (big-endian, unsigned)."
  (os2ip (der-content node)))

(defun der-bitstring-bytes (node)
  "Return the payload octets of a BIT STRING node (dropping the unused-bits byte)."
  (let ((c (der-content node)))
    (subseq c 1)))

;;; ---- public key material ---------------------------------------------------

(defstruct (spki (:conc-name spki-))
  type          ; :rsa | :ec | :ed25519 | :unknown
  rsa-key       ; RSA-PUBLIC-KEY for :rsa
  ec-curve      ; EC-CURVE for :ec
  ec-point      ; (cons x y) for :ec
  ed-key        ; 32-byte vector for :ed25519
  raw)          ; raw SPKI DER (for identity comparison in the trust store)

(defparameter +oid-rsa-encryption+ "1.2.840.113549.1.1.1")
(defparameter +oid-ec-public-key+ "1.2.840.10045.2.1")
(defparameter +oid-ed25519+ "1.3.101.112")
(defparameter +oid-p256+ "1.2.840.10045.3.1.7")
(defparameter +oid-p384+ "1.3.132.0.34")

(defun parse-spki (spki-node raw)
  "Parse a SubjectPublicKeyInfo node into an SPKI struct."
  (let* ((kids (der-children spki-node))
         (alg (first kids))
         (alg-kids (der-children alg))
         (alg-oid (der-oid-string (der-content (first alg-kids))))
         (bitstr (second kids))
         (key-bytes (der-bitstring-bytes bitstr)))
    (cond
      ((string= alg-oid +oid-rsa-encryption+)
       (let* ((seq (der-read key-bytes 0))
              (kk (der-children seq)))
         (make-spki :type :rsa :raw raw
                    :rsa-key (make-rsa-public-key
                              :n (der-integer (first kk))
                              :e (der-integer (second kk))))))
      ((string= alg-oid +oid-ec-public-key+)
       (let* ((curve-oid (der-oid-string (der-content (second alg-kids))))
              (curve (cond ((string= curve-oid +oid-p256+) *p256*)
                           ((string= curve-oid +oid-p384+) *p384*)
                           (t nil))))
         (make-spki :type :ec :raw raw :ec-curve curve
                    :ec-point (and curve (ec-decode-point curve key-bytes)))))
      ((string= alg-oid +oid-ed25519+)
       (make-spki :type :ed25519 :raw raw :ed-key key-bytes))
      (t (make-spki :type :unknown :raw raw)))))

;;; ---- signature algorithm OIDs ----------------------------------------------

(defun sig-alg-scheme (sigalg-node)
  "Map a signatureAlgorithm AlgorithmIdentifier to (values scheme hash salt-len).
SCHEME is :rsa-pkcs1, :rsa-pss, :ecdsa, :ed25519 or :unknown."
  (let* ((kids (der-children sigalg-node))
         (oid (der-oid-string (der-content (first kids)))))
    (cond
      ((string= oid "1.2.840.113549.1.1.11") (values :rsa-pkcs1 :sha256 nil))
      ((string= oid "1.2.840.113549.1.1.12") (values :rsa-pkcs1 :sha384 nil))
      ((string= oid "1.2.840.113549.1.1.13") (values :rsa-pkcs1 :sha512 nil))
      ((string= oid "1.2.840.113549.1.1.10") (parse-pss-params (second kids)))
      ((string= oid "1.2.840.10045.4.3.2") (values :ecdsa :sha256 nil))
      ((string= oid "1.2.840.10045.4.3.3") (values :ecdsa :sha384 nil))
      ((string= oid "1.2.840.10045.4.3.4") (values :ecdsa :sha512 nil))
      ((string= oid +oid-ed25519+) (values :ed25519 nil nil))
      (t (values :unknown nil nil)))))

(defun parse-pss-params (params-node)
  "Decode RSASSA-PSS parameters -> (values :rsa-pss hash salt-len). Defaults per
RFC 4055 (SHA-1, salt 20) when a field is absent, but modern certs are explicit."
  (let ((hash :sha1) (salt 20))
    (when (and params-node (der-constructed params-node))
      (dolist (field (der-children params-node))
        (case (der-tag field)
          (#xa0                                   ; [0] hashAlgorithm
           (let ((h-oid (der-oid-string
                         (der-content (first (der-children (first (der-children field))))))))
             (setf hash (cond ((string= h-oid "2.16.840.1.101.3.4.2.1") :sha256)
                              ((string= h-oid "2.16.840.1.101.3.4.2.2") :sha384)
                              ((string= h-oid "2.16.840.1.101.3.4.2.3") :sha512)
                              (t :sha1)))))
          (#xa2                                   ; [2] saltLength
           (setf salt (der-integer (first (der-children field))))))))
    (values :rsa-pss hash salt)))

;;; ---- certificate -----------------------------------------------------------

(defstruct (certificate (:conc-name certificate-))
  raw subject issuer not-before not-after subject-alt-names public-key-info
  tbs-der signature sig-scheme sig-hash sig-salt spki
  (ca-p nil) (path-len nil) key-usage
  not-before-univ not-after-univ)

(defun der-time->universal (node)
  "Parse a UTCTime or GeneralizedTime node to a Lisp universal time (UTC)."
  (let* ((s (der-string node))
         (utc-p (= (der-tag node) #x17)))          ; 0x17 UTCTime, 0x18 GeneralizedTime
    (multiple-value-bind (year rest)
        (if utc-p
            (let ((yy (parse-integer s :start 0 :end 2)))
              (values (if (>= yy 50) (+ 1900 yy) (+ 2000 yy)) 2))
            (values (parse-integer s :start 0 :end 4) 4))
      (flet ((n (i) (parse-integer s :start (+ rest i) :end (+ rest i 2))))
        (encode-universal-time (n 8) (n 6) (n 4)  ; ss mm hh
                               (n 2) (n 0) year 0)))))  ; DD MM yyyy, GMT

(defun %parse-extensions (cert extensions-node)
  "Fill basicConstraints, keyUsage and SANs on CERT from the extensions node."
  (dolist (ext (der-children extensions-node))
    (let* ((kids (der-children ext))
           (oid (der-oid-string (der-content (first kids))))
           (octet (car (last kids))))
      (cond
        ((string= oid "2.5.29.19")                 ; basicConstraints
         (let ((seq (der-read (der-content octet) 0)))
           (when (der-constructed seq)
             (dolist (f (der-children seq))
               (cond
                 ((= (der-tag f) #x01)              ; cA BOOLEAN
                  (setf (certificate-ca-p cert) (plusp (aref (der-content f) 0))))
                 ((= (der-tag f) #x02)              ; pathLenConstraint INTEGER
                  (setf (certificate-path-len cert) (der-integer f))))))))
        ((string= oid "2.5.29.15")                 ; keyUsage
         (setf (certificate-key-usage cert) (der-bitstring-bytes
                                             (der-read (der-content octet) 0))))
        ((string= oid "2.5.29.17")                 ; subjectAltName
         (setf (certificate-subject-alt-names cert)
               (%extract-san-octet octet)))))))

(defun %extract-san-octet (octet-node)
  (let ((general-names (der-read (der-content octet-node) 0)) (names nil))
    (dolist (gn (der-children general-names))
      (when (= (der-tag gn) #x82)                   ; dNSName [2]
        (push (map 'string #'code-char (der-content gn)) names)))
    (nreverse names)))

(defun parse-certificate (bytes)
  "Parse a DER X.509 certificate into a CERTIFICATE struct, including the fields
needed for chain and signature verification."
  (let* ((cert-node (der-read bytes 0))
         (cert-kids (der-children cert-node))
         (tbs (first cert-kids))
         (sigalg-node (second cert-kids))
         (sigval-node (third cert-kids))
         (kids (der-children tbs))
         (idx 0))
    (when (= (der-tag (nth idx kids)) #xa0) (incf idx))  ; optional [0] version
    (incf idx)                                   ; serialNumber
    (incf idx)                                   ; signature AlgorithmIdentifier
    (let ((issuer (nth idx kids)))    (incf idx)
      (let* ((validity (nth idx kids))  (d1 (incf idx))
             (subject (nth idx kids))   (d2 (incf idx))
             (spki-node (nth idx kids)) (d3 (incf idx))
             (validity-kids (der-children validity))
             (extensions
               (loop for n in (nthcdr idx kids)
                     when (= (der-tag n) #xa3)     ; [3] EXPLICIT extensions
                       return (first (der-children n))))
             (cert (make-certificate
                    :raw bytes
                    :issuer (der-name-string issuer)
                    :subject (der-name-string subject)
                    :not-before (der-string (first validity-kids))
                    :not-after (der-string (second validity-kids))
                    :not-before-univ (ignore-errors (der-time->universal (first validity-kids)))
                    :not-after-univ (ignore-errors (der-time->universal (second validity-kids)))
                    :public-key-info (subseq bytes (der-start spki-node) (der-end spki-node))
                    :tbs-der (subseq bytes (der-hstart tbs) (der-end tbs))
                    :signature (der-bitstring-bytes sigval-node)
                    :spki (parse-spki spki-node
                                      (subseq bytes (der-hstart spki-node) (der-end spki-node))))))
        (declare (ignore d1 d2 d3))
        (multiple-value-bind (scheme hash salt) (sig-alg-scheme sigalg-node)
          (setf (certificate-sig-scheme cert) scheme
                (certificate-sig-hash cert) hash
                (certificate-sig-salt cert) salt))
        (when extensions (%parse-extensions cert extensions))
        cert))))

;;; ---- hostname matching -----------------------------------------------------

(defun %host-matches-pattern-p (host pattern)
  "Match HOST against a certificate name PATTERN, honoring a single leading
wildcard label (RFC 6125)."
  (let ((host (string-downcase host))
        (pattern (string-downcase pattern)))
    (cond
      ((string= host pattern) t)
      ((and (> (length pattern) 2)
            (char= (char pattern 0) #\*) (char= (char pattern 1) #\.))
       (let ((suffix (subseq pattern 1))          ; ".example.com"
             (dot (position #\. host)))
         (and dot
              (string= (subseq host dot) suffix)
              ;; wildcard covers exactly one left-most label
              (not (find #\. (subseq host 0 dot))))))
      (t nil))))

(defun certificate-matches-host-p (certificate host)
  "True if CERTIFICATE presents a name matching HOST (SAN dNSNames, else CN)."
  (let ((sans (certificate-subject-alt-names certificate)))
    (if sans
        (some (lambda (p) (%host-matches-pattern-p host p)) sans)
        ;; fall back to subject CN
        (let* ((subj (certificate-subject certificate))
               (cn-pos (search "CN=" subj)))
          (when cn-pos
            (let* ((start (+ cn-pos 3))
                   (end (or (position #\, subj :start start) (length subj))))
              (%host-matches-pattern-p host (subseq subj start end))))))))
