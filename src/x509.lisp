;;;; x509.lisp — minimal DER / X.509 certificate parsing.
;;;;
;;;; Enough to expose the fields a caller needs to make a trust decision:
;;;; subject, issuer, validity window, subjectAltName dNSNames, and the raw
;;;; SubjectPublicKeyInfo. This is parsing and exposure, NOT chain validation.

(in-package #:seal)

;;; ---- DER reader ------------------------------------------------------------

(defstruct der tag constructed content children start end)

(defun der-read (bytes pos)
  "Read one DER TLV at POS in BYTES. Returns (values node next-position)."
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
                           :start content-start :end content-end)))
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

;;; ---- certificate -----------------------------------------------------------

(defstruct (certificate (:conc-name certificate-))
  raw subject issuer not-before not-after subject-alt-names public-key-info)

(defun %extract-san (extensions-node)
  "Collect dNSName entries from a subjectAltName extension, if present."
  (let ((names nil))
    (dolist (ext (der-children extensions-node))
      (let* ((kids (der-children ext))
             (oid (der-oid-string (der-content (first kids)))))
        (when (string= oid "2.5.29.17")            ; subjectAltName
          ;; last child is an OCTET STRING wrapping GeneralNames
          (let* ((octet (car (last kids)))
                 (general-names (der-read (der-content octet) 0)))
            (dolist (gn (der-children general-names))
              ;; dNSName is [2] IMPLICIT IA5String -> tag 0x82
              (when (= (der-tag gn) #x82)
                (push (map 'string #'code-char (der-content gn)) names)))))))
    (nreverse names)))

(defun parse-certificate (bytes)
  "Parse a DER X.509 certificate into a CERTIFICATE struct."
  (let* ((cert (der-read bytes 0))
         (tbs (first (der-children cert)))
         (kids (der-children tbs))
         (idx 0))
    ;; optional [0] EXPLICIT version
    (when (= (der-tag (nth idx kids)) #xa0) (incf idx))
    (incf idx)                                   ; serialNumber
    (incf idx)                                   ; signature AlgorithmIdentifier
    (let ((issuer (nth idx kids)))    (incf idx)
      (let* ((validity (nth idx kids))  (dummy (incf idx))
             (subject (nth idx kids))   (d2 (incf idx))
             (spki (nth idx kids))      (d3 (incf idx))
             (validity-kids (der-children validity))
             (extensions
               (loop for n in (nthcdr idx kids)
                     when (= (der-tag n) #xa3)     ; [3] EXPLICIT extensions
                       return (first (der-children n)))))
        (declare (ignore dummy d2 d3))
        (make-certificate
         :raw bytes
         :issuer (der-name-string issuer)
         :subject (der-name-string subject)
         :not-before (der-string (first validity-kids))
         :not-after (der-string (second validity-kids))
         :public-key-info (subseq bytes (der-start spki) (der-end spki))
         :subject-alt-names (when extensions (%extract-san extensions)))))))

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
