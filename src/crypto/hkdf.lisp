;;;; hkdf.lisp — HKDF (RFC 5869) and the TLS 1.3 key-schedule helpers.

(in-package #:seal)

;;; HKDF is parameterized on the hash: :sha256 (32-byte) or :sha384 (48-byte).
;;; The public entry points default to SHA-256, matching the RFC 5869 vectors.

(defun hash-length (which)
  (ecase which (:sha256 32) (:sha384 48)))

(defun hmac-hash (which key message)
  (ecase which
    (:sha256 (hmac-sha256 key message))
    (:sha384 (hmac-sha384 key message))))

(defun digest-hash (which message)
  (ecase which
    (:sha256 (sha256 message))
    (:sha384 (sha384 message))))

(defun hkdf-extract (salt ikm &optional (which :sha256))
  "HKDF-Extract(salt, IKM) -> PRK."
  (let ((salt (if (and salt (plusp (length salt)))
                  salt
                  (make-array (hash-length which) :element-type '(unsigned-byte 8)
                              :initial-element 0))))
    (hmac-hash which salt ikm)))

(defun hkdf-expand (prk info length &optional (which :sha256))
  "HKDF-Expand(PRK, info, L) -> OKM of LENGTH bytes."
  (let* ((hash-len (hash-length which))
         (n (ceiling length hash-len))
         (okm (make-array length :element-type '(unsigned-byte 8)))
         (info (or info (make-array 0 :element-type '(unsigned-byte 8))))
         (prev (make-array 0 :element-type '(unsigned-byte 8))))
    (when (> n 255) (error "HKDF-Expand: requested length too long"))
    (dotimes (i n okm)
      (let ((input (concatenate '(vector (unsigned-byte 8))
                                prev info (vector (1+ i)))))
        (setf prev (hmac-hash which prk input))
        (let* ((offset (* i hash-len))
               (copy-len (min hash-len (- length offset))))
          (replace okm prev :start1 offset :end1 (+ offset copy-len) :end2 copy-len))))))

(defun hkdf (salt ikm info length &optional (which :sha256))
  "HKDF combined Extract-and-Expand."
  (hkdf-expand (hkdf-extract salt ikm which) info length which))

(defun tls13-hkdf-expand-label (secret label context length &optional (which :sha256))
  "TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1)."
  (let* ((full-label (concatenate 'string "tls13 " label))
         (label-len (length full-label))
         (context-len (if context (length context) 0))
         (info (make-array (+ 2 1 label-len 1 context-len)
                           :element-type '(unsigned-byte 8)))
         (pos 0))
    (setf (aref info pos) (logand (ash length -8) #xff)) (incf pos)
    (setf (aref info pos) (logand length #xff)) (incf pos)
    (setf (aref info pos) label-len) (incf pos)
    (dotimes (i label-len)
      (setf (aref info pos) (char-code (char full-label i))) (incf pos))
    (setf (aref info pos) context-len) (incf pos)
    (when context
      (dotimes (i context-len)
        (setf (aref info pos) (aref context i)) (incf pos)))
    (hkdf-expand secret info length which)))

(defun tls13-derive-secret (secret label transcript-hash &optional (which :sha256))
  "TLS 1.3 Derive-Secret(secret, label, transcript-hash)."
  (tls13-hkdf-expand-label secret label transcript-hash (hash-length which) which))
