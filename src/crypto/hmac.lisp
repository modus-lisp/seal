;;;; hmac.lisp — HMAC (RFC 2104) over SHA-256 and SHA-384.

(in-package #:seal)

(defun %hmac (hash-fn block-size key message)
  (let ((k (make-array block-size :element-type '(unsigned-byte 8) :initial-element 0)))
    (if (> (length key) block-size)
        (replace k (funcall hash-fn key))
        (replace k key))
    (let ((ipad (make-array block-size :element-type '(unsigned-byte 8)))
          (opad (make-array block-size :element-type '(unsigned-byte 8))))
      (dotimes (i block-size)
        (setf (aref ipad i) (logxor (aref k i) #x36))
        (setf (aref opad i) (logxor (aref k i) #x5c)))
      (let ((inner (funcall hash-fn (concatenate '(vector (unsigned-byte 8)) ipad message))))
        (funcall hash-fn (concatenate '(vector (unsigned-byte 8)) opad inner))))))

(defun hmac-sha256 (key message)
  "HMAC-SHA256. Returns a 32-byte vector."
  (%hmac #'sha256 64 key message))

(defun hmac-sha384 (key message)
  "HMAC-SHA384. Returns a 48-byte vector."
  (%hmac #'sha384 128 key message))
