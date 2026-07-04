;;;; bigint.lisp — big-integer helpers for the signature primitives.
;;;;
;;;; RSA and the elliptic curves all reduce to arithmetic on arbitrary-precision
;;;; integers, which Common Lisp provides natively (bignums). These helpers cover
;;;; the octet-string <-> integer conversions of PKCS#1 (I2OSP / OS2IP), modular
;;;; exponentiation, and the modular inverse.

(in-package #:seal)

(defun os2ip (bytes)
  "OS2IP (RFC 8017 §4.2): big-endian octet string -> nonnegative integer."
  (let ((n 0))
    (loop for b across bytes do (setf n (logior (ash n 8) b)))
    n))

(defun i2osp (n length)
  "I2OSP (RFC 8017 §4.1): integer -> big-endian octet string of LENGTH bytes.
Signals an error if N does not fit."
  (when (< n 0) (error "i2osp: negative integer"))
  (when (>= n (ash 1 (* 8 length))) (error "i2osp: integer too large"))
  (let ((out (make-array length :element-type '(unsigned-byte 8))))
    (loop for i from (1- length) downto 0 do
      (setf (aref out i) (logand n #xff)
            n (ash n -8)))
    out))

(defun os2ip-le (bytes)
  "Little-endian octet string -> nonnegative integer."
  (let ((n 0))
    (loop for i from (1- (length bytes)) downto 0
          do (setf n (logior (ash n 8) (aref bytes i))))
    n))

(defun bytes->int (bytes) (os2ip bytes))

(defun int->bytes (n length) (i2osp n length))

(defun mod-expt (base exponent modulus)
  "Modular exponentiation BASE^EXPONENT mod MODULUS by square-and-multiply."
  (let ((result 1)
        (b (mod base modulus))
        (e exponent))
    (loop while (plusp e) do
      (when (oddp e) (setf result (mod (* result b) modulus)))
      (setf e (ash e -1))
      (when (plusp e) (setf b (mod (* b b) modulus))))
    result))

(defun mod-inverse (a modulus)
  "Modular inverse of A mod MODULUS via the extended Euclidean algorithm.
Returns NIL if A is not invertible."
  (let ((t0 0) (t1 1)
        (r0 modulus) (r1 (mod a modulus)))
    (loop while (not (zerop r1)) do
      (let ((q (floor r0 r1)))
        (psetf r0 r1 r1 (- r0 (* q r1))
               t0 t1 t1 (- t0 (* q t1)))))
    (cond ((> r0 1) nil)                       ; not invertible
          ((< t0 0) (+ t0 modulus))
          (t t0))))
