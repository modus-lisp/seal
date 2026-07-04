;;;; x25519.lisp — X25519 Diffie-Hellman on Curve25519 (RFC 7748).
;;;;
;;;; A direct big-integer Montgomery ladder mod p = 2^255-19. Correct and
;;;; compact; not constant-time (SBCL bignum ops are data-dependent).

(in-package #:seal)

(defconstant +x25519-p+ (- (ash 1 255) 19))
(defconstant +x25519-a24+ 121665)

(defun %le->int (bytes)
  (let ((x 0))
    (dotimes (i (length bytes) x)
      (setf x (logior x (ash (aref bytes i) (* 8 i)))))))

(defun %int->le (n len)
  (let ((out (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (i len out)
      (setf (aref out i) (logand (ash n (* -8 i)) #xff)))))

(defun %mod-expt (base exp modulus)
  (let ((result 1) (base (mod base modulus)))
    (loop while (> exp 0) do
      (when (oddp exp) (setf result (mod (* result base) modulus)))
      (setf exp (ash exp -1)
            base (mod (* base base) modulus)))
    result))

(defun %x25519-clamp (scalar)
  (let ((k (copy-seq scalar)))
    (setf (aref k 0) (logand (aref k 0) 248)
          (aref k 31) (logior (logand (aref k 31) 127) 64))
    (%le->int k)))

(defun x25519 (scalar u)
  "X25519(scalar, u-coordinate). Both inputs and the result are 32-byte vectors."
  (let* ((p +x25519-p+)
         (k (%x25519-clamp scalar))
         ;; decodeUCoordinate: clear the most significant bit, reduce mod p
         (x1 (mod (logand (%le->int u) (1- (ash 1 255))) p))
         (x2 1) (z2 0) (x3 x1) (z3 1) (swap 0))
    (loop for tbit from 254 downto 0 do
      (let ((kt (logand (ash k (- tbit)) 1)))
        (setf swap (logxor swap kt))
        (when (= swap 1)
          (rotatef x2 x3) (rotatef z2 z3))
        (setf swap kt)
        (let* ((a (mod (+ x2 z2) p)) (aa (mod (* a a) p))
               (b (mod (- x2 z2) p)) (bb (mod (* b b) p))
               (e (mod (- aa bb) p))
               (c (mod (+ x3 z3) p)) (d (mod (- x3 z3) p))
               (da (mod (* d a) p)) (cb (mod (* c b) p)))
          (setf x3 (mod (* (+ da cb) (+ da cb)) p)
                z3 (mod (* x1 (mod (* (- da cb) (- da cb)) p)) p)
                x2 (mod (* aa bb) p)
                z2 (mod (* e (mod (+ aa (mod (* +x25519-a24+ e) p)) p)) p)))))
    (when (= swap 1)
      (rotatef x2 x3) (rotatef z2 z3))
    ;; result = x2 * z2^(p-2) mod p
    (let ((result (mod (* x2 (%mod-expt z2 (- p 2) p)) p)))
      (%int->le result 32))))

(defun x25519-public-key (scalar)
  "Public key for a 32-byte private SCALAR (X25519 over base point 9)."
  (let ((base (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref base 0) 9)
    (x25519 scalar base)))
