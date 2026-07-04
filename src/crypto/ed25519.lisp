;;;; ed25519.lisp — Ed25519 signature verification (RFC 8032).
;;;;
;;;; The twisted Edwards curve  -x^2 + y^2 = 1 + d x^2 y^2  over the field of
;;;; 2^255-19, in extended homogeneous coordinates (X:Y:Z:T). Verification only.
;;;; Reuses SHA-512 from seal's crypto. Not constant-time (verification is over
;;;; public data).

(in-package #:seal)

(defconstant +ed-p+ (- (ash 1 255) 19))
(defconstant +ed-l+ (+ (ash 1 252) 27742317777372353535851937790883648493))

(defun ed-hex (s) (parse-integer (remove #\Space s) :radix 16))

(defparameter *ed-d*
  (mod (* -121665 (mod-inverse 121666 +ed-p+)) +ed-p+))
(defparameter *ed-sqrt-m1*
  (mod-expt 2 (ash (1- +ed-p+) -2) +ed-p+))           ; 2^((p-1)/4) = sqrt(-1)
(defparameter *ed-bx*
  (ed-hex "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"))
(defparameter *ed-by*
  (ed-hex "6666666666666666666666666666666666666666666666666666666666666658"))

(defun ed-fe-inv (a) (mod-expt a (- +ed-p+ 2) +ed-p+))

;;; ---- extended coordinate points  (list X Y Z T) ---------------------------

(defun ed-point (x y)
  (list (mod x +ed-p+) (mod y +ed-p+) 1 (mod (* x y) +ed-p+)))

(defun ed-base () (ed-point *ed-bx* *ed-by*))

(defun ed-identity () (list 0 1 1 0))

(defun ed-add (p q)
  "Unified addition on the a=-1 twisted Edwards curve (RFC 8032 §5.1.4)."
  (destructuring-bind (x1 y1 z1 t1) p
    (destructuring-bind (x2 y2 z2 t2) q
      (let* ((pp +ed-p+)
             (a (mod (* (mod (- y1 x1) pp) (mod (- y2 x2) pp)) pp))
             (b (mod (* (mod (+ y1 x1) pp) (mod (+ y2 x2) pp)) pp))
             (c (mod (* t1 2 *ed-d* t2) pp))
             (d (mod (* z1 2 z2) pp))
             (e (mod (- b a) pp))
             (f (mod (- d c) pp))
             (g (mod (+ d c) pp))
             (h (mod (+ b a) pp)))
        (list (mod (* e f) pp) (mod (* g h) pp) (mod (* f g) pp) (mod (* e h) pp))))))

(defun ed-scalar-mult (k point)
  (let ((result (ed-identity)))
    (loop for i from (1- (integer-length k)) downto 0 do
      (setf result (ed-add result result))
      (when (logbitp i k) (setf result (ed-add result point))))
    result))

(defun ed-affine (point)
  "Return (values x y) in affine coordinates."
  (destructuring-bind (x y z tt) point
    (declare (ignore tt))
    (let ((zi (ed-fe-inv z)))
      (values (mod (* x zi) +ed-p+) (mod (* y zi) +ed-p+)))))

(defun ed-encode-point (point)
  "Encode POINT to the 32-byte little-endian RFC 8032 form."
  (multiple-value-bind (x y) (ed-affine point)
    (let ((out (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 32) (setf (aref out i) (logand (ash y (* -8 i)) #xff)))
      (when (logbitp 0 x) (setf (aref out 31) (logior (aref out 31) #x80)))
      out)))

(defun ed-decode-point (bytes)
  "Decode a 32-byte encoded point. Returns a point, or NIL if invalid."
  (when (/= (length bytes) 32) (return-from ed-decode-point nil))
  (let* ((raw (os2ip-le bytes))
         (x-sign (logand (ash raw -255) 1))
         (y (logand raw (1- (ash 1 255)))))
    (when (>= y +ed-p+) (return-from ed-decode-point nil))
    (let* ((pp +ed-p+)
           (y2 (mod (* y y) pp))
           (u (mod (- y2 1) pp))
           (v (mod (+ (* *ed-d* y2) 1) pp))
           (v3 (mod (* v v v) pp))
           (v7 (mod (* v3 v3 v) pp))
           (x (mod (* u v3 (mod-expt (mod (* u v7) pp) (ash (- pp 5) -3) pp)) pp))
           (vx2 (mod (* v x x) pp)))
      (cond
        ((= vx2 (mod u pp)) nil)                 ; x is correct
        ((= vx2 (mod (- u) pp)) (setf x (mod (* x *ed-sqrt-m1*) pp)))
        (t (return-from ed-decode-point nil)))   ; no square root
      (when (and (zerop x) (= x-sign 1)) (return-from ed-decode-point nil))
      (when (/= (logand x 1) x-sign) (setf x (mod (- pp x) pp)))
      (ed-point x y))))

(defun ed25519-verify (public-key signature message)
  "Verify an Ed25519 SIGNATURE (64 bytes) over MESSAGE with the 32-byte
PUBLIC-KEY. Returns T / NIL. (RFC 8032 §5.1.7.)"
  (when (or (/= (length public-key) 32) (/= (length signature) 64))
    (return-from ed25519-verify nil))
  (let* ((r-bytes (subseq signature 0 32))
         (s (os2ip-le (subseq signature 32 64)))
         (a-point (ed-decode-point public-key))
         (r-point (ed-decode-point r-bytes)))
    (when (or (null a-point) (null r-point) (>= s +ed-l+))
      (return-from ed25519-verify nil))
    (let* ((k (mod (os2ip-le (sha512 (concatenate '(vector (unsigned-byte 8))
                                                  r-bytes public-key message)))
                   +ed-l+))
           (lhs (ed-scalar-mult s (ed-base)))
           (rhs (ed-add r-point (ed-scalar-mult k a-point))))
      (equalp (ed-encode-point lhs) (ed-encode-point rhs)))))
