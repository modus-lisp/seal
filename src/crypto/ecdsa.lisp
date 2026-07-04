;;;; ecdsa.lisp — ECDSA signature verification over NIST P-256 and P-384.
;;;;
;;;; Short-Weierstrass curves  y^2 = x^3 + a*x + b  (mod p)  with a = -3, over
;;;; the prime fields of secp256r1 (P-256) and secp384r1 (P-384). Affine point
;;;; arithmetic on Common Lisp bignums, plus the ECDSA verification equation
;;;; (RFC 6979 / SEC 1). Verification only, not constant-time.

(in-package #:seal)

;;; ---- curve descriptor ------------------------------------------------------

(defstruct (ec-curve (:conc-name ec-)) p a b gx gy n name)

(defun ec-hex (s) (parse-integer (remove #\Space s) :radix 16))

(defparameter *p256*
  (make-ec-curve
   :name :p256
   :p (ec-hex "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
   :a (ec-hex "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc")
   :b (ec-hex "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
   :gx (ec-hex "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
   :gy (ec-hex "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
   :n (ec-hex "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")))

(defparameter *p384*
  (make-ec-curve
   :name :p384
   :p (ec-hex "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff")
   :a (ec-hex "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc")
   :b (ec-hex "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef")
   :gx (ec-hex "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7")
   :gy (ec-hex "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")
   :n (ec-hex "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973")))

;;; ---- affine point arithmetic ----------------------------------------------
;;; Points are (cons x y); the point at infinity is :infinity.

(defun ec-infinity-p (pt) (eq pt :infinity))

(defun ec-on-curve-p (curve pt)
  (or (ec-infinity-p pt)
      (let ((p (ec-p curve)) (x (car pt)) (y (cdr pt)))
        (= (mod (* y y) p)
           (mod (+ (* x x x) (* (ec-a curve) x) (ec-b curve)) p)))))

(defun ec-double (curve pt)
  (if (ec-infinity-p pt)
      pt
      (let ((p (ec-p curve)) (x (car pt)) (y (cdr pt)))
        (if (zerop y)
            :infinity
            (let* ((lam (mod (* (+ (* 3 x x) (ec-a curve))
                                (mod-inverse (mod (* 2 y) p) p))
                             p))
                   (x3 (mod (- (* lam lam) (* 2 x)) p))
                   (y3 (mod (- (* lam (- x x3)) y) p)))
              (cons x3 y3))))))

(defun ec-add (curve a b)
  (cond
    ((ec-infinity-p a) b)
    ((ec-infinity-p b) a)
    (t (let ((p (ec-p curve))
             (x1 (car a)) (y1 (cdr a))
             (x2 (car b)) (y2 (cdr b)))
         (cond
           ((and (= x1 x2) (= (mod (+ y1 y2) p) 0)) :infinity)
           ((and (= x1 x2) (= y1 y2)) (ec-double curve a))
           (t (let* ((lam (mod (* (- y2 y1) (mod-inverse (mod (- x2 x1) p) p)) p))
                     (x3 (mod (- (* lam lam) x1 x2) p))
                     (y3 (mod (- (* lam (- x1 x3)) y1) p)))
                (cons x3 y3))))))))

(defun ec-scalar-mult (curve k pt)
  "Compute k*PT by left-to-right double-and-add."
  (let ((result :infinity))
    (loop for i from (1- (integer-length k)) downto 0 do
      (setf result (ec-double curve result))
      (when (logbitp i k)
        (setf result (ec-add curve result pt))))
    result))

;;; ---- ECDSA verification ----------------------------------------------------

(defun ecdsa-truncate-hash (hash n)
  "Left-truncate HASH (a byte vector) to the bit length of the order N (SEC 1)."
  (let* ((e (os2ip hash))
         (hbits (* 8 (length hash)))
         (nbits (integer-length n)))
    (if (> hbits nbits) (ash e (- (- hbits nbits))) e)))

(defun ecdsa-verify (curve public-point hash r s)
  "Verify ECDSA (R,S) over the digest HASH with PUBLIC-POINT on CURVE. T / NIL.
PUBLIC-POINT is (cons x y). HASH is the raw digest byte vector."
  (let ((n (ec-n curve)))
    (unless (and (< 0 r n) (< 0 s n)) (return-from ecdsa-verify nil))
    (unless (ec-on-curve-p curve public-point) (return-from ecdsa-verify nil))
    (let* ((e (ecdsa-truncate-hash hash n))
           (w (mod-inverse s n))
           (u1 (mod (* e w) n))
           (u2 (mod (* r w) n))
           (point (ec-add curve
                          (ec-scalar-mult curve u1 (cons (ec-gx curve) (ec-gy curve)))
                          (ec-scalar-mult curve u2 public-point))))
      (and (not (ec-infinity-p point))
           (= (mod (car point) n) r)))))

(defun ec-decode-point (curve bytes)
  "Decode an uncompressed SEC1 point (0x04 || X || Y). Returns (cons x y) or NIL."
  (let ((flen (ceiling (integer-length (ec-p curve)) 8)))
    (cond
      ((and (= (length bytes) (1+ (* 2 flen))) (= (aref bytes 0) #x04))
       (cons (os2ip (subseq bytes 1 (1+ flen)))
             (os2ip (subseq bytes (1+ flen)))))
      (t nil))))
