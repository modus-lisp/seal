;;;; ecdsa.lisp — ECDSA signatures over NIST P-256 and P-384 (sign + verify).
;;;;
;;;; Short-Weierstrass curves  y^2 = x^3 + a*x + b  (mod p)  with a = -3, over
;;;; the prime fields of secp256r1 (P-256) and secp384r1 (P-384). Affine point
;;;; arithmetic on Common Lisp bignums, plus the ECDSA sign/verify equations
;;;; (SEC 1). Not constant-time — signing uses a fresh random nonce (WebRTC
;;;; ephemeral keys), so no long-term-key side-channel exposure here.

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

;;; ---- affine point predicates ----------------------------------------------
;;; Affine points are (cons x y); the point at infinity is :infinity.

(defun ec-infinity-p (pt) (eq pt :infinity))

(defun ec-on-curve-p (curve pt)
  (or (ec-infinity-p pt)
      (let ((p (ec-p curve)) (x (car pt)) (y (cdr pt)))
        (= (mod (* y y) p)
           (mod (+ (* x x x) (* (ec-a curve) x) (ec-b curve)) p)))))

;;; ---- Jacobian projective coordinates --------------------------------------
;;; A point (X : Y : Z) stands for the affine point (X/Z^2, Y/Z^3); Z = 0 is the
;;; point at infinity. Working projectively defers the single expensive modular
;;; inversion to the very end of a scalar multiplication instead of paying one
;;; per group operation, which is the dominant cost of affine arithmetic (Guide
;;; to Elliptic Curve Cryptography, Hankerson/Menezes/Vanstone, ch. 3). Both
;;; NIST curves here have a = -3, admitting the fast doubling below.
;;;
;;; A Jacobian point is carried as a three-element simple-vector #(X Y Z).

(declaim (inline jac-x jac-y jac-z))
(defun jac-x (q) (svref q 0))
(defun jac-y (q) (svref q 1))
(defun jac-z (q) (svref q 2))

(defun jac-double (p q)
  "Point doubling in Jacobian coordinates for a = -3 (EFD dbl-2001-b)."
  (let ((y1 (jac-y q)) (z1 (jac-z q)) (x1 (jac-x q)))
    (if (or (zerop z1) (zerop y1))
        (vector 0 1 0)
        (let* ((delta (mod (* z1 z1) p))
               (gamma (mod (* y1 y1) p))
               (beta  (mod (* x1 gamma) p))
               (alpha (mod (* 3 (mod (* (- x1 delta) (+ x1 delta)) p)) p))
               (x3 (mod (- (* alpha alpha) (* 8 beta)) p))
               (z3 (mod (- (* (+ y1 z1) (+ y1 z1)) gamma delta) p))
               (y3 (mod (- (* alpha (- (* 4 beta) x3))
                           (* 8 (mod (* gamma gamma) p)))
                        p)))
          (vector x3 y3 z3)))))

(defun jac-add-affine (p q ax ay)
  "Add the affine point (AX, AY) to the Jacobian point Q (mixed addition,
EFD madd-2007-bl). AX/AY are assumed to lie on the curve and to be non-infinite."
  (let ((z1 (jac-z q)))
    (if (zerop z1)
        (vector ax ay 1)                     ; Q is the point at infinity
        (let* ((x1 (jac-x q)) (y1 (jac-y q))
               (z1z1 (mod (* z1 z1) p))
               (u2 (mod (* ax z1z1) p))
               (s2 (mod (* ay z1 z1z1) p))
               (h  (mod (- u2 x1) p))
               (r  (mod (- s2 y1) p)))
          (cond
            ((zerop h)
             (if (zerop r) (jac-double p q) (vector 0 1 0)))
            (t (let* ((hh  (mod (* h h) p))
                      (hhh (mod (* h hh) p))
                      (v   (mod (* x1 hh) p))
                      (x3 (mod (- (* r r) hhh (* 2 v)) p))
                      (y3 (mod (- (* r (- v x3)) (* y1 hhh)) p))
                      (z3 (mod (* z1 h) p)))
                 (vector x3 y3 z3))))))))

(defun jac-to-affine (p q)
  "Convert a Jacobian point back to affine (cons x y) with one inversion, or
:INFINITY. Returns the point at infinity when Z = 0."
  (let ((z (jac-z q)))
    (if (zerop z)
        :infinity
        (let* ((zinv (mod-inverse z p))
               (zinv2 (mod (* zinv zinv) p))
               (zinv3 (mod (* zinv2 zinv) p)))
          (cons (mod (* (jac-x q) zinv2) p)
                (mod (* (jac-y q) zinv3) p))))))

(defun ec-scalar-mult (curve k pt)
  "Compute k*PT, returning an affine point. Left-to-right double-and-add in
Jacobian coordinates with a single final inversion."
  (if (or (zerop k) (ec-infinity-p pt))
      :infinity
      (let* ((p (ec-p curve))
             (ax (car pt)) (ay (cdr pt))
             (acc (vector 0 1 0)))
        (loop for i from (1- (integer-length k)) downto 0 do
          (setf acc (jac-double p acc))
          (when (logbitp i k)
            (setf acc (jac-add-affine p acc ax ay))))
        (jac-to-affine p acc))))

(defun ec-double-scalar-mult (curve k1 pt1 k2 pt2)
  "Compute k1*PT1 + k2*PT2 as one affine point using Shamir's trick: a single
interleaved double-and-add over both scalars sharing the doublings, roughly
halving the work of two independent scalar multiplications. PT1 and PT2 are
affine points assumed to be on the curve."
  (let* ((p (ec-p curve))
         (x1 (car pt1)) (y1 (cdr pt1))
         (x2 (car pt2)) (y2 (cdr pt2))
         ;; Precompute PT1 + PT2 in affine so all table lookups are mixed adds.
         (sum (jac-to-affine p (jac-add-affine p (vector x1 y1 1) x2 y2)))
         (acc (vector 0 1 0))
         (nbits (max (integer-length k1) (integer-length k2))))
    (loop for i from (1- nbits) downto 0 do
      (setf acc (jac-double p acc))
      (let ((b1 (logbitp i k1)) (b2 (logbitp i k2)))
        (cond
          ((and b1 b2)
           ;; PT1 + PT2 may be the point at infinity (PT1 = -PT2).
           (if (ec-infinity-p sum)
               (setf acc (jac-add-affine p (jac-add-affine p acc x1 y1) x2 y2))
               (setf acc (jac-add-affine p acc (car sum) (cdr sum)))))
          (b1 (setf acc (jac-add-affine p acc x1 y1)))
          (b2 (setf acc (jac-add-affine p acc x2 y2))))))
    (jac-to-affine p acc)))

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
           (point (ec-double-scalar-mult
                   curve
                   u1 (cons (ec-gx curve) (ec-gy curve))
                   u2 public-point)))
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

(defun ec-field-len (curve) (ceiling (integer-length (ec-p curve)) 8))

(defun ec-encode-point (curve pt)
  "Encode an affine point as an uncompressed SEC1 octet string (0x04 || X || Y)."
  (let ((flen (ec-field-len curve)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 #(#x04) (i2osp (car pt) flen) (i2osp (cdr pt) flen))))

;;; ---- ECDSA signing ---------------------------------------------------------

(defun ec-random-scalar (curve)
  "A uniform random scalar in [1, n-1] on CURVE (rejection sampling — n is within a
hair of 2^bits for both curves here, so rejections are astronomically rare)."
  (let* ((n (ec-n curve)) (nbytes (ceiling (integer-length n) 8)))
    (loop for k = (os2ip (secure-random-bytes nbytes))
          when (< 0 k n) return k)))

(defun ec-generate-key (curve)
  "Generate an ECDSA key pair on CURVE.  Returns (values private-scalar public-point),
the public point being D*G as (cons x y)."
  (let ((d (ec-random-scalar curve)))
    (values d (ec-scalar-mult curve d (cons (ec-gx curve) (ec-gy curve))))))

(defun ecdsa-sign (curve d hash)
  "Sign the digest HASH with private scalar D on CURVE (SEC 1 §4.1.3, random nonce).
Returns (values r s), both in [1, n-1], retrying the vanishing r/s cases."
  (let* ((n (ec-n curve))
         (e (ecdsa-truncate-hash hash n))
         (g (cons (ec-gx curve) (ec-gy curve))))
    (loop
      (let* ((k (ec-random-scalar curve))
             (r (mod (car (ec-scalar-mult curve k g)) n)))
        (unless (zerop r)
          (let ((s (mod (* (mod-inverse k n) (mod (+ e (* r d)) n)) n)))
            (unless (zerop s)
              (return (values r s)))))))))
