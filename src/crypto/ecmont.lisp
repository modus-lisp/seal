;;;; ecmont.lisp — P-256 / P-384 point arithmetic on FIXNUM limbs (Montgomery form).
;;;;
;;;; The group operations in ecdsa.lisp are written on CL bignums: every field
;;;; multiply is a bignum `*' and a bignum `mod'.  That is the right shape where
;;;; bignums are native (SBCL: a verify is milliseconds) and ruinous where they
;;;; are not -- on modus a 256-bit multiply-and-reduce costs ~0.4 ms, so one
;;;; P-256 verify took ~2 s, a certificate chain ~16 s, and servers hung up on
;;;; the TLS connection before the client had finished checking who they were.
;;;;
;;;; Here a field element is a simple-vector of N limbs of 28 bits (N = 10 for
;;;; P-256, 14 for P-384), kept in Montgomery form (a*R mod p, R = 2^(28N)).
;;;; Every intermediate is a fixnum on any implementation with >= 60-bit
;;;; fixnums: a limb product is < 2^56 and the CIOS accumulator adds at most
;;;; two of them plus a carry.  The point formulas are exactly ecdsa.lisp's
;;;; (EFD dbl-2001-b / madd-2007-bl, a = -3); only the field arithmetic moved.
;;;; *EC-FAST-P* selects this path; ecdsa.lisp's bignum path stays the
;;;; reference it is tested against.

(in-package #:seal)

(defconstant +ecm-bits+ 28)
(defconstant +ecm-mask+ (1- (ash 1 28)))

(defparameter *ec-fast-p* #+sbcl nil #-sbcl t
  "Use the fixnum-limb Montgomery path for ECDSA verification.  Off on SBCL,
   whose native bignums are already fast; on everywhere else.")

(defstruct (ecm-field (:conc-name ecm-))
  n            ; limb count
  p            ; the prime, as an integer
  p-limbs      ; the prime, as limbs
  pinv         ; -p^-1 mod 2^28
  r2           ; R^2 mod p, as limbs (NOT Montgomery form -- used to enter it)
  one)         ; R mod p, as limbs (1 in Montgomery form)

(defun %ecm-int->limbs (x n)
  (let ((v (make-array n)))
    (dotimes (i n v)
      (setf (svref v i) (logand (ash x (- (* i +ecm-bits+))) +ecm-mask+)))))

(defun %ecm-limbs->int (v)
  (let ((x 0))
    (loop for i from (1- (length v)) downto 0
          do (setf x (+ (ash x +ecm-bits+) (svref v i))))
    x))

(defun %ecm-make-field (p)
  (let* ((n (ceiling (integer-length p) +ecm-bits+))
         (r (ash 1 (* n +ecm-bits+)))
         ;; -p^-1 mod 2^28 by Newton iteration on the low limb
         (p0 (logand p +ecm-mask+))
         (inv 1))
    (dotimes (i 6) (setf inv (logand (* inv (- 2 (* p0 inv))) +ecm-mask+)))
    (make-ecm-field :n n :p p :p-limbs (%ecm-int->limbs p n)
                    :pinv (logand (- inv) +ecm-mask+)
                    :r2 (%ecm-int->limbs (mod (* r r) p) n)
                    :one (%ecm-int->limbs (mod r p) n))))

(defvar *ecm-fields* nil)
#+modus ; per computation on modus: threads and actors share no state
(let ((reg (find-symbol "REGISTER-PER-COMPUTATION-SPECIAL" "COMMON-LISP-USER")))
  (when (and reg (fboundp reg)) (funcall reg '*ecm-fields*)))
(defun %ecm-field-for (p)
  (or (cdr (assoc p *ecm-fields*))
      (let ((f (%ecm-make-field p)))
        (push (cons p f) *ecm-fields*)
        f)))

(defun %ecm-geq-p (a p-limbs n)
  "A >= P, both N-limb little-endian."
  (loop for i from (1- n) downto 0
        do (let ((x (svref a i)) (y (svref p-limbs i)))
             (cond ((> x y) (return-from %ecm-geq-p t))
                   ((< x y) (return-from %ecm-geq-p nil)))))
  t)

(defun %ecm-sub-p-in-place (a p-limbs n)
  (let ((borrow 0))
    (dotimes (i n a)
      (let ((d (- (svref a i) (svref p-limbs i) borrow)))
        (if (< d 0)
            (setf (svref a i) (+ d (ash 1 +ecm-bits+)) borrow 1)
            (setf (svref a i) d borrow 0))))))

(defun ecm-mul (f a b)
  "Montgomery product a*b*R^-1 mod p (CIOS), fully reduced."
  (let* ((n (ecm-n f)) (p (ecm-p-limbs f)) (pinv (ecm-pinv f))
         (tt (make-array (+ n 2) :initial-element 0)))
    (dotimes (i n)
      (let ((bi (svref b i)) (c 0))
        (dotimes (j n)
          (let ((s (+ (svref tt j) (* (svref a j) bi) c)))
            (setf (svref tt j) (logand s +ecm-mask+)
                  c (ash s (- +ecm-bits+)))))
        (let ((s (+ (svref tt n) c)))
          (setf (svref tt n) (logand s +ecm-mask+)
                (svref tt (1+ n)) (+ (svref tt (1+ n)) (ash s (- +ecm-bits+))))))
      (let* ((m (logand (* (svref tt 0) pinv) +ecm-mask+))
             (c (ash (+ (svref tt 0) (* m (svref p 0))) (- +ecm-bits+))))
        (loop for j from 1 below n
              do (let ((s (+ (svref tt j) (* m (svref p j)) c)))
                   (setf (svref tt (1- j)) (logand s +ecm-mask+)
                         c (ash s (- +ecm-bits+)))))
        (let ((s (+ (svref tt n) c)))
          (setf (svref tt (1- n)) (logand s +ecm-mask+)
                (svref tt n) (+ (svref tt (1+ n)) (ash s (- +ecm-bits+)))
                (svref tt (1+ n)) 0))))
    (let ((r (make-array n)))
      (dotimes (i n) (setf (svref r i) (svref tt i)))
      (when (or (plusp (svref tt n)) (%ecm-geq-p r p n))
        (%ecm-sub-p-in-place r p n))
      r)))

(defun ecm-add (f a b)
  (let* ((n (ecm-n f)) (p (ecm-p-limbs f)) (r (make-array n)) (c 0))
    (dotimes (i n)
      (let ((s (+ (svref a i) (svref b i) c)))
        (setf (svref r i) (logand s +ecm-mask+) c (ash s (- +ecm-bits+)))))
    (when (or (plusp c) (%ecm-geq-p r p n)) (%ecm-sub-p-in-place r p n))
    r))

(defun ecm-sub (f a b)
  (let* ((n (ecm-n f)) (p (ecm-p-limbs f)) (r (make-array n)) (borrow 0))
    (dotimes (i n)
      (let ((d (- (svref a i) (svref b i) borrow)))
        (if (< d 0)
            (setf (svref r i) (+ d (ash 1 +ecm-bits+)) borrow 1)
            (setf (svref r i) d borrow 0))))
    (when (plusp borrow)                ; went negative: add p back
      (let ((c 0))
        (dotimes (i n)
          (let ((s (+ (svref r i) (svref p i) c)))
            (setf (svref r i) (logand s +ecm-mask+) c (ash s (- +ecm-bits+)))))))
    r))

(defun ecm-zero-p (a) (every #'zerop a))
(defun ecm-to (f x) (ecm-mul f (%ecm-int->limbs (mod x (ecm-p f)) (ecm-n f)) (ecm-r2 f)))
(defun ecm-from (f a)
  (let ((one (make-array (ecm-n f) :initial-element 0)))
    (setf (svref one 0) 1)
    (%ecm-limbs->int (ecm-mul f a one))))

;;; --- Jacobian points, coordinates in Montgomery form -------------------------

(defun ecm-double (f q)
  "EFD dbl-2001-b, a = -3 (ecdsa.lisp JAC-DOUBLE, on limbs)."
  (let ((x1 (svref q 0)) (y1 (svref q 1)) (z1 (svref q 2)))
    (if (or (ecm-zero-p z1) (ecm-zero-p y1))
        (vector (ecm-one f) (ecm-one f) (make-array (ecm-n f) :initial-element 0))
        (let* ((delta (ecm-mul f z1 z1))
               (gamma (ecm-mul f y1 y1))
               (beta (ecm-mul f x1 gamma))
               (t1 (ecm-mul f (ecm-sub f x1 delta) (ecm-add f x1 delta)))
               (alpha (ecm-add f t1 (ecm-add f t1 t1)))
               (beta2 (ecm-add f beta beta))
               (beta4 (ecm-add f beta2 beta2))
               (beta8 (ecm-add f beta4 beta4))
               (x3 (ecm-sub f (ecm-mul f alpha alpha) beta8))
               (yz (ecm-add f y1 z1))
               (z3 (ecm-sub f (ecm-sub f (ecm-mul f yz yz) gamma) delta))
               (g2 (ecm-mul f gamma gamma))
               (g2x2 (ecm-add f g2 g2))
               (g2x4 (ecm-add f g2x2 g2x2))
               (g2x8 (ecm-add f g2x4 g2x4))
               (y3 (ecm-sub f (ecm-mul f alpha (ecm-sub f beta4 x3)) g2x8)))
          (vector x3 y3 z3)))))

(defun ecm-add-affine (f q ax ay)
  "EFD madd-2007-bl (ecdsa.lisp JAC-ADD-AFFINE, on limbs)."
  (let ((z1 (svref q 2)))
    (if (ecm-zero-p z1)
        (vector ax ay (ecm-one f))
        (let* ((x1 (svref q 0)) (y1 (svref q 1))
               (z1z1 (ecm-mul f z1 z1))
               (u2 (ecm-mul f ax z1z1))
               (s2 (ecm-mul f ay (ecm-mul f z1 z1z1)))
               (h (ecm-sub f u2 x1))
               (r (ecm-sub f s2 y1)))
          (cond
            ((ecm-zero-p h)
             (if (ecm-zero-p r)
                 (ecm-double f q)
                 (vector (ecm-one f) (ecm-one f) (make-array (ecm-n f) :initial-element 0))))
            (t (let* ((hh (ecm-mul f h h))
                      (hhh (ecm-mul f h hh))
                      (v (ecm-mul f x1 hh))
                      (x3 (ecm-sub f (ecm-sub f (ecm-mul f r r) hhh) (ecm-add f v v)))
                      (y3 (ecm-sub f (ecm-mul f r (ecm-sub f v x3)) (ecm-mul f y1 hhh)))
                      (z3 (ecm-mul f z1 h)))
                 (vector x3 y3 z3))))))))

(defun ecm-to-affine (f q)
  "Back to an affine (cons x y) of plain integers, or :INFINITY."
  (let ((z (svref q 2)))
    (if (ecm-zero-p z)
        :infinity
        (let* ((p (ecm-p f))
               (zi (mod-inverse (ecm-from f z) p))
               (zi2 (mod (* zi zi) p))
               (zi3 (mod (* zi2 zi) p)))
          (cons (mod (* (ecm-from f (svref q 0)) zi2) p)
                (mod (* (ecm-from f (svref q 1)) zi3) p))))))

(defun ec-double-scalar-mult-fast (curve k1 pt1 k2 pt2)
  "EC-DOUBLE-SCALAR-MULT (Shamir's trick) on fixnum limbs."
  (let* ((f (%ecm-field-for (ec-p curve)))
         (x1 (ecm-to f (car pt1))) (y1 (ecm-to f (cdr pt1)))
         (x2 (ecm-to f (car pt2))) (y2 (ecm-to f (cdr pt2)))
         (sum (ecm-add-affine f (vector x1 y1 (ecm-one f)) x2 y2))
         (sum-aff (ecm-to-affine f sum))
         (sx (and (consp sum-aff) (ecm-to f (car sum-aff))))
         (sy (and (consp sum-aff) (ecm-to f (cdr sum-aff))))
         (acc (vector (ecm-one f) (ecm-one f) (make-array (ecm-n f) :initial-element 0)))
         (nbits (max (integer-length k1) (integer-length k2))))
    (loop for i from (1- nbits) downto 0 do
      (setf acc (ecm-double f acc))
      (let ((b1 (logbitp i k1)) (b2 (logbitp i k2)))
        (cond
          ((and b1 b2)
           (if sx
               (setf acc (ecm-add-affine f acc sx sy))
               (setf acc (ecm-add-affine f (ecm-add-affine f acc x1 y1) x2 y2))))
          (b1 (setf acc (ecm-add-affine f acc x1 y1)))
          (b2 (setf acc (ecm-add-affine f acc x2 y2))))))
    (ecm-to-affine f acc)))
