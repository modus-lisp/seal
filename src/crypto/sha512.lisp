;;;; sha512.lisp — SHA-512 and SHA-384 (FIPS 180-4)

(in-package #:seal)

(declaim (inline u64 rotr64))
(defun u64 (x) (logand x #xffffffffffffffff))
(defun rotr64 (x n)
  (u64 (logior (ash x (- n)) (ash x (- 64 n)))))

(defparameter *sha512-k*
  #(#x428a2f98d728ae22 #x7137449123ef65cd #xb5c0fbcfec4d3b2f #xe9b5dba58189dbbc
    #x3956c25bf348b538 #x59f111f1b605d019 #x923f82a4af194f9b #xab1c5ed5da6d8118
    #xd807aa98a3030242 #x12835b0145706fbe #x243185be4ee4b28c #x550c7dc3d5ffb4e2
    #x72be5d74f27b896f #x80deb1fe3b1696b1 #x9bdc06a725c71235 #xc19bf174cf692694
    #xe49b69c19ef14ad2 #xefbe4786384f25e3 #x0fc19dc68b8cd5b5 #x240ca1cc77ac9c65
    #x2de92c6f592b0275 #x4a7484aa6ea6e483 #x5cb0a9dcbd41fbd4 #x76f988da831153b5
    #x983e5152ee66dfab #xa831c66d2db43210 #xb00327c898fb213f #xbf597fc7beef0ee4
    #xc6e00bf33da88fc2 #xd5a79147930aa725 #x06ca6351e003826f #x142929670a0e6e70
    #x27b70a8546d22ffc #x2e1b21385c26c926 #x4d2c6dfc5ac42aed #x53380d139d95b3df
    #x650a73548baf63de #x766a0abb3c77b2a8 #x81c2c92e47edaee6 #x92722c851482353b
    #xa2bfe8a14cf10364 #xa81a664bbc423001 #xc24b8b70d0f89791 #xc76c51a30654be30
    #xd192e819d6ef5218 #xd69906245565a910 #xf40e35855771202a #x106aa07032bbd1b8
    #x19a4c116b8d2d0c8 #x1e376c085141ab53 #x2748774cdf8eeb99 #x34b0bcb5e19b48a8
    #x391c0cb3c5c95a63 #x4ed8aa4ae3418acb #x5b9cca4f7763e373 #x682e6ff3d6b2b8a3
    #x748f82ee5defb2fc #x78a5636f43172f60 #x84c87814a1f0ab72 #x8cc702081a6439ec
    #x90befffa23631e28 #xa4506cebde82bde9 #xbef9a3f7b2c67915 #xc67178f2e372532b
    #xca273eceea26619c #xd186b8c721c0c207 #xeada7dd6cde0eb1e #xf57d4f7fee6ed178
    #x06f067aa72176fba #x0a637dc5a2c898a6 #x113f9804bef90dae #x1b710b35131c471b
    #x28db77f523047d84 #x32caab7b40c72493 #x3c9ebe0a15c9bebc #x431d67c49c100d4c
    #x4cc5d4becb3e42b6 #x597f299cfc657e2a #x5fcb6fab3ad6faec #x6c44198c4a475817))

(defun sha512-block (h block off)
  (let ((w (make-array 80 :element-type '(unsigned-byte 64))))
    (dotimes (i 16)
      (let ((j (+ off (* i 8))) (v 0))
        (dotimes (b 8) (setf v (logior (ash v 8) (aref block (+ j b)))))
        (setf (aref w i) v)))
    (loop for i from 16 below 80 do
      (let ((s0 (logxor (rotr64 (aref w (- i 15)) 1)
                        (rotr64 (aref w (- i 15)) 8)
                        (ash (aref w (- i 15)) -7)))
            (s1 (logxor (rotr64 (aref w (- i 2)) 19)
                        (rotr64 (aref w (- i 2)) 61)
                        (ash (aref w (- i 2)) -6))))
        (setf (aref w i) (u64 (+ (aref w (- i 16)) s0 (aref w (- i 7)) s1)))))
    (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
          (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
      (dotimes (i 80)
        (let* ((s1 (logxor (rotr64 e 14) (rotr64 e 18) (rotr64 e 41)))
               (ch (logxor (logand e f) (logand (lognot e) g)))
               (t1 (u64 (+ hh s1 ch (aref *sha512-k* i) (aref w i))))
               (s0 (logxor (rotr64 a 28) (rotr64 a 34) (rotr64 a 39)))
               (maj (logxor (logand a b) (logand a c) (logand b c)))
               (t2 (u64 (+ s0 maj))))
          (setf hh g g f f e e (u64 (+ d t1))
                d c c b b a a (u64 (+ t1 t2)))))
      (setf (aref h 0) (u64 (+ (aref h 0) a))
            (aref h 1) (u64 (+ (aref h 1) b))
            (aref h 2) (u64 (+ (aref h 2) c))
            (aref h 3) (u64 (+ (aref h 3) d))
            (aref h 4) (u64 (+ (aref h 4) e))
            (aref h 5) (u64 (+ (aref h 5) f))
            (aref h 6) (u64 (+ (aref h 6) g))
            (aref h 7) (u64 (+ (aref h 7) hh))))))

(defun %sha512-core (message init out-words)
  (let* ((msg (coerce message '(simple-array (unsigned-byte 8) (*))))
         (len (length msg))
         (bitlen (* len 8))
         (padlen (let ((r (mod (+ len 1 16) 128)))
                   (+ len 1 16 (if (zerop r) 0 (- 128 r)))))
         (padded (make-array padlen :element-type '(unsigned-byte 8)
                             :initial-element 0))
         (h (make-array 8 :element-type '(unsigned-byte 64)
                        :initial-contents init)))
    (replace padded msg)
    (setf (aref padded len) #x80)
    ;; 128-bit length; only low 64 bits are meaningful here
    (dotimes (i 8)
      (setf (aref padded (- padlen 1 i)) (logand (ash bitlen (* -8 i)) #xff)))
    (do ((off 0 (+ off 128)))
        ((>= off padlen))
      (sha512-block h padded off))
    (let ((out (make-array (* out-words 8) :element-type '(unsigned-byte 8))))
      (dotimes (i out-words)
        (let ((v (aref h i)))
          (dotimes (b 8)
            (setf (aref out (+ (* i 8) b)) (logand (ash v (* -8 (- 7 b))) #xff)))))
      out)))

(defun sha512 (message)
  "SHA-512 of a byte vector. Returns a 64-byte vector."
  (%sha512-core message
                '(#x6a09e667f3bcc908 #xbb67ae8584caa73b #x3c6ef372fe94f82b
                  #xa54ff53a5f1d36f1 #x510e527fade682d1 #x9b05688c2b3e6c1f
                  #x1f83d9abfb41bd6b #x5be0cd19137e2179)
                8))

(defun sha384 (message)
  "SHA-384 of a byte vector. Returns a 48-byte vector."
  (%sha512-core message
                '(#xcbbb9d5dc1059ed8 #x629a292a367cd507 #x9159015a3070dd17
                  #x152fecd8f70e5939 #x67332667ffc00b31 #x8eb44a8768581511
                  #xdb0c2e0d64f98fa7 #x47b5481dbefa4fa4)
                6))
