;;;; sha256.lisp — SHA-256 (FIPS 180-4)

(in-package #:seal)

(declaim (inline u32 rotr32))
(defun u32 (x) (logand x #xffffffff))
(defun rotr32 (x n)
  (u32 (logior (ash x (- n)) (ash x (- 32 n)))))

(defparameter *sha256-k*
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1
    #x923f82a4 #xab1c5ed5 #xd807aa98 #x12835b01 #x243185be #x550c7dc3
    #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174 #xe49b69c1 #xefbe4786
    #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147
    #x06ca6351 #x14292967 #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
    #x650a7354 #x766a0abb #x81c2c92e #x92722c85 #xa2bfe8a1 #xa81a664b
    #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a
    #x5b9cca4f #x682e6ff3 #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))

(defun sha256-block (h block off)
  "Process one 64-byte block at OFF in BLOCK, updating the 8-word state H."
  (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
    (dotimes (i 16)
      (let ((j (+ off (* i 4))))
        (setf (aref w i)
              (logior (ash (aref block j) 24)
                      (ash (aref block (+ j 1)) 16)
                      (ash (aref block (+ j 2)) 8)
                      (aref block (+ j 3))))))
    (loop for i from 16 below 64 do
      (let ((s0 (logxor (rotr32 (aref w (- i 15)) 7)
                        (rotr32 (aref w (- i 15)) 18)
                        (ash (aref w (- i 15)) -3)))
            (s1 (logxor (rotr32 (aref w (- i 2)) 17)
                        (rotr32 (aref w (- i 2)) 19)
                        (ash (aref w (- i 2)) -10))))
        (setf (aref w i) (u32 (+ (aref w (- i 16)) s0 (aref w (- i 7)) s1)))))
    (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
          (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
      (dotimes (i 64)
        (let* ((s1 (logxor (rotr32 e 6) (rotr32 e 11) (rotr32 e 25)))
               (ch (logxor (logand e f) (logand (lognot e) g)))
               (t1 (u32 (+ hh s1 ch (aref *sha256-k* i) (aref w i))))
               (s0 (logxor (rotr32 a 2) (rotr32 a 13) (rotr32 a 22)))
               (maj (logxor (logand a b) (logand a c) (logand b c)))
               (t2 (u32 (+ s0 maj))))
          (setf hh g g f f e e (u32 (+ d t1))
                d c c b b a a (u32 (+ t1 t2)))))
      (setf (aref h 0) (u32 (+ (aref h 0) a))
            (aref h 1) (u32 (+ (aref h 1) b))
            (aref h 2) (u32 (+ (aref h 2) c))
            (aref h 3) (u32 (+ (aref h 3) d))
            (aref h 4) (u32 (+ (aref h 4) e))
            (aref h 5) (u32 (+ (aref h 5) f))
            (aref h 6) (u32 (+ (aref h 6) g))
            (aref h 7) (u32 (+ (aref h 7) hh))))))

(defun sha256 (message)
  "SHA-256 of a byte vector. Returns a 32-byte vector."
  (let* ((msg (coerce message '(simple-array (unsigned-byte 8) (*))))
         (len (length msg))
         (bitlen (* len 8))
         ;; padded length: message + 0x80 + zeros + 8-byte length, multiple of 64
         (padlen (let ((r (mod (+ len 1 8) 64)))
                   (+ len 1 8 (if (zerop r) 0 (- 64 r)))))
         (padded (make-array padlen :element-type '(unsigned-byte 8)
                             :initial-element 0))
         (h (make-array 8 :element-type '(unsigned-byte 32)
                        :initial-contents
                        '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                          #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19))))
    (replace padded msg)
    (setf (aref padded len) #x80)
    (dotimes (i 8)
      (setf (aref padded (- padlen 1 i)) (logand (ash bitlen (* -8 i)) #xff)))
    (do ((off 0 (+ off 64)))
        ((>= off padlen))
      (sha256-block h padded off))
    (let ((out (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 8)
        (let ((v (aref h i)))
          (setf (aref out (* i 4)) (logand (ash v -24) #xff)
                (aref out (+ (* i 4) 1)) (logand (ash v -16) #xff)
                (aref out (+ (* i 4) 2)) (logand (ash v -8) #xff)
                (aref out (+ (* i 4) 3)) (logand v #xff))))
      out)))
