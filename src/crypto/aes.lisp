;;;; aes.lisp — AES block cipher (FIPS 197), 128- and 256-bit keys, plus CBC.

(in-package #:seal)

(defparameter *aes-sbox*
  #(#x63 #x7c #x77 #x7b #xf2 #x6b #x6f #xc5 #x30 #x01 #x67 #x2b #xfe #xd7 #xab #x76
    #xca #x82 #xc9 #x7d #xfa #x59 #x47 #xf0 #xad #xd4 #xa2 #xaf #x9c #xa4 #x72 #xc0
    #xb7 #xfd #x93 #x26 #x36 #x3f #xf7 #xcc #x34 #xa5 #xe5 #xf1 #x71 #xd8 #x31 #x15
    #x04 #xc7 #x23 #xc3 #x18 #x96 #x05 #x9a #x07 #x12 #x80 #xe2 #xeb #x27 #xb2 #x75
    #x09 #x83 #x2c #x1a #x1b #x6e #x5a #xa0 #x52 #x3b #xd6 #xb3 #x29 #xe3 #x2f #x84
    #x53 #xd1 #x00 #xed #x20 #xfc #xb1 #x5b #x6a #xcb #xbe #x39 #x4a #x4c #x58 #xcf
    #xd0 #xef #xaa #xfb #x43 #x4d #x33 #x85 #x45 #xf9 #x02 #x7f #x50 #x3c #x9f #xa8
    #x51 #xa3 #x40 #x8f #x92 #x9d #x38 #xf5 #xbc #xb6 #xda #x21 #x10 #xff #xf3 #xd2
    #xcd #x0c #x13 #xec #x5f #x97 #x44 #x17 #xc4 #xa7 #x7e #x3d #x64 #x5d #x19 #x73
    #x60 #x81 #x4f #xdc #x22 #x2a #x90 #x88 #x46 #xee #xb8 #x14 #xde #x5e #x0b #xdb
    #xe0 #x32 #x3a #x0a #x49 #x06 #x24 #x5c #xc2 #xd3 #xac #x62 #x91 #x95 #xe4 #x79
    #xe7 #xc8 #x37 #x6d #x8d #xd5 #x4e #xa9 #x6c #x56 #xf4 #xea #x65 #x7a #xae #x08
    #xba #x78 #x25 #x2e #x1c #xa6 #xb4 #xc6 #xe8 #xdd #x74 #x1f #x4b #xbd #x8b #x8a
    #x70 #x3e #xb5 #x66 #x48 #x03 #xf6 #x0e #x61 #x35 #x57 #xb9 #x86 #xc1 #x1d #x9e
    #xe1 #xf8 #x98 #x11 #x69 #xd9 #x8e #x94 #x9b #x1e #x87 #xe9 #xce #x55 #x28 #xdf
    #x8c #xa1 #x89 #x0d #xbf #xe6 #x42 #x68 #x41 #x99 #x2d #x0f #xb0 #x54 #xbb #x16))

(defparameter *aes-inv-sbox*
  #(#x52 #x09 #x6a #xd5 #x30 #x36 #xa5 #x38 #xbf #x40 #xa3 #x9e #x81 #xf3 #xd7 #xfb
    #x7c #xe3 #x39 #x82 #x9b #x2f #xff #x87 #x34 #x8e #x43 #x44 #xc4 #xde #xe9 #xcb
    #x54 #x7b #x94 #x32 #xa6 #xc2 #x23 #x3d #xee #x4c #x95 #x0b #x42 #xfa #xc3 #x4e
    #x08 #x2e #xa1 #x66 #x28 #xd9 #x24 #xb2 #x76 #x5b #xa2 #x49 #x6d #x8b #xd1 #x25
    #x72 #xf8 #xf6 #x64 #x86 #x68 #x98 #x16 #xd4 #xa4 #x5c #xcc #x5d #x65 #xb6 #x92
    #x6c #x70 #x48 #x50 #xfd #xed #xb9 #xda #x5e #x15 #x46 #x57 #xa7 #x8d #x9d #x84
    #x90 #xd8 #xab #x00 #x8c #xbc #xd3 #x0a #xf7 #xe4 #x58 #x05 #xb8 #xb3 #x45 #x06
    #xd0 #x2c #x1e #x8f #xca #x3f #x0f #x02 #xc1 #xaf #xbd #x03 #x01 #x13 #x8a #x6b
    #x3a #x91 #x11 #x41 #x4f #x67 #xdc #xea #x97 #xf2 #xcf #xce #xf0 #xb4 #xe6 #x73
    #x96 #xac #x74 #x22 #xe7 #xad #x35 #x85 #xe2 #xf9 #x37 #xe8 #x1c #x75 #xdf #x6e
    #x47 #xf1 #x1a #x71 #x1d #x29 #xc5 #x89 #x6f #xb7 #x62 #x0e #xaa #x18 #xbe #x1b
    #xfc #x56 #x3e #x4b #xc6 #xd2 #x79 #x20 #x9a #xdb #xc0 #xfe #x78 #xcd #x5a #xf4
    #x1f #xdd #xa8 #x33 #x88 #x07 #xc7 #x31 #xb1 #x12 #x10 #x59 #x27 #x80 #xec #x5f
    #x60 #x51 #x7f #xa9 #x19 #xb5 #x4a #x0d #x2d #xe5 #x7a #x9f #x93 #xc9 #x9c #xef
    #xa0 #xe0 #x3b #x4d #xae #x2a #xf5 #xb0 #xc8 #xeb #xbb #x3c #x83 #x53 #x99 #x61
    #x17 #x2b #x04 #x7e #xba #x77 #xd6 #x26 #xe1 #x69 #x14 #x63 #x55 #x21 #x0c #x7d))

(defparameter *aes-rcon*
  #(#x01 #x02 #x04 #x08 #x10 #x20 #x40 #x80 #x1b #x36))

;;; ---- Fast-path tables (T-tables) -------------------------------------------
;;; A byte-typed copy of the S-box for the hot encryption path (declared type
;;; lets SBCL emit a direct byte load instead of a boxed general-vector ref).
(declaim (type (simple-array (unsigned-byte 8) (256)) +aes-sbox-b+))
(defparameter +aes-sbox-b+
  (let ((a (make-array 256 :element-type '(unsigned-byte 8))))
    (dotimes (i 256) (setf (aref a i) (aref *aes-sbox* i)))
    a))

;;; Te0..Te3: the classic 4-table AES encryption tables (Rijndael).  Each entry
;;; is SubBytes(x) spread through one MixColumns column, with ShiftRows folded
;;; into which table each state byte indexes.  Words are big-endian packed:
;;; (b0<<24)|(b1<<16)|(b2<<8)|b3 with b0 = row 0.  Built from the S-box + xtime
;;; so they are provably the same transform as the byte-oriented reference.
(declaim (type (simple-array (unsigned-byte 32) (256)) +te0+ +te1+ +te2+ +te3+))
(macrolet ((pack (a b c d)
             `(logior (ash ,a 24) (ash ,b 16) (ash ,c 8) ,d)))
  (labels ((xt (x) (let ((r (logand (ash x 1) #xff)))
                     (if (> x #x7f) (logxor r #x1b) r))))
    (let ((te0 (make-array 256 :element-type '(unsigned-byte 32)))
          (te1 (make-array 256 :element-type '(unsigned-byte 32)))
          (te2 (make-array 256 :element-type '(unsigned-byte 32)))
          (te3 (make-array 256 :element-type '(unsigned-byte 32))))
      (dotimes (x 256)
        (let* ((s (aref *aes-sbox* x))
               (s2 (xt s))
               (s3 (logxor s2 s)))
          ;; column pattern [2,1,1,3] and its rotations
          (setf (aref te0 x) (pack s2 s  s  s3)
                (aref te1 x) (pack s3 s2 s  s)
                (aref te2 x) (pack s  s3 s2 s)
                (aref te3 x) (pack s  s  s3 s2))))
      (defparameter +te0+ te0)
      (defparameter +te1+ te1)
      (defparameter +te2+ te2)
      (defparameter +te3+ te3))))

(defun aes-expand-key-128 (key)
  "Expand a 16-byte key to 176 bytes (11 round keys)."
  (let ((expanded (make-array 176 :element-type '(unsigned-byte 8))))
    (dotimes (i 16) (setf (aref expanded i) (aref key i)))
    (let ((i 16))
      (dotimes (round 10)
        (let ((t0 (aref *aes-sbox* (aref expanded (- i 3))))
              (t1 (aref *aes-sbox* (aref expanded (- i 2))))
              (t2 (aref *aes-sbox* (aref expanded (- i 1))))
              (t3 (aref *aes-sbox* (aref expanded (- i 4)))))
          (setf (aref expanded i) (logxor (aref expanded (- i 16)) t0 (aref *aes-rcon* round)))
          (setf (aref expanded (+ i 1)) (logxor (aref expanded (- i 15)) t1))
          (setf (aref expanded (+ i 2)) (logxor (aref expanded (- i 14)) t2))
          (setf (aref expanded (+ i 3)) (logxor (aref expanded (- i 13)) t3))
          (incf i 4))
        (dotimes (j 3)
          (setf (aref expanded i) (logxor (aref expanded (- i 16)) (aref expanded (- i 4))))
          (setf (aref expanded (+ i 1)) (logxor (aref expanded (- i 15)) (aref expanded (- i 3))))
          (setf (aref expanded (+ i 2)) (logxor (aref expanded (- i 14)) (aref expanded (- i 2))))
          (setf (aref expanded (+ i 3)) (logxor (aref expanded (- i 13)) (aref expanded (- i 1))))
          (incf i 4))))
    expanded))

(defun aes-expand-key-256 (key)
  "Expand a 32-byte key to 240 bytes (15 round keys)."
  (let ((expanded (make-array 240 :element-type '(unsigned-byte 8))))
    (dotimes (i 32) (setf (aref expanded i) (aref key i)))
    (let ((i 32))
      (dotimes (round 7)
        (let ((t0 (aref *aes-sbox* (aref expanded (- i 3))))
              (t1 (aref *aes-sbox* (aref expanded (- i 2))))
              (t2 (aref *aes-sbox* (aref expanded (- i 1))))
              (t3 (aref *aes-sbox* (aref expanded (- i 4)))))
          (setf (aref expanded i) (logxor (aref expanded (- i 32)) t0 (aref *aes-rcon* round)))
          (setf (aref expanded (+ i 1)) (logxor (aref expanded (- i 31)) t1))
          (setf (aref expanded (+ i 2)) (logxor (aref expanded (- i 30)) t2))
          (setf (aref expanded (+ i 3)) (logxor (aref expanded (- i 29)) t3))
          (incf i 4))
        (dotimes (j 3)
          (setf (aref expanded i) (logxor (aref expanded (- i 32)) (aref expanded (- i 4))))
          (setf (aref expanded (+ i 1)) (logxor (aref expanded (- i 31)) (aref expanded (- i 3))))
          (setf (aref expanded (+ i 2)) (logxor (aref expanded (- i 30)) (aref expanded (- i 2))))
          (setf (aref expanded (+ i 3)) (logxor (aref expanded (- i 29)) (aref expanded (- i 1))))
          (incf i 4))
        (when (< i 240)
          (setf (aref expanded i) (logxor (aref expanded (- i 32))
                                          (aref *aes-sbox* (aref expanded (- i 4)))))
          (setf (aref expanded (+ i 1)) (logxor (aref expanded (- i 31))
                                                (aref *aes-sbox* (aref expanded (- i 3)))))
          (setf (aref expanded (+ i 2)) (logxor (aref expanded (- i 30))
                                                (aref *aes-sbox* (aref expanded (- i 2)))))
          (setf (aref expanded (+ i 3)) (logxor (aref expanded (- i 29))
                                                (aref *aes-sbox* (aref expanded (- i 1)))))
          (incf i 4)
          (dotimes (j 3)
            (when (< i 240)
              (setf (aref expanded i) (logxor (aref expanded (- i 32)) (aref expanded (- i 4))))
              (setf (aref expanded (+ i 1)) (logxor (aref expanded (- i 31)) (aref expanded (- i 3))))
              (setf (aref expanded (+ i 2)) (logxor (aref expanded (- i 30)) (aref expanded (- i 2))))
              (setf (aref expanded (+ i 3)) (logxor (aref expanded (- i 29)) (aref expanded (- i 1))))
              (incf i 4))))))
    expanded))

(defun aes-xtime (x)
  "Multiply by 2 in GF(2^8), reduction polynomial x^8+x^4+x^3+x+1."
  (let ((result (logand (ash x 1) #xff)))
    (if (> x #x7f) (logxor result #x1b) result)))

(defun aes-mul (a b)
  "Multiply two bytes in GF(2^8)."
  (let ((result 0))
    (dotimes (i 8)
      (when (logbitp i b) (setf result (logxor result a)))
      (setf a (aes-xtime a)))
    result))

(defun aes-encrypt-block (block expanded-key &optional (rounds 10))
  "Encrypt a 16-byte block with an expanded key. Returns a fresh 16-byte array.
Fast T-table (Rijndael 4-table) implementation: each of the (rounds-1) full
rounds is 16 table lookups + XORs; the final round is 16 S-box lookups."
  (declare (optimize (speed 3) (safety 0)) (type fixnum rounds))
  (let ((blk block) (ek expanded-key)
        (te0 +te0+) (te1 +te1+) (te2 +te2+) (te3 +te3+) (sb +aes-sbox-b+))
    (declare (type (simple-array (unsigned-byte 8) (*)) blk ek)
             (type (simple-array (unsigned-byte 32) (256)) te0 te1 te2 te3)
             (type (simple-array (unsigned-byte 8) (256)) sb))
    (macrolet ((w (arr off)
                 `(the (unsigned-byte 32)
                       (logior (ash (aref ,arr ,off) 24)
                               (ash (aref ,arr (+ ,off 1)) 16)
                               (ash (aref ,arr (+ ,off 2)) 8)
                               (aref ,arr (+ ,off 3)))))
               (b0 (x) `(ldb (byte 8 24) ,x))
               (b1 (x) `(ldb (byte 8 16) ,x))
               (b2 (x) `(ldb (byte 8 8) ,x))
               (b3 (x) `(logand ,x #xff)))
      (let ((s0 (logxor (w blk 0) (w ek 0)))
            (s1 (logxor (w blk 4) (w ek 4)))
            (s2 (logxor (w blk 8) (w ek 8)))
            (s3 (logxor (w blk 12) (w ek 12)))
            (koff 16))
        (declare (type (unsigned-byte 32) s0 s1 s2 s3) (type fixnum koff))
        (dotimes (round (- rounds 1))
          (let ((n0 (logxor (aref te0 (b0 s0)) (aref te1 (b1 s1))
                            (aref te2 (b2 s2)) (aref te3 (b3 s3)) (w ek koff)))
                (n1 (logxor (aref te0 (b0 s1)) (aref te1 (b1 s2))
                            (aref te2 (b2 s3)) (aref te3 (b3 s0)) (w ek (+ koff 4))))
                (n2 (logxor (aref te0 (b0 s2)) (aref te1 (b1 s3))
                            (aref te2 (b2 s0)) (aref te3 (b3 s1)) (w ek (+ koff 8))))
                (n3 (logxor (aref te0 (b0 s3)) (aref te1 (b1 s0))
                            (aref te2 (b2 s1)) (aref te3 (b3 s2)) (w ek (+ koff 12)))))
            (declare (type (unsigned-byte 32) n0 n1 n2 n3))
            (setf s0 n0 s1 n1 s2 n2 s3 n3 koff (+ koff 16))))
        ;; Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns).
        (let ((out (make-array 16 :element-type '(unsigned-byte 8)))
              (r0 (logxor (logior (ash (aref sb (b0 s0)) 24) (ash (aref sb (b1 s1)) 16)
                                  (ash (aref sb (b2 s2)) 8) (aref sb (b3 s3))) (w ek koff)))
              (r1 (logxor (logior (ash (aref sb (b0 s1)) 24) (ash (aref sb (b1 s2)) 16)
                                  (ash (aref sb (b2 s3)) 8) (aref sb (b3 s0))) (w ek (+ koff 4))))
              (r2 (logxor (logior (ash (aref sb (b0 s2)) 24) (ash (aref sb (b1 s3)) 16)
                                  (ash (aref sb (b2 s0)) 8) (aref sb (b3 s1))) (w ek (+ koff 8))))
              (r3 (logxor (logior (ash (aref sb (b0 s3)) 24) (ash (aref sb (b1 s0)) 16)
                                  (ash (aref sb (b2 s1)) 8) (aref sb (b3 s2))) (w ek (+ koff 12)))))
          (declare (type (unsigned-byte 32) r0 r1 r2 r3))
          (macrolet ((put (base word)
                       `(setf (aref out ,base) (b0 ,word)
                              (aref out (+ ,base 1)) (b1 ,word)
                              (aref out (+ ,base 2)) (b2 ,word)
                              (aref out (+ ,base 3)) (b3 ,word))))
            (put 0 r0) (put 4 r1) (put 8 r2) (put 12 r3))
          out)))))

(defun aes-decrypt-block (block expanded-key &optional (rounds 10))
  "Decrypt a 16-byte block with an expanded key. Returns a fresh 16-byte array."
  (let ((state (make-array 16 :element-type '(unsigned-byte 8))))
    (let ((round-key-offset (* rounds 16)))
      (dotimes (i 16)
        (setf (aref state i) (logxor (aref block i) (aref expanded-key (+ round-key-offset i))))))
    (dotimes (round (1- rounds))
      (let ((round-key-offset (* (- rounds 1 round) 16)))
        (let ((t1 (aref state 1)) (t5 (aref state 5)) (t9 (aref state 9)) (t13 (aref state 13))
              (t2 (aref state 2)) (t6 (aref state 6)) (t10 (aref state 10)) (t14 (aref state 14))
              (t3 (aref state 3)) (t7 (aref state 7)) (t11 (aref state 11)) (t15 (aref state 15)))
          (setf (aref state 1) t13 (aref state 5) t1 (aref state 9) t5 (aref state 13) t9)
          (setf (aref state 2) t10 (aref state 6) t14 (aref state 10) t2 (aref state 14) t6)
          (setf (aref state 3) t7 (aref state 7) t11 (aref state 11) t15 (aref state 15) t3))
        (dotimes (i 16) (setf (aref state i) (aref *aes-inv-sbox* (aref state i))))
        (dotimes (i 16)
          (setf (aref state i) (logxor (aref state i) (aref expanded-key (+ round-key-offset i)))))
        (dotimes (col 4)
          (let* ((c (* col 4))
                 (s0 (aref state c)) (s1 (aref state (+ c 1)))
                 (s2 (aref state (+ c 2))) (s3 (aref state (+ c 3))))
            (setf (aref state c)
                  (logxor (aes-mul #x0e s0) (aes-mul #x0b s1) (aes-mul #x0d s2) (aes-mul #x09 s3)))
            (setf (aref state (+ c 1))
                  (logxor (aes-mul #x09 s0) (aes-mul #x0e s1) (aes-mul #x0b s2) (aes-mul #x0d s3)))
            (setf (aref state (+ c 2))
                  (logxor (aes-mul #x0d s0) (aes-mul #x09 s1) (aes-mul #x0e s2) (aes-mul #x0b s3)))
            (setf (aref state (+ c 3))
                  (logxor (aes-mul #x0b s0) (aes-mul #x0d s1) (aes-mul #x09 s2) (aes-mul #x0e s3)))))))
    (let ((t1 (aref state 1)) (t5 (aref state 5)) (t9 (aref state 9)) (t13 (aref state 13))
          (t2 (aref state 2)) (t6 (aref state 6)) (t10 (aref state 10)) (t14 (aref state 14))
          (t3 (aref state 3)) (t7 (aref state 7)) (t11 (aref state 11)) (t15 (aref state 15)))
      (setf (aref state 1) t13 (aref state 5) t1 (aref state 9) t5 (aref state 13) t9)
      (setf (aref state 2) t10 (aref state 6) t14 (aref state 10) t2 (aref state 14) t6)
      (setf (aref state 3) t7 (aref state 7) t11 (aref state 11) t15 (aref state 15) t3))
    (dotimes (i 16) (setf (aref state i) (aref *aes-inv-sbox* (aref state i))))
    (dotimes (i 16)
      (setf (aref state i) (logxor (aref state i) (aref expanded-key i))))
    state))

(defun aes-128-encrypt-block (key block)
  (aes-encrypt-block block (aes-expand-key-128 key) 10))
(defun aes-256-encrypt-block (key block)
  (aes-encrypt-block block (aes-expand-key-256 key) 14))
(defun aes-128-decrypt-block (key block)
  (aes-decrypt-block block (aes-expand-key-128 key) 10))
(defun aes-256-decrypt-block (key block)
  (aes-decrypt-block block (aes-expand-key-256 key) 14))
