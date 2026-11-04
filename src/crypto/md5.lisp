;;;; md5.lisp — MD5 (RFC 1321) and HMAC-SHA1 (RFC 2104), pure Common Lisp.
;;;;
;;;; Legacy constructs, here for interop like sha1.lisp: TURN's long-term
;;;; credential key is MD5(user:realm:password) and STUN's MESSAGE-INTEGRITY is
;;;; HMAC-SHA1 (RFC 8489).  Not for new security use.

(in-package #:seal)

(declaim (type (simple-array (unsigned-byte 32) (64)) +md5-k+)
         (type (simple-array (unsigned-byte 8) (64)) +md5-s+))
(defparameter +md5-k+
  (make-array 64 :element-type '(unsigned-byte 32) :initial-contents
              '(#xd76aa478 #xe8c7b756 #x242070db #xc1bdceee #xf57c0faf #x4787c62a #xa8304613 #xfd469501
                #x698098d8 #x8b44f7af #xffff5bb1 #x895cd7be #x6b901122 #xfd987193 #xa679438e #x49b40821
                #xf61e2562 #xc040b340 #x265e5a51 #xe9b6c7aa #xd62f105d #x02441453 #xd8a1e681 #xe7d3fbc8
                #x21e1cde6 #xc33707d6 #xf4d50d87 #x455a14ed #xa9e3e905 #xfcefa3f8 #x676f02d9 #x8d2a4c8a
                #xfffa3942 #x8771f681 #x6d9d6122 #xfde5380c #xa4beea44 #x4bdecfa9 #xf6bb4b60 #xbebfbc70
                #x289b7ec6 #xeaa127fa #xd4ef3085 #x04881d05 #xd9d4d039 #xe6db99e5 #x1fa27cf8 #xc4ac5665
                #xf4292244 #x432aff97 #xab9423a7 #xfc93a039 #x655b59c3 #x8f0ccc92 #xffeff47d #x85845dd1
                #x6fa87e4f #xfe2ce6e0 #xa3014314 #x4e0811a1 #xf7537e82 #xbd3af235 #x2ad7d2bb #xeb86d391)))
(defparameter +md5-s+
  (make-array 64 :element-type '(unsigned-byte 8) :initial-contents
              '(7 12 17 22 7 12 17 22 7 12 17 22 7 12 17 22
                5 9 14 20 5 9 14 20 5 9 14 20 5 9 14 20
                4 11 16 23 4 11 16 23 4 11 16 23 4 11 16 23
                6 10 15 21 6 10 15 21 6 10 15 21 6 10 15 21)))

(defun md5 (msg)
  "MD5 of byte vector MSG → fresh 16-byte digest."
  (let* ((msg (coerce msg '(simple-array (unsigned-byte 8) (*))))
         (n (length msg))
         (total (* 64 (ceiling (+ n 9) 64)))
         (p (make-array total :element-type '(unsigned-byte 8) :initial-element 0))
         (m (make-array 16 :element-type '(unsigned-byte 32)))
         (a0 #x67452301) (b0 #xefcdab89) (c0 #x98badcfe) (d0 #x10325476))
    (replace p msg)
    (setf (aref p n) #x80)
    (let ((bits (* 8 n)))                       ; the length, little-endian, in the last 8 bytes
      (dotimes (k 8) (setf (aref p (+ (- total 8) k)) (ldb (byte 8 (* 8 k)) bits))))
    (loop for off from 0 below total by 64 do
      (dotimes (i 16)
        (let ((o (+ off (* 4 i))))
          (setf (aref m i) (logior (aref p o) (ash (aref p (+ o 1)) 8)
                                   (ash (aref p (+ o 2)) 16) (ash (aref p (+ o 3)) 24)))))
      (let ((a a0) (b b0) (c c0) (d d0))
        (dotimes (i 64)
          (let ((f 0) (g 0))
            (cond ((< i 16) (setf f (logior (logand b c) (logand (logxor b #xffffffff) d)) g i))
                  ((< i 32) (setf f (logior (logand d b) (logand (logxor d #xffffffff) c))
                                  g (mod (+ (* 5 i) 1) 16)))
                  ((< i 48) (setf f (logxor b c d) g (mod (+ (* 3 i) 5) 16)))
                  (t (setf f (logxor c (logior b (logxor d #xffffffff))) g (mod (* 7 i) 16))))
            (let ((x (logand #xffffffff (+ f a (aref +md5-k+ i) (aref m g)))))
              (setf a d d c c b
                    b (logand #xffffffff (+ b (sha1-rol32 x (aref +md5-s+ i))))))))
        (setf a0 (logand #xffffffff (+ a0 a)) b0 (logand #xffffffff (+ b0 b))
              c0 (logand #xffffffff (+ c0 c)) d0 (logand #xffffffff (+ d0 d)))))
    (let ((out (make-array 16 :element-type '(unsigned-byte 8))) (i 0))
      (dolist (w (list a0 b0 c0 d0) out)
        (dotimes (k 4) (setf (aref out i) (ldb (byte 8 (* 8 k)) w)) (incf i))))))

(defun hmac-sha1 (key message)
  "HMAC-SHA1 (RFC 2104) of byte vectors KEY and MESSAGE → 20 bytes."
  (let* ((key (coerce key '(simple-array (unsigned-byte 8) (*))))
         (key (if (> (length key) 64) (sha1 key) key))
         (ipad (make-array 64 :element-type '(unsigned-byte 8) :initial-element #x36))
         (opad (make-array 64 :element-type '(unsigned-byte 8) :initial-element #x5c)))
    (dotimes (i (length key))
      (setf (aref ipad i) (logxor (aref ipad i) (aref key i))
            (aref opad i) (logxor (aref opad i) (aref key i))))
    (let ((s (sha1-init)))
      (sha1-update s ipad)
      (sha1-update s (coerce message '(simple-array (unsigned-byte 8) (*))))
      (let ((inner (sha1-final s)) (o (sha1-init)))
        (sha1-update o opad)
        (sha1-update o inner)
        (sha1-final o)))))
