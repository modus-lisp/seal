;;;; sha1.lisp — SHA-1 (FIPS 180-4), pure Common Lisp.
;;;;
;;;; A legacy hash: cryptographically broken for collision resistance, kept here
;;;; (the classical-crypto home, not the modern natrium floor) for interop —
;;;; legacy X.509 / TLS 1.0-1.1 constructs, and callers like cairn that need
;;;; git's content-address hash.  Not for new security use.
;;;;
;;;; Block-streaming: the compression function reads 64-byte blocks straight from
;;;; the caller's buffer (no padded copy of the whole message), and the
;;;; incremental init/update/final API lets a caller hash several pieces — e.g.
;;;; git's "<type> <size>\0" header then the content — without concatenating
;;;; them.  That keeps allocation flat (a small reusable state), which matters
;;;; when hashing gigabytes across many threads.

(in-package #:seal)

(declaim (inline sha1-rol32))
(defun sha1-rol32 (x n)
  (declare (type (unsigned-byte 32) x) (type (integer 0 31) n)
           (optimize (speed 3) (safety 0)))
  (logand #xffffffff (logior (ash x n) (ash x (- n 32)))))

(deftype sha1-h () '(simple-array (unsigned-byte 32) (5)))
(deftype sha1-w () '(simple-array (unsigned-byte 32) (80)))
(deftype u8vec () '(simple-array (unsigned-byte 8) (*)))

(defun sha1-compress (h w src off)
  "Fold the 64-byte block at SRC[OFF..OFF+64) into the state vector H, using W as
   scratch."
  (declare (type sha1-h h) (type sha1-w w) (type u8vec src) (type fixnum off)
           (optimize (speed 3) (safety 0)))
  (dotimes (i 16)
    (let ((j (+ off (* i 4))))
      (declare (type fixnum j))
      (setf (aref w i) (logior (ash (aref src j) 24) (ash (aref src (+ j 1)) 16)
                               (ash (aref src (+ j 2)) 8) (aref src (+ j 3))))))
  (loop for i of-type fixnum from 16 below 80 do
    (setf (aref w i) (sha1-rol32 (logxor (aref w (- i 3)) (aref w (- i 8))
                                         (aref w (- i 14)) (aref w (- i 16))) 1)))
  (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3)) (e (aref h 4)))
    (declare (type (unsigned-byte 32) a b c d e))
    (dotimes (i 80)
      (multiple-value-bind (f k)
          (cond ((< i 20) (values (logior (logand b c) (logand (logxor b #xffffffff) d)) #x5a827999))
                ((< i 40) (values (logxor b c d) #x6ed9eba1))
                ((< i 60) (values (logior (logand b c) (logand b d) (logand c d)) #x8f1bbcdc))
                (t (values (logxor b c d) #xca62c1d6)))
        (declare (type (unsigned-byte 32) f k))
        (let ((tmp (logand #xffffffff (+ (sha1-rol32 a 5) f e k (aref w i)))))
          (setf e d  d c  c (sha1-rol32 b 30)  b a  a tmp))))
    (setf (aref h 0) (logand #xffffffff (+ (aref h 0) a))
          (aref h 1) (logand #xffffffff (+ (aref h 1) b))
          (aref h 2) (logand #xffffffff (+ (aref h 2) c))
          (aref h 3) (logand #xffffffff (+ (aref h 3) d))
          (aref h 4) (logand #xffffffff (+ (aref h 4) e)))))

(defstruct (sha1-state (:conc-name s1-) (:constructor %make-sha1-state))
  (h (make-array 5 :element-type '(unsigned-byte 32) :initial-contents
       '(#x67452301 #xefcdab89 #x98badcfe #x10325476 #xc3d2e1f0)) :type sha1-h)
  (w (make-array 80 :element-type '(unsigned-byte 32)) :type sha1-w)
  (block (make-array 64 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (64)))
  (fill 0 :type fixnum)
  (len 0 :type unsigned-byte))

(defun sha1-init () "A fresh streaming SHA-1 state." (%make-sha1-state))

(defun sha1-update (state src &optional (start 0) (end (length src)))
  "Feed the bytes SRC[START..END) into STATE.  Full 64-byte blocks are folded
   straight from SRC; a trailing partial block is buffered for next time."
  (declare (type sha1-state state) (type fixnum start end)
           (optimize (speed 3) (safety 1)))
  (let ((src (if (typep src 'u8vec) src (coerce src 'u8vec)))
        (block (s1-block state)) (h (s1-h state)) (w (s1-w state)))
    (incf (s1-len state) (- end start))
    (let ((fill (s1-fill state)))
      (declare (type fixnum fill))
      (when (plusp fill)                                   ; top up a buffered block
        (loop while (and (< start end) (< fill 64)) do
          (setf (aref block fill) (aref src start)) (incf fill) (incf start))
        (when (= fill 64) (sha1-compress h w block 0) (setf fill 0)))
      (loop while (<= (+ start 64) end) do                ; whole blocks, no copy
        (sha1-compress h w src start) (incf start 64))
      (loop while (< start end) do                        ; buffer the remainder
        (setf (aref block fill) (aref src start)) (incf fill) (incf start))
      (setf (s1-fill state) fill)))
  state)

(defun sha1-final (state)
  "Finish STATE and return its 20-byte big-endian digest."
  (declare (type sha1-state state))
  (let ((block (s1-block state)) (h (s1-h state)) (w (s1-w state))
        (fill (s1-fill state)) (bitlen (* (s1-len state) 8)))
    (declare (type fixnum fill))
    (setf (aref block fill) #x80) (incf fill)
    (when (> fill 56)                                     ; no room for the length: flush
      (loop while (< fill 64) do (setf (aref block fill) 0) (incf fill))
      (sha1-compress h w block 0) (setf fill 0))
    (loop while (< fill 56) do (setf (aref block fill) 0) (incf fill))
    (dotimes (i 8) (setf (aref block (+ 56 i)) (logand #xff (ash bitlen (* -8 (- 7 i))))))
    (sha1-compress h w block 0)
    (let ((out (make-array 20 :element-type '(unsigned-byte 8))))
      (dotimes (i 5)
        (let ((v (aref h i)) (o (* i 4)))
          (setf (aref out o) (logand #xff (ash v -24))
                (aref out (+ o 1)) (logand #xff (ash v -16))
                (aref out (+ o 2)) (logand #xff (ash v -8))
                (aref out (+ o 3)) (logand #xff v))))
      out)))

(defun sha1 (msg)
  "SHA-1 of byte vector MSG → fresh 20-byte big-endian digest."
  (let ((s (sha1-init))) (sha1-update s msg) (sha1-final s)))
