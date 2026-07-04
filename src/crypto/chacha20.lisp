;;;; chacha20.lisp — ChaCha20 stream cipher (RFC 8439).

(in-package #:seal)

(declaim (inline rotl32))
(defun rotl32 (x n)
  (logand (logior (ash x n) (ash x (- n 32))) #xffffffff))

(defmacro %qr (st a b c d)
  `(progn
     (setf (aref ,st ,a) (logand (+ (aref ,st ,a) (aref ,st ,b)) #xffffffff))
     (setf (aref ,st ,d) (rotl32 (logxor (aref ,st ,d) (aref ,st ,a)) 16))
     (setf (aref ,st ,c) (logand (+ (aref ,st ,c) (aref ,st ,d)) #xffffffff))
     (setf (aref ,st ,b) (rotl32 (logxor (aref ,st ,b) (aref ,st ,c)) 12))
     (setf (aref ,st ,a) (logand (+ (aref ,st ,a) (aref ,st ,b)) #xffffffff))
     (setf (aref ,st ,d) (rotl32 (logxor (aref ,st ,d) (aref ,st ,a)) 8))
     (setf (aref ,st ,c) (logand (+ (aref ,st ,c) (aref ,st ,d)) #xffffffff))
     (setf (aref ,st ,b) (rotl32 (logxor (aref ,st ,b) (aref ,st ,c)) 7))))

(defun %u32le (bytes off)
  (logior (aref bytes off)
          (ash (aref bytes (+ off 1)) 8)
          (ash (aref bytes (+ off 2)) 16)
          (ash (aref bytes (+ off 3)) 24)))

(defun chacha20-block (key counter nonce)
  "Return the 64-byte ChaCha20 keystream block for KEY (32B), COUNTER (u32),
NONCE (12B)."
  (let ((s (make-array 16 :element-type '(unsigned-byte 32))))
    (setf (aref s 0) #x61707865 (aref s 1) #x3320646e
          (aref s 2) #x79622d32 (aref s 3) #x6b206574)
    (dotimes (i 8) (setf (aref s (+ 4 i)) (%u32le key (* i 4))))
    (setf (aref s 12) (logand counter #xffffffff))
    (dotimes (i 3) (setf (aref s (+ 13 i)) (%u32le nonce (* i 4))))
    (let ((w (make-array 16 :element-type '(unsigned-byte 32))))
      (replace w s)
      (dotimes (i 10)
        (%qr w 0 4 8 12) (%qr w 1 5 9 13) (%qr w 2 6 10 14) (%qr w 3 7 11 15)
        (%qr w 0 5 10 15) (%qr w 1 6 11 12) (%qr w 2 7 8 13) (%qr w 3 4 9 14))
      (let ((out (make-array 64 :element-type '(unsigned-byte 8))))
        (dotimes (i 16)
          (let ((v (logand (+ (aref w i) (aref s i)) #xffffffff)))
            (setf (aref out (* i 4)) (logand v #xff)
                  (aref out (+ (* i 4) 1)) (logand (ash v -8) #xff)
                  (aref out (+ (* i 4) 2)) (logand (ash v -16) #xff)
                  (aref out (+ (* i 4) 3)) (logand (ash v -24) #xff))))
        out))))

(defun chacha20-xor (key counter nonce data)
  "XOR DATA with the ChaCha20 keystream, starting at block COUNTER."
  (let* ((len (length data))
         (out (make-array len :element-type '(unsigned-byte 8))))
    (do ((i 0 (+ i 64))
         (blk counter (1+ blk)))
        ((>= i len) out)
      (let ((ks (chacha20-block key blk nonce)))
        (dotimes (j 64)
          (when (< (+ i j) len)
            (setf (aref out (+ i j)) (logxor (aref data (+ i j)) (aref ks j)))))))))
