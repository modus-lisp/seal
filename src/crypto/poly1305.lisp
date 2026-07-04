;;;; poly1305.lisp — Poly1305 one-time authenticator (RFC 8439).

(in-package #:seal)

(defun poly1305-mac (key message)
  "Poly1305 MAC of MESSAGE under the 32-byte one-time KEY. Returns a 16-byte tag."
  (let* ((p (- (ash 1 130) 5))
         (r (let ((x 0)) (dotimes (i 16 x) (setf x (logior x (ash (aref key i) (* 8 i)))))))
         (s (let ((x 0)) (dotimes (i 16 x) (setf x (logior x (ash (aref key (+ 16 i)) (* 8 i)))))))
         (acc 0)
         (len (length message)))
    ;; clamp r
    (setf r (logand r #x0ffffffc0ffffffc0ffffffc0fffffff))
    (do ((i 0 (+ i 16)))
        ((>= i len))
      (let* ((blocklen (min 16 (- len i)))
             (n 0))
        (dotimes (j blocklen)
          (setf n (logior n (ash (aref message (+ i j)) (* 8 j)))))
        (setf n (logior n (ash 1 (* 8 blocklen))))
        (setf acc (mod (* (+ acc n) r) p))))
    (setf acc (logand (+ acc s) #xffffffffffffffffffffffffffffffff))
    (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
      (dotimes (i 16 out)
        (setf (aref out i) (logand (ash acc (* -8 i)) #xff))))))
