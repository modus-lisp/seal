;;;; entropy.lisp — cryptographically secure random bytes.

(in-package #:seal)

(defun secure-random-bytes (n)
  "Return N random bytes from the OS CSPRNG (/dev/urandom).

Falls back to the Lisp PRNG only if /dev/urandom is unavailable; that fallback
is NOT cryptographically secure and is signalled by a warning."
  (let ((out (make-array n :element-type '(unsigned-byte 8))))
    (handler-case
        (with-open-file (s "/dev/urandom" :element-type '(unsigned-byte 8))
          (dotimes (i n out)
            (setf (aref out i) (read-byte s))))
      (error ()
        (warn "seal: /dev/urandom unavailable; using non-cryptographic PRNG")
        (dotimes (i n out)
          (setf (aref out i) (random 256)))))))
