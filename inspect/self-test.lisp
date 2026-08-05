;;;; self-test.lisp — the seal self-test: crypto vectors + one live fetch.
;;;;
;;;; Run via ASDF:
;;;;   (asdf:test-system :seal)
;;;; or directly:
;;;;   sbcl --non-interactive --eval '(require :asdf)' \
;;;;        --eval '(push #p"/path/to/seal/" asdf:*central-registry*)' \
;;;;        --eval '(asdf:test-system :seal)'

(in-package #:seal)

(defun run-self-test ()
  "Run the crypto vectors and a single live handshake. Signals an error on any
failure so ASDF:TEST-SYSTEM reports it."
  (let* ((crypto-failures (run-vectors))
         (negative-failures (run-negative-tests))
         ;; The live hosts all speak TLS 1.3, so without this the 1.2 key
         ;; exchange is never run at all.  It serves against loopback and skips
         ;; itself, loudly, where there is no openssl to serve with.
         (tls12-failures
           (handler-case (run-tls12)
             (error (e)
               (format t "~%TLS 1.2 check errored: ~a~%" e)
               1)))
         (live-failures
           (handler-case (run-live :hosts '("example.com"))
             (error (e)
               (format t "~%live fetch errored: ~a~%" e)
               1))))
    (format t "~%======== self-test: ~d crypto, ~d negative, ~d tls1.2, ~d live failure(s) ========~%"
            crypto-failures negative-failures tls12-failures live-failures)
    (when (plusp (+ crypto-failures negative-failures tls12-failures live-failures))
      (error "seal self-test failed"))
    t))
