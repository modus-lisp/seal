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
  (let ((crypto-failures (run-vectors))
        (negative-failures (run-negative-tests))
        (live-failures
          (handler-case (run-live :hosts '("example.com"))
            (error (e)
              (format t "~%live fetch errored: ~a~%" e)
              1))))
    (format t "~%======== self-test: ~d crypto, ~d negative, ~d live failure(s) ========~%"
            crypto-failures negative-failures live-failures)
    (when (plusp (+ crypto-failures negative-failures live-failures))
      (error "seal self-test failed"))
    t))
