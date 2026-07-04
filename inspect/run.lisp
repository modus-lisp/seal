;;;; run.lisp — run the full seal check: crypto vectors + live interop.
;;;;
;;;;   sbcl --script inspect/run.lisp
;;;;
;;;; Exits non-zero if any vector or any live host fails.

(require :asdf)
(require :sb-bsd-sockets)
(let* ((here (truename (or *load-pathname* *default-pathname-defaults*)))
       (root (make-pathname :directory (butlast (pathname-directory here)))))
  (push root asdf:*central-registry*))
(asdf:load-system :seal/test)

(in-package #:seal)
(let ((failures (+ (run-vectors) (run-live))))
  (sb-ext:exit :code (if (zerop failures) 0 1)))
