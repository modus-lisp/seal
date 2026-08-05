;;;; run.lisp — run the full seal check: crypto vectors + live interop.
;;;;
;;;;   sbcl --script inspect/run.lisp
;;;;
;;;; Exits non-zero if any vector or any live host fails.

(require :asdf)
(require :sb-bsd-sockets)
;; --script skips the user's init, so whatever normally puts these systems on
;; ASDF's search path isn't here.  Point it at this repo and at the sibling
;; natrium checkout the way conch's probes do.
(let* ((here (truename (or *load-pathname* *default-pathname-defaults*)))
       (root (make-pathname :directory (butlast (pathname-directory here)))))
  (push root asdf:*central-registry*)
  (let ((natrium (probe-file (merge-pathnames #p"../natrium/" root))))
    (when natrium (push natrium asdf:*central-registry*))))
(asdf:load-system :seal/test)

(in-package #:seal)
(let ((failures (+ (run-vectors) (run-negative-tests) (run-tls12) (run-live))))
  (sb-ext:exit :code (if (zerop failures) 0 1)))
