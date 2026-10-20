;;;; trust-store.lisp — seal.http's *TRUST-STORE* reaches seal:connect, on every path.
;;;;
;;;; A program that must trust a CA beyond the system bundle sets *trust-store*, and the
;;;; setting is only worth something if every https request in seal.http hands it to
;;;; seal:connect.  There are two such paths -- the direct socket and a *DIAL* carrier --
;;;; and a regression in either would make a build silently trust the system bundle alone
;;;; (or, worse, silently trust nothing it was told to).
;;;;
;;;; There is no TLS server here to verify against, and the fixtures in negatives.lisp are
;;;; certificates without keys.  So this records the trust store each call is given, by
;;;; encapsulating seal:connect, and lets the connect itself fail.  That is the wiring under
;;;; test; the verification it feeds is negatives.lisp's job.

(in-package #:seal)

(defvar *tsp-seen* :unset "The :trust-store of the most recent seal:connect call.")
(defvar *tsp-calls* 0 "How many seal:connect calls were made.")

(defun %tsp-record (orig host port &rest args &key (trust-store :absent) &allow-other-keys)
  (setf *tsp-seen* trust-store)
  (incf *tsp-calls*)
  (apply orig host port args))

(defun %tsp-attempt (thunk)
  "Run THUNK, which is expected to fail at connect; the failure is the point."
  (handler-case (funcall thunk) (error () nil)))

(defun run-trust-store-tests ()
  "Run the *trust-store* wiring checks.  Returns the number of failures."
  (let ((pass 0) (fail 0))
    (flet ((ok (name got expect)
             (if (equalp got expect)
                 (progn (incf pass) (format t "  PASS ~a~%" name))
                 (progn (incf fail) (format t "  FAIL ~a~%       got    ~s~%       expect ~s~%"
                                            name got expect)))))
      (sb-int:encapsulate 'connect 'trust-store-probe #'%tsp-record)
      (unwind-protect
           (let* ((store (make-trust-store-from-pem ""))
                  (refused "https://127.0.0.1:9/")
                  (no-dial (lambda (h p tm) (declare (ignore h p tm))
                             (values (make-string-input-stream "") (lambda () nil)))))
             (format t "~&== *trust-store* reaches seal:connect~%")
             (let ((seal.http:*dial* nil))
               (let ((seal.http:*trust-store* :system))
                 (%tsp-attempt (lambda () (seal.http:http-get refused)))
                 (ok "direct path, default :system" *tsp-seen* :system))
               (let ((seal.http:*trust-store* store))
                 (%tsp-attempt (lambda () (seal.http:http-get refused)))
                 (ok "direct path, a TRUST-STORE object is passed through" (eq *tsp-seen* store) t))
               (let ((seal.http:*trust-store* #p"/nonexistent/ca.pem"))
                 (%tsp-attempt (lambda () (seal.http:http-get refused)))
                 (ok "direct path, a PEM pathname is passed through" *tsp-seen* #p"/nonexistent/ca.pem")))
             (let ((seal.http:*dial* no-dial)
                   (seal.http:*trust-store* store))
               (%tsp-attempt (lambda () (seal.http:http-get refused)))
               (ok "dial path, the trust store still reaches connect" (eq *tsp-seen* store) t))
             (let ((seal.http:*dial* nil)
                   (seal.http:*trust-store* :system))
               (setf *tsp-seen* :unset)
               (%tsp-attempt (lambda () (seal.http:http-get "http://127.0.0.1:9/")))
               (ok "plain http makes no TLS connect, so nothing is recorded" *tsp-seen* :unset)))
        (sb-int:unencapsulate 'connect 'trust-store-probe)))
    (format t "~&==== *trust-store*: ~d passed, ~d failed ====~%" pass fail)
    fail))
