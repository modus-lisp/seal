;;;; conditions.lisp — seal error conditions.

(in-package #:seal)

(define-condition tls-error (error)
  ((message :initarg :message :initform nil :reader tls-error-message))
  (:report (lambda (c stream)
             (format stream "TLS error: ~a" (tls-error-message c)))))

(define-condition tls-alert (tls-error)
  ((level :initarg :level :initform nil :reader tls-alert-level)
   (description :initarg :description :initform nil :reader tls-alert-description))
  (:report (lambda (c stream)
             (format stream "TLS alert: level ~a, description ~a"
                     (tls-alert-level c) (tls-alert-description c)))))

(define-condition tls-verify-error (tls-error)
  ()
  (:report (lambda (c stream)
             (format stream "TLS certificate verification failed: ~a"
                     (tls-error-message c)))))
