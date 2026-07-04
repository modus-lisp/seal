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

;;; Specific certificate-validation failures. All inherit from
;;; TLS-CERTIFICATE-ERROR (itself a TLS-VERIFY-ERROR), so callers can catch
;;; broadly or discriminate on the exact failure. The point of every one of
;;; these is to FAIL CLOSED: a bad certificate must raise, never connect.

(define-condition tls-certificate-error (tls-verify-error) ())

(define-condition tls-certificate-untrusted-error (tls-certificate-error) ()
  (:documentation "The chain does not terminate at a trusted root CA."))

(define-condition tls-certificate-expired-error (tls-certificate-error) ()
  (:documentation "A certificate in the chain is outside its validity window."))

(define-condition tls-certificate-hostname-error (tls-certificate-error) ()
  (:documentation "No presented name matches the requested hostname."))

(define-condition tls-certificate-bad-signature-error (tls-certificate-error) ()
  (:documentation "A signature in the chain (or CertificateVerify) did not verify."))
