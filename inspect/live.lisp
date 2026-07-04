;;;; live.lisp — live TLS 1.3 interop against real HTTPS servers.

(in-package #:seal)

(defparameter *live-hosts*
  '("example.com" "www.google.com" "en.wikipedia.org"
    "news.ycombinator.com" "www.cloudflare.com" "github.com"))

(defun http-get-status (conn host)
  "Send a GET and return the first response line."
  (tls-send conn (format nil "GET / HTTP/1.1~c~cHost: ~a~c~cConnection: close~c~c~c~c"
                         #\return #\newline host #\return #\newline
                         #\return #\newline #\return #\newline))
  (let ((resp (tls-recv conn)))
    (when resp
      (let* ((text (map 'string #'code-char resp))
             (eol (or (position #\return text) (position #\newline text) (length text))))
        (subseq text 0 eol)))))

(defun leaf-sig-summary (conn)
  "Describe the leaf certificate's signature algorithm (proves which family the
chain validation exercised)."
  (let ((leaf (first (tls-connection-peer-certificates conn))))
    (if leaf
        (format nil "~a/~a" (certificate-sig-scheme leaf) (certificate-sig-hash leaf))
        "?")))

(defun run-live (&key (hosts *live-hosts*) (verify t))
  "Full-validation (:verify T by default) handshake + GET against each host.
Returns the number of failures. Reports each leaf's signature algorithm so it is
clear that both RSA and ECDSA chains were validated."
  (let ((failures 0))
    (format t "~%== Live TLS 1.3 + FULL certificate validation (:verify t) ==~%")
    (dolist (host hosts)
      (handler-case
          (let ((conn (connect host 443 :verify verify)))
            (unwind-protect
                 (let ((status (http-get-status conn host)))
                   (if (and status (search "HTTP/1.1" status))
                       (format t "  OK   ~22a ~24a sig=~18a ~a~%"
                               host (tls-connection-cipher conn)
                               (leaf-sig-summary conn) status)
                       (progn (incf failures)
                              (format t "  FAIL ~22a no status line~%" host))))
              (tls-close conn)))
        (error (e)
          (incf failures)
          (format t "  FAIL ~22a ~a~%" host e))))
    (format t "==== live: ~d host(s), ~d failed ====~%" (length hosts) failures)
    failures))
