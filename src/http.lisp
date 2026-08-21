;;;; http.lisp — an HTTP/1.1 client on seal's TLS.
;;;;
;;;; Kept OUT of the core :seal system on purpose.  seal is a TLS
;;;; implementation, and that is the file in this workspace you most want small
;;;; and readable; a socket for some other protocol should not have to carry an
;;;; HTTP parser.  :seal/http is where callers that do speak HTTP come to get it,
;;;; so the three hand-rolled clients this replaces (cairn's git transport,
;;;; skep's, and whatever cl-nostr was reaching to dexador for) can share one.
;;;;
;;;; What it deliberately does NOT do: cookies, charset decoding, and
;;;; Content-Encoding.  Those are browser concerns and weft.fetch already layers
;;;; them properly on top of exactly this shape.  Requests advertise
;;;; `Accept-Encoding: identity' so the body you get back is the body that was
;;;; sent — an API client wants bytes, not a decompressor dependency.

(defpackage #:seal.http
  (:use #:cl)
  (:export #:response #:response-p #:response-status #:response-headers
           #:response-body #:response-url
           #:request #:http-get #:get-string #:header
           #:parse-url #:url-scheme #:url-host #:url-port #:url-path
           #:*user-agent* #:*max-redirects* #:http-error #:http-error-status))

(in-package #:seal.http)

(defparameter *user-agent* "seal.http/0.1")
(defparameter *max-redirects* 5
  "How many 3xx hops REQUEST will follow before giving up.")

(define-condition http-error (error)
  ((status :initarg :status :reader http-error-status :initform nil)
   (text :initarg :text :initform "" :reader http-error-text))
  (:report (lambda (c s) (format s "seal.http: ~a~@[ (HTTP ~d)~]"
                                 (http-error-text c) (http-error-status c)))))

(defun fail (status fmt &rest args)
  (error 'http-error :status status :text (apply #'format nil fmt args)))

(defstruct response status headers body url)

(defun header (response-or-headers name)
  "Case-insensitive header lookup."
  (let ((headers (if (response-p response-or-headers)
                     (response-headers response-or-headers)
                     response-or-headers)))
    (cdr (assoc name headers :test #'string-equal))))

;;; ---- URLs -------------------------------------------------------------------

(defstruct (url (:constructor %make-url)) scheme host port path)

(defun parse-url (string)
  "Split STRING into scheme/host/port/path.  Defaults: https, port 443 (80 for
   http), path \"/\"."
  (let* ((sep (search "://" string))
         (scheme (string-downcase (if sep (subseq string 0 sep) "https")))
         (rest (if sep (subseq string (+ sep 3)) string))
         (slash (position #\/ rest))
         (authority (if slash (subseq rest 0 slash) rest))
         (path (if slash (subseq rest slash) "/"))
         ;; An IPv6 literal is bracketed, and its colons are not a port separator.
         (colon (if (and (plusp (length authority)) (char= (char authority 0) #\[))
                    (position #\: authority :start (or (position #\] authority) 0))
                    (position #\: authority)))
         (host (if colon (subseq authority 0 colon) authority))
         (port (if colon
                   (or (ignore-errors (parse-integer authority :start (1+ colon)))
                       (fail nil "bad port in ~s" string))
                   (if (string= scheme "http") 80 443))))
    (when (zerop (length host)) (fail nil "no host in ~s" string))
    (%make-url :scheme scheme :host host :port port :path path)))

(defun url-string (u)
  (format nil "~a://~a~@[:~d~]~a" (url-scheme u) (url-host u)
          (unless (or (and (string= (url-scheme u) "https") (= (url-port u) 443))
                      (and (string= (url-scheme u) "http") (= (url-port u) 80)))
            (url-port u))
          (url-path u)))

(defun merge-location (base location)
  "Resolve a Location header against the URL it came from: absolute, or rooted,
   or relative to the current directory."
  (cond
    ((search "://" location) (parse-url location))
    ((and (plusp (length location)) (char= (char location 0) #\/))
     (%make-url :scheme (url-scheme base) :host (url-host base)
                :port (url-port base) :path location))
    (t (let* ((path (url-path base))
              (dir (subseq path 0 (1+ (or (position #\/ path :from-end t) 0)))))
         (%make-url :scheme (url-scheme base) :host (url-host base)
                    :port (url-port base)
                    :path (concatenate 'string dir location))))))

;;; ---- wire I/O ---------------------------------------------------------------

(defun ascii (bytes) (map 'string #'code-char bytes))
(defun bytes (string) (sb-ext:string-to-octets string :external-format :utf-8))

(defun crlf-line (stream)
  "One CRLF-terminated line as a string, CRLF stripped; NIL at end of stream."
  (let ((out (make-array 64 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for b = (read-byte stream nil :eof) do
      (cond ((eq b :eof) (return (when (plusp (length out)) (ascii out))))
            ((= b 13))                                    ; CR: swallow
            ((= b 10) (return (ascii out)))                ; LF: end of line
            (t (vector-push-extend b out))))))

(defun read-headers (stream)
  (loop for line = (crlf-line stream)
        while (and line (plusp (length line)))
        for c = (position #\: line)
        when c
          collect (cons (string-downcase (string-trim " " (subseq line 0 c)))
                        (string-trim " " (subseq line (1+ c))))))

(defun read-n-bytes (stream n)
  (let ((buf (make-array n :element-type '(unsigned-byte 8))))
    (let ((got (read-sequence buf stream)))
      (when (< got n) (fail nil "short body (~d of ~d bytes)" got n)))
    buf))

(defun read-chunked-body (stream)
  (let ((out (make-array 4096 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop
      (let* ((line (crlf-line stream))
             (semi (and line (position #\; line)))
             (size (or (ignore-errors (parse-integer line :end semi :radix 16))
                       (fail nil "bad chunk size ~s" line))))
        (when (zerop size)
          (loop for l = (crlf-line stream) while (and l (plusp (length l))))  ; trailers
          (return))
        (let ((chunk (read-n-bytes stream size)))
          (loop for b across chunk do (vector-push-extend b out)))
        (crlf-line stream)))                              ; CRLF after each chunk
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun read-to-eof (stream)
  (let ((out (make-array 4096 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
        (buf (make-array 4096 :element-type '(unsigned-byte 8))))
    (loop for n = (read-sequence buf stream)
          while (plusp n)
          do (dotimes (i n) (vector-push-extend (aref buf i) out))
          while (= n (length buf)))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun open-stream (url)
  "A byte stream to URL's host: TLS for https, a plain socket for http."
  (if (string= (url-scheme url) "https")
      (let ((conn (seal:connect (url-host url) (url-port url))))
        (values (seal:make-tls-stream conn) conn))
      (let ((sock (make-instance 'sb-bsd-sockets:inet-socket
                                 :type :stream :protocol :tcp)))
        (sb-bsd-sockets:socket-connect
         sock (sb-bsd-sockets:host-ent-address
               (sb-bsd-sockets:get-host-by-name (url-host url)))
         (url-port url))
        (values (sb-bsd-sockets:socket-make-stream
                 sock :input t :output t :element-type '(unsigned-byte 8)
                 :buffering :full)
                nil))))

(defun one-request (method url headers body)
  (multiple-value-bind (stream conn) (open-stream url)
    (declare (ignore conn))
    (unwind-protect
         (let* ((req (append (list (cons "Host" (url-host url))
                                   (cons "User-Agent" *user-agent*)
                                   (cons "Accept" "*/*")
                                   ;; We hand back bytes, not a decompressor.
                                   (cons "Accept-Encoding" "identity")
                                   (cons "Connection" "close"))
                             headers
                             (when body
                               (list (cons "Content-Length"
                                           (princ-to-string (length body)))))))
                (head (with-output-to-string (s)
                        (format s "~a ~a HTTP/1.1~c~c" method (url-path url)
                                #\Return #\Linefeed)
                        (dolist (h req)
                          (format s "~a: ~a~c~c" (car h) (cdr h) #\Return #\Linefeed))
                        (format s "~c~c" #\Return #\Linefeed))))
           (write-sequence (bytes head) stream)
           (when body (write-sequence body stream))
           (finish-output stream)
           (let ((status-line (or (crlf-line stream) (fail nil "no response"))))
             (let* ((sp (or (position #\Space status-line)
                            (fail nil "bad status line ~s" status-line)))
                    (code (or (ignore-errors (parse-integer status-line :start (1+ sp)
                                                                        :end (+ sp 4)))
                              (fail nil "bad status line ~s" status-line)))
                    (hdrs (read-headers stream))
                    (te (cdr (assoc "transfer-encoding" hdrs :test #'string=)))
                    (cl (cdr (assoc "content-length" hdrs :test #'string=)))
                    ;; HEAD and 1xx/204/304 carry no body however they are framed.
                    (bodyless (or (string-equal method "HEAD")
                                  (= code 204) (= code 304) (< code 200)))
                    (payload (cond (bodyless #())
                                   ((and te (search "chunked" te)) (read-chunked-body stream))
                                   (cl (read-n-bytes stream (parse-integer cl)))
                                   (t (read-to-eof stream)))))
               (make-response :status code :headers hdrs :body payload
                              :url (url-string url)))))
      (ignore-errors (close stream)))))

;;; ---- the public API ---------------------------------------------------------

(defun request (method url &key headers body (max-redirects *max-redirects*))
  "Perform METHOD against URL, following up to MAX-REDIRECTS 3xx hops.  Returns a
   RESPONSE; RESPONSE-URL is where it finally landed.

   303, and 301/302 on a POST, become GETs without the body, which is what every
   client does in practice whatever the RFC once said.  307 and 308 preserve
   both."
  (let ((current (if (url-p url) url (parse-url url)))
        (method method)
        (body body))
    (loop for hop from 0 to max-redirects
          do (let* ((r (one-request method current headers body))
                    (code (response-status r))
                    (location (header r "location")))
               (cond
                 ((and (member code '(301 302 303 307 308)) location (< hop max-redirects))
                  (setf current (merge-location current location))
                  (when (or (= code 303)
                            (and (member code '(301 302)) (not (string-equal method "GET"))))
                    (setf method "GET" body nil)))
                 (t (return r))))
          finally (fail nil "too many redirects (~d)" max-redirects))))

(defun http-get (url &key headers)
  (request "GET" url :headers headers))

(defun get-string (url &key headers (external-format :utf-8))
  "GET URL and decode the body as text.  Signals HTTP-ERROR on a non-2xx status —
   a caller asking for a string wants the document, not a stringified error page."
  (let ((r (request "GET" url :headers headers)))
    (unless (<= 200 (response-status r) 299)
      (fail (response-status r) "GET ~a" (if (url-p url) (url-string url) url)))
    (sb-ext:octets-to-string (coerce (response-body r) '(vector (unsigned-byte 8)))
                             :external-format external-format)))
