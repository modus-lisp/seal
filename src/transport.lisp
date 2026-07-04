;;;; transport.lisp — the byte transport under TLS.
;;;;
;;;; TLS is transport-agnostic: a connection holds three closures — send, recv,
;;;; close — bundled in a TRANSPORT struct. The default backend here speaks TCP
;;;; over SBCL's own sb-bsd-sockets. A different backend (e.g. a bare-metal TCP
;;;; stack) only has to provide the same three closures.

(in-package #:seal)

(defstruct (transport (:constructor %make-transport))
  sender      ; (lambda (byte-vector) -> t/nil)   push bytes to the peer
  receiver    ; (lambda () -> byte-vector | nil)   pull up-to-N bytes, nil on EOF/timeout
  closer)     ; (lambda () -> nil)                 release the connection

(defun transport-send (transport bytes)
  "Send BYTES (a byte vector) over TRANSPORT. Returns non-nil on success."
  (funcall (transport-sender transport) bytes))

(defun transport-recv (transport)
  "Receive the next chunk of bytes, or NIL on timeout / end of stream."
  (funcall (transport-receiver transport)))

(defun transport-close (transport)
  "Close TRANSPORT."
  (funcall (transport-closer transport)))

(defun make-socket-transport (host port &key (timeout 30))
  "Open a TCP connection to HOST:PORT and wrap it as a TRANSPORT.
HOST may be a name or a dotted-quad string. TIMEOUT is the per-recv timeout in
seconds."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                               :type :stream :protocol :tcp))
        (address (%resolve host)))
    (handler-case
        (progn
          (sb-bsd-sockets:socket-connect socket address port)
          (let ((fd (sb-bsd-sockets:socket-file-descriptor socket)))
            (%make-transport
             :sender
             (lambda (bytes)
               (let ((buf (coerce bytes '(simple-array (unsigned-byte 8) (*)))))
                 (sb-bsd-sockets:socket-send socket buf (length buf))
                 t))
             :receiver
             (lambda ()
               ;; Wait up to TIMEOUT seconds for the socket to become readable,
               ;; then pull whatever bytes are available.
               (if (sb-sys:wait-until-fd-usable fd :input timeout)
                   (let ((buf (make-array 16384 :element-type '(unsigned-byte 8))))
                     (handler-case
                         (multiple-value-bind (data len)
                             (sb-bsd-sockets:socket-receive socket buf nil)
                           (declare (ignore data))
                           (if (and len (plusp len)) (subseq buf 0 len) nil))
                       (sb-bsd-sockets:socket-error () nil)))
                   nil))                            ; timeout
             :closer
             (lambda () (ignore-errors (sb-bsd-sockets:socket-close socket))))))
      (error (e)
        (ignore-errors (sb-bsd-sockets:socket-close socket))
        (error 'tls-error :message (format nil "connect to ~a:~a failed: ~a"
                                           host port e))))))

(defun %resolve (host)
  "Resolve HOST to a 4-byte IPv4 address vector."
  (or (%parse-dotted-quad host)
      (handler-case
          (sb-bsd-sockets:host-ent-address (sb-bsd-sockets:get-host-by-name host))
        (error ()
          (error 'tls-error :message (format nil "DNS resolution failed for ~a" host))))))

(defun %parse-dotted-quad (str)
  "Parse \"a.b.c.d\" into #(a b c d), or NIL if it is not a dotted quad."
  (when (stringp str)
    (let ((parts (loop with start = 0
                       for dot = (position #\. str :start start)
                       for end = (or dot (length str))
                       for tok = (ignore-errors (parse-integer str :start start :end end))
                       do (setf start (1+ end))
                       collect tok
                       until (null dot))))
      (when (and (= (length parts) 4)
                 (every (lambda (n) (and (integerp n) (<= 0 n 255))) parts))
        (make-array 4 :element-type '(unsigned-byte 8) :initial-contents parts)))))
