;;;; websocket.lisp — an RFC 6455 WebSocket client on seal's TLS.
;;;;
;;;; Lifted out of modus/proto/websocket.lisp, which had the only real
;;;; implementation in the workspace but could not be reached from a hosted Lisp:
;;;; it dialled through muerte.x86-pc.e1000, used modus's own TLS, and was not in
;;;; any ASDF system.  modus should be an SBCL-like OS that USES these libraries,
;;;; not a place they hide.
;;;;
;;;; The framing half is transport-independent and exported as such — BUILD-FRAME,
;;;; READ-FRAME, MASK — so a caller with its own sockets (modus on bare metal)
;;;; can keep the protocol and bring its own transport.  CONNECT is the hosted
;;;; convenience: seal for wss://, a plain socket for ws://.
;;;;
;;;; Four things are done differently from the original, all of them bugs there:
;;;;
;;;;   * The masking key comes from SECURE-RANDOM-BYTES, not CL:RANDOM.  RFC 6455
;;;;     s5.3 requires it to be unpredictable — masking exists to stop a client
;;;;     being coerced into emitting attacker-chosen bytes at a confused proxy,
;;;;     and a predictable mask defeats exactly that.  Same for the handshake key.
;;;;   * Sec-WebSocket-Accept is verified (s4.1).  Without it any server that says
;;;;     101 is believed, and the handshake stops proving the peer even read the
;;;;     key.
;;;;   * Text is UTF-8, not CHAR-CODE.  The original was latin-1 by accident, so
;;;;     any relay message with a non-ASCII character was silently corrupted.
;;;;   * Continuation frames are reassembled, and 64-bit lengths are read as 64
;;;;     bits rather than truncated to 32.

(defpackage #:seal.websocket
  (:use #:cl)
  (:nicknames #:seal.ws)
  (:export #:connect #:websocket #:websocket-p #:websocket-stream #:open-p
           #:send-text #:send-binary #:send-ping #:send-pong #:close-socket
           #:receive #:receive-text
           ;; the protocol half, for callers bringing their own transport
           #:build-frame #:read-frame #:handshake-request #:check-accept
           #:+text+ #:+binary+ #:+close+ #:+ping+ #:+pong+ #:+continuation+
           #:*user-agent* #:websocket-error #:websocket-error-code))

(in-package #:seal.websocket)

(defconstant +continuation+ #x0)
(defconstant +text+         #x1)
(defconstant +binary+       #x2)
(defconstant +close+        #x8)
(defconstant +ping+         #x9)
(defconstant +pong+         #xa)

(defparameter *user-agent* "seal.websocket/0.1")

;;; The fixed GUID from RFC 6455 s1.3 — concatenated with the client's key and
;;; hashed to produce the server's Sec-WebSocket-Accept.
(defparameter +ws-guid+ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

(define-condition websocket-error (error)
  ((text :initarg :text :initform "" :reader websocket-error-text)
   (code :initarg :code :initform nil :reader websocket-error-code))
  (:report (lambda (c s) (format s "seal.websocket: ~a" (websocket-error-text c)))))

(defun fail (fmt &rest args)
  (error 'websocket-error :text (apply #'format nil fmt args)))

(defstruct websocket stream host (state :open) (fragments nil) (frag-opcode nil)
  ;; Duplex use is the normal case — a read loop on one thread, sends from
  ;; another (that is exactly how an event-driven client is built on top of this).
  ;; Two writers interleaving frames would corrupt the stream, and on TLS would
  ;; desynchronise the record layer, so every send takes this.
  (send-lock (sb-thread:make-mutex :name "seal-ws-send")))

(defun open-p (ws) (eq (websocket-state ws) :open))

(defun utf8 (s) (seal:utf8-encode s))
(defun from-utf8 (b) (seal:utf8-decode (coerce b '(vector (unsigned-byte 8)))))

;;; ---- framing (transport-independent) ----------------------------------------

(defun build-frame (opcode payload &key (fin t))
  "One client frame.  Client frames are ALWAYS masked (RFC 6455 s5.1), with a
   fresh unpredictable key per frame."
  (let* ((payload (coerce payload '(vector (unsigned-byte 8))))
         (n (length payload))
         (mask (seal:secure-random-bytes 4))
         (header (cond ((<= n 125) 2) ((<= n 65535) 4) (t 10)))
         (frame (make-array (+ header 4 n) :element-type '(unsigned-byte 8)))
         (p 0))
    (flet ((put (b) (setf (aref frame p) (logand b #xff)) (incf p)))
      (put (logior (if fin #x80 0) (logand opcode #x0f)))
      (cond ((<= n 125) (put (logior #x80 n)))
            ((<= n 65535) (put (logior #x80 126)) (put (ash n -8)) (put n))
            (t (put (logior #x80 127))
               ;; A full 64-bit length, most significant byte first.
               (loop for shift from 56 downto 0 by 8 do (put (ash n (- shift))))))
      (dotimes (i 4) (put (aref mask i)))
      (dotimes (i n) (put (logxor (aref payload i) (aref mask (mod i 4))))))
    frame))

(defun read-exactly (stream n)
  (let ((buf (make-array n :element-type '(unsigned-byte 8))))
    (let ((got (read-sequence buf stream)))
      (unless (= got n) (fail "short read (~d of ~d)" got n)))
    buf))

(defun be-integer (bytes)
  (let ((v 0)) (loop for b across bytes do (setf v (logior (ash v 8) b))) v))

(defun read-frame (stream)
  "Read one frame.  Returns (values FIN OPCODE PAYLOAD)."
  (let* ((h (read-exactly stream 2))
         (b0 (aref h 0)) (b1 (aref h 1))
         (fin (logbitp 7 b0))
         (opcode (logand b0 #x0f))
         (masked (logbitp 7 b1))
         (n (logand b1 #x7f)))
    (cond ((= n 126) (setf n (be-integer (read-exactly stream 2))))
          ((= n 127) (setf n (be-integer (read-exactly stream 8)))))
    (let ((mask (when masked (read-exactly stream 4)))
          (payload (if (plusp n) (read-exactly stream n)
                       (make-array 0 :element-type '(unsigned-byte 8)))))
      ;; A server MUST NOT mask (s5.1), but unmask rather than reject: being
      ;; strict here buys nothing and breaks against sloppy servers.
      (when mask
        (dotimes (i n) (setf (aref payload i) (logxor (aref payload i) (aref mask (mod i 4))))))
      (values fin opcode payload))))

;;; ---- handshake ---------------------------------------------------------------

(defun handshake-request (host path key &key (port nil))
  (with-output-to-string (s)
    (format s "GET ~a HTTP/1.1~c~c" path #\Return #\Linefeed)
    (format s "Host: ~a~@[:~d~]~c~c" host port #\Return #\Linefeed)
    (format s "User-Agent: ~a~c~c" *user-agent* #\Return #\Linefeed)
    (format s "Upgrade: websocket~c~c" #\Return #\Linefeed)
    (format s "Connection: Upgrade~c~c" #\Return #\Linefeed)
    (format s "Sec-WebSocket-Key: ~a~c~c" key #\Return #\Linefeed)
    (format s "Sec-WebSocket-Version: 13~c~c" #\Return #\Linefeed)
    (format s "~c~c" #\Return #\Linefeed)))

(defun expected-accept (key)
  "base64(SHA1(key + GUID)) — what the server must echo back (RFC 6455 s4.1)."
  (seal:base64-encode (seal:sha1 (utf8 (concatenate 'string key +ws-guid+)))))

(defun check-accept (key header-value)
  (unless (and header-value (string= header-value (expected-accept key)))
    (fail "bad Sec-WebSocket-Accept: server did not prove it read our key"))
  t)

(defun crlf-line (stream)
  (let ((out (make-array 64 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for b = (read-byte stream nil :eof) do
      (cond ((eq b :eof) (return (when (plusp (length out)) (map 'string #'code-char out))))
            ((= b 13))
            ((= b 10) (return (map 'string #'code-char out)))
            (t (vector-push-extend b out))))))

(defun read-handshake-response (stream key)
  (let ((status-line (or (crlf-line stream) (fail "no handshake response"))))
    (let* ((sp (or (position #\Space status-line) (fail "bad status line ~s" status-line)))
           (code (or (ignore-errors (parse-integer status-line :start (1+ sp) :end (+ sp 4)))
                     (fail "bad status line ~s" status-line)))
           (headers (loop for line = (crlf-line stream)
                          while (and line (plusp (length line)))
                          for c = (position #\: line)
                          when c collect (cons (string-downcase (string-trim " " (subseq line 0 c)))
                                               (string-trim " " (subseq line (1+ c)))))))
      (unless (= code 101) (fail "expected 101 Switching Protocols, got ~d" code))
      (check-accept key (cdr (assoc "sec-websocket-accept" headers :test #'string=)))
      headers)))

;;; ---- connect -----------------------------------------------------------------

(defun parse-ws-url (url)
  "ws://host[:port]/path or wss://... -> (values host port path securep)."
  (let* ((sep (or (search "://" url) (fail "not a ws URL: ~s" url)))
         (scheme (string-downcase (subseq url 0 sep)))
         (rest (subseq url (+ sep 3)))
         (slash (position #\/ rest))
         (authority (if slash (subseq rest 0 slash) rest))
         (path (if slash (subseq rest slash) "/"))
         (colon (position #\: authority))
         (host (if colon (subseq authority 0 colon) authority))
         (securep (string= scheme "wss"))
         (port (if colon (parse-integer authority :start (1+ colon)) (if securep 443 80))))
    (unless (member scheme '("ws" "wss") :test #'string=)
      (fail "unsupported scheme ~s" scheme))
    (values host port path securep)))

(defun connect (url &key (timeout 30) (verify t))
  "Open a WebSocket to URL (ws:// or wss://).  wss rides seal's TLS; VERIFY is
   seal's certificate policy and defaults to full verification."
  (declare (ignore timeout))
  (multiple-value-bind (host port path securep) (parse-ws-url url)
    (let* ((stream (if securep
                       (seal:make-tls-stream
                        (seal:connect host port :verify verify :alpn nil))
                       (let ((sock (make-instance 'sb-bsd-sockets:inet-socket
                                                  :type :stream :protocol :tcp)))
                         (sb-bsd-sockets:socket-connect
                          sock (sb-bsd-sockets:host-ent-address
                                (sb-bsd-sockets:get-host-by-name host))
                          port)
                         (sb-bsd-sockets:socket-make-stream
                          sock :input t :output t :element-type '(unsigned-byte 8)
                          :buffering :full))))
           (key (seal:base64-encode (seal:secure-random-bytes 16))))
      (write-sequence (utf8 (handshake-request host path key
                                               :port (unless (or (and securep (= port 443))
                                                                 (and (not securep) (= port 80)))
                                                       port)))
                      stream)
      (finish-output stream)
      (read-handshake-response stream key)
      (make-websocket :stream stream :host host))))

;;; ---- messages ----------------------------------------------------------------

(defun send-frame (ws opcode payload)
  (unless (open-p ws) (fail "socket is ~(~a~)" (websocket-state ws)))
  (sb-thread:with-recursive-lock ((websocket-send-lock ws))
    (write-sequence (build-frame opcode payload) (websocket-stream ws))
    (finish-output (websocket-stream ws))))

(defun send-text (ws string) (send-frame ws +text+ (utf8 string)))
(defun send-binary (ws bytes) (send-frame ws +binary+ bytes))
(defun send-ping (ws &optional (data #())) (send-frame ws +ping+ data))
(defun send-pong (ws &optional (data #())) (send-frame ws +pong+ data))

(defun close-socket (ws &key (code 1000) (reason ""))
  (when (open-p ws)
    (let* ((r (utf8 reason))
           (payload (make-array (+ 2 (length r)) :element-type '(unsigned-byte 8))))
      (setf (aref payload 0) (ldb (byte 8 8) code)
            (aref payload 1) (ldb (byte 8 0) code))
      (replace payload r :start1 2)
      (ignore-errors (send-frame ws +close+ payload)))
    (setf (websocket-state ws) :closing))
  (ignore-errors (close (websocket-stream ws)))
  (setf (websocket-state ws) :closed)
  t)

(defun receive (ws)
  "Next application message.  Returns (values PAYLOAD OPCODE), or NIL once closed.

   Control frames are handled here rather than handed up: a ping is answered
   immediately and a close is honoured, because a caller that has to remember to
   do that will eventually forget and the connection will die quietly."
  (loop
    (unless (member (websocket-state ws) '(:open :closing)) (return nil))
    (multiple-value-bind (fin opcode payload)
        (handler-case (read-frame (websocket-stream ws))
          (error () (setf (websocket-state ws) :closed) (return nil)))
      (cond
        ((= opcode +ping+) (ignore-errors (send-pong ws payload)))
        ((= opcode +pong+) nil)
        ((= opcode +close+)
         (setf (websocket-state ws) :closing)
         (close-socket ws)
         (return nil))
        ((= opcode +continuation+)
         (push payload (websocket-fragments ws))
         (when fin (return (finish-fragments ws))))
        (t
         (if fin
             (return (values payload opcode))
             (progn (setf (websocket-fragments ws) (list payload)
                          (websocket-frag-opcode ws) opcode))))))))

(defun finish-fragments (ws)
  (let* ((parts (reverse (websocket-fragments ws)))
         (n (reduce #'+ parts :key #'length))
         (out (make-array n :element-type '(unsigned-byte 8)))
         (p 0))
    (dolist (part parts) (replace out part :start1 p) (incf p (length part)))
    (setf (websocket-fragments ws) nil)
    (values out (or (websocket-frag-opcode ws) +binary+))))

(defun receive-text (ws)
  "Next message as a string, or NIL at close."
  (multiple-value-bind (payload opcode) (receive ws)
    (when payload
      (if (= opcode +binary+) payload (from-utf8 payload)))))
