;;;; port.lisp — the few places seal would otherwise reach into one implementation.
;;;;
;;;; seal's promise is pure Common Lisp with one platform dependency (a socket library), and
;;;; that promise is what lets it run where there is no FFI.  Three things were quietly SBCL's:
;;;;
;;;;   * UTF-8 conversion went through SB-EXT.  It is replaced here by a codec in plain CL, so
;;;;     there is nothing left to port: the same code runs everywhere, with no conditional.
;;;;   * Gray streams came from SB-GRAY.  The protocol is the same on every implementation that
;;;;     has it, only the package differs, so packages.lisp imports the names from whichever
;;;;     package this implementation provides and the stream code uses them unqualified.
;;;;   * Waiting for a socket to become readable used SB-SYS.  This one is genuinely per
;;;;     implementation — there is no portable readiness primitive — so it is the single
;;;;     function below with a branch per implementation, rather than a conditional scattered
;;;;     through the transport.
;;;;
;;;; Threads are NOT abstracted.  seal's one mutex uses SB-THREAD, and modus provides an
;;;; SB-THREAD surface with the same operators, so that code already runs on both as written.

(in-package #:seal)

;;; ---- UTF-8, in plain CL ---------------------------------------------------------------

(defun utf8-encode (string)
  "STRING as UTF-8 octets."
  (let ((out (make-array (length string) :element-type '(unsigned-byte 8)
                                         :adjustable t :fill-pointer 0)))
    (loop for ch across string
          for c = (char-code ch)
          do (cond ((< c #x80) (vector-push-extend c out))
                   ((< c #x800)
                    (vector-push-extend (logior #xC0 (ash c -6)) out)
                    (vector-push-extend (logior #x80 (logand c #x3F)) out))
                   ((< c #x10000)
                    (vector-push-extend (logior #xE0 (ash c -12)) out)
                    (vector-push-extend (logior #x80 (logand (ash c -6) #x3F)) out)
                    (vector-push-extend (logior #x80 (logand c #x3F)) out))
                   (t
                    (vector-push-extend (logior #xF0 (ash c -18)) out)
                    (vector-push-extend (logior #x80 (logand (ash c -12) #x3F)) out)
                    (vector-push-extend (logior #x80 (logand (ash c -6) #x3F)) out)
                    (vector-push-extend (logior #x80 (logand c #x3F)) out))))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun utf8-decode (octets &key (start 0) end (replacement #\?))
  "OCTETS (START..END) decoded from UTF-8.  LENIENT: a malformed or truncated sequence becomes
   REPLACEMENT rather than an error, because the bytes come from a network peer and a bad one
   must degrade a string, not abort the read that produced it.  Overlong forms and surrogates
   are malformed and are replaced too, so the result is never a string no encoder could have
   produced."
  (let* ((end (or end (length octets)))
         (out (make-array (- end start) :element-type 'character
                                        :adjustable t :fill-pointer 0))
         (i start))
    (flet ((cont (k) (and (< k end) (= (logand (aref octets k) #xC0) #x80)
                          (logand (aref octets k) #x3F))))
      (loop while (< i end) do
        (let ((b (aref octets i)))
          (multiple-value-bind (code len)
              (cond ((< b #x80) (values b 1))
                    ((= (logand b #xE0) #xC0)
                     (let ((c1 (cont (+ i 1))))
                       (if c1 (values (logior (ash (logand b #x1F) 6) c1) 2) (values nil 1))))
                    ((= (logand b #xF0) #xE0)
                     (let ((c1 (cont (+ i 1))) (c2 (cont (+ i 2))))
                       (if (and c1 c2)
                           (values (logior (ash (logand b #x0F) 12) (ash c1 6) c2) 3)
                           (values nil 1))))
                    ((= (logand b #xF8) #xF0)
                     (let ((c1 (cont (+ i 1))) (c2 (cont (+ i 2))) (c3 (cont (+ i 3))))
                       (if (and c1 c2 c3)
                           (values (logior (ash (logand b #x07) 18) (ash c1 12) (ash c2 6) c3) 4)
                           (values nil 1))))
                    (t (values nil 1)))
            ;; reject what a well-formed encoder never emits: overlong forms, surrogates,
            ;; and anything past U+10FFFF
            (when (and code (or (and (= len 2) (< code #x80))
                                (and (= len 3) (< code #x800))
                                (and (= len 4) (< code #x10000))
                                (<= #xD800 code #xDFFF)
                                (> code #x10FFFF)))
              (setf code nil len 1))
            (vector-push-extend (if code (code-char code) replacement) out)
            (incf i len)))))
    (coerce out 'simple-string)))

;;; ---- waiting for a socket ---------------------------------------------------------------

(defun wait-readable (fd timeout)
  "Block until FD has input or TIMEOUT seconds pass.  True if readable, NIL on timeout.

   The only per-implementation function in seal.  On an implementation without a readiness
   primitive the answer is simply T -- the read that follows then blocks with no timeout of its
   own.  That is a real loss (a silent peer is waited for indefinitely rather than abandoned),
   and it is stated here rather than hidden: the fix is to give that implementation a branch."
  #+sbcl (sb-sys:wait-until-fd-usable fd :input timeout)
  #-sbcl (progn fd timeout t))
