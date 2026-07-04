;;;; stream.lisp — a Gray-stream wrapper presenting a TLS connection as an
;;;; ordinary bidirectional binary stream.

(in-package #:seal)

(defclass tls-stream (sb-gray:fundamental-binary-input-stream
                      sb-gray:fundamental-binary-output-stream)
  ((connection :initarg :connection :reader tls-stream-connection)
   (in-buffer :initform nil)
   (in-pos :initform 0)
   (out-buffer :initform (make-array 1024 :element-type '(unsigned-byte 8)
                                     :adjustable t :fill-pointer 0))))

(defun make-tls-stream (connection)
  "Wrap an established TLS-CONNECTION as a bidirectional binary stream."
  (make-instance 'tls-stream :connection connection))

(defun %stream-fill (stream)
  "Ensure the input buffer holds data. Returns NIL at end of stream."
  (with-slots (connection in-buffer in-pos) stream
    (when (or (null in-buffer) (>= in-pos (length in-buffer)))
      (let ((chunk (tls-recv connection)))
        (if (and chunk (plusp (length chunk)))
            (setf in-buffer chunk in-pos 0)
            (progn (setf in-buffer nil) (return-from %stream-fill nil)))))
    t))

(defmethod sb-gray:stream-read-byte ((stream tls-stream))
  (if (%stream-fill stream)
      (with-slots (in-buffer in-pos) stream
        (prog1 (aref in-buffer in-pos) (incf in-pos)))
      :eof))

(defmethod sb-gray:stream-read-sequence ((stream tls-stream) seq &optional (start 0) end)
  (let ((end (or end (length seq))))
    (loop for i from start below end do
      (let ((b (sb-gray:stream-read-byte stream)))
        (when (eq b :eof) (return-from sb-gray:stream-read-sequence i))
        (setf (elt seq i) b)))
    end))

(defmethod sb-gray:stream-write-byte ((stream tls-stream) byte)
  (with-slots (out-buffer) stream
    (vector-push-extend byte out-buffer))
  byte)

(defmethod sb-gray:stream-write-sequence ((stream tls-stream) seq &optional (start 0) end)
  (let ((end (or end (length seq))))
    (with-slots (out-buffer) stream
      (loop for i from start below end do
        (vector-push-extend (elt seq i) out-buffer)))
    seq))

(defmethod sb-gray:stream-force-output ((stream tls-stream))
  (with-slots (connection out-buffer) stream
    (when (plusp (length out-buffer))
      (tls-send connection (copy-seq out-buffer))
      (setf (fill-pointer out-buffer) 0)))
  nil)

(defmethod sb-gray:stream-finish-output ((stream tls-stream))
  (sb-gray:stream-force-output stream))

(defmethod close ((stream tls-stream) &key abort)
  (unless abort (ignore-errors (sb-gray:stream-force-output stream)))
  (tls-close (tls-stream-connection stream))
  t)
