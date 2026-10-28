;;;; stream.lisp — a Gray-stream wrapper presenting a TLS connection as an
;;;; ordinary bidirectional binary stream.

(in-package #:seal)

(defclass tls-stream (fundamental-binary-input-stream
                      fundamental-binary-output-stream)
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

(defun tls-stream-pending-p (stream)
  "True when reading STREAM can proceed without waiting: bytes left in its own
buffer, or the connection under it has input pending (INPUT-PENDING-P)."
  (with-slots (connection in-buffer in-pos) stream
    (or (and in-buffer (< in-pos (length in-buffer)))
        (input-pending-p connection))))

(defmethod stream-read-byte ((stream tls-stream))
  (if (%stream-fill stream)
      (with-slots (in-buffer in-pos) stream
        (prog1 (aref in-buffer in-pos) (incf in-pos)))
      :eof))

(defmethod stream-read-sequence ((stream tls-stream) seq &optional (start 0) end)
  ;; A record at a time, not a byte at a time: the per-byte path is a generic call and two slot
  ;; accesses per byte, and a relay's 4 KB event took seconds that way on a Pi.
  (let ((end (or end (length seq))) (i start))
    (loop while (< i end) do
      (unless (%stream-fill stream) (return))
      (with-slots (in-buffer in-pos) stream
        (let ((n (min (- end i) (- (length in-buffer) in-pos))))
          (replace seq in-buffer :start1 i :end1 (+ i n) :start2 in-pos)
          (incf i n)
          (incf in-pos n))))
    i))

(defmethod stream-write-byte ((stream tls-stream) byte)
  (with-slots (out-buffer) stream
    (vector-push-extend byte out-buffer))
  byte)

(defmethod stream-write-sequence ((stream tls-stream) seq &optional (start 0) end)
  (let ((end (or end (length seq))))
    (with-slots (out-buffer) stream
      (let* ((fp (fill-pointer out-buffer)) (need (+ fp (- end start))))
        (when (< (array-dimension out-buffer 0) need)
          (setf out-buffer (adjust-array out-buffer (max need (* 2 (array-dimension out-buffer 0))))))
        (setf (fill-pointer out-buffer) need)
        (replace out-buffer seq :start1 fp :start2 start :end2 end)))
    seq))

(defmethod stream-force-output ((stream tls-stream))
  (with-slots (connection out-buffer) stream
    (when (plusp (length out-buffer))
      (tls-send connection (copy-seq out-buffer))
      (setf (fill-pointer out-buffer) 0)))
  nil)

(defmethod stream-finish-output ((stream tls-stream))
  (stream-force-output stream))

(defmethod close ((stream tls-stream) &key abort)
  (unless abort (ignore-errors (stream-force-output stream)))
  (tls-close (tls-stream-connection stream))
  t)
