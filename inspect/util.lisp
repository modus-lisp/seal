;;;; util.lisp — small helpers for the inspect/ test drivers.
(in-package #:seal)

(defun hx (v)
  "Lowercase hex string of a byte vector."
  (with-output-to-string (s)
    (loop for x across v do (format s "~(~2,'0x~)" x))))

(defun unhex (str)
  "Parse a hex string into a byte vector."
  (let* ((str (remove #\Space str))
         (n (/ (length str) 2))
         (out (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n out)
      (setf (aref out i) (parse-integer str :start (* i 2) :end (+ (* i 2) 2)
                                        :radix 16)))))

(defun ascii (s)
  "Byte vector of a Latin-1 string."
  (map '(vector (unsigned-byte 8)) #'char-code s))

(defvar *pass* 0)
(defvar *fail* 0)

(defun check (name got want)
  (let ((g (if (stringp got) got (hx got)))
        (w (if (stringp want) (string-downcase want) (hx want))))
    (if (string= g w)
        (progn (incf *pass*) (format t "  PASS ~a~%" name))
        (progn (incf *fail*)
               (format t "  FAIL ~a~%    got:  ~a~%    want: ~a~%" name g w)))))
