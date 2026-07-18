;;;; gcm.lisp — AES-GCM authenticated encryption (NIST SP 800-38D).

(in-package #:seal)

(defun gcm-shift-right (block)
  "Shift a 128-bit block right by one bit, in place."
  (let ((carry 0))
    (dotimes (i 16)
      (let ((new-carry (logand (aref block i) 1)))
        (setf (aref block i) (logior (ash (aref block i) -1) (ash carry 7)))
        (setf carry new-carry))))
  block)

(defun gcm-mul (x y)
  "Multiply two 16-byte blocks in GF(2^128). Returns a fresh 16-byte array."
  (let ((z (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (v (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16) (setf (aref v i) (aref y i)))
    (dotimes (i 16)
      (let ((xi (aref x i)))
        (dotimes (j 8)
          (when (logbitp (- 7 j) xi)
            (dotimes (k 16) (setf (aref z k) (logxor (aref z k) (aref v k)))))
          (let ((lsb (logand (aref v 15) 1)))
            (gcm-shift-right v)
            (when (= lsb 1) (setf (aref v 0) (logxor (aref v 0) #xe1)))))))
    z))

;;; ---- Fast table-based GHASH ------------------------------------------------
;;; GF(2^128) with GCM's reflected bit convention (reduction R = 0xE1<<120).
;;; A 128-bit block is held as two big-endian 64-bit words: HI = bytes 0..7
;;; (byte 0 in the top byte), LO = bytes 8..15.  This reproduces the reference
;;; `gcm-mul'/`gcm-shift-right' bit-for-bit (cross-checked over random inputs).

;;; +gcm-rem8+ is H-independent: rem8[r] is the reduction correction that
;;; results from shifting the low byte `r' out during a multiply-by-alpha^8
;;; (eight applications of the one-bit right shift with reduction).
(declaim (type (simple-array (unsigned-byte 64) (256)) +gcm-rem8+))
(defparameter +gcm-rem8+
  (let ((rem (make-array 256 :element-type '(unsigned-byte 64) :initial-element 0)))
    (dotimes (r 256)
      (let ((chi 0) (clo r))
        (dotimes (i 8)
          (let* ((carry (logand clo 1))
                 (nlo (logior (ash clo -1) (ash (logand chi 1) 63)))
                 (nhi (ash chi -1)))
            (when (= carry 1) (setf nhi (logxor nhi #xe100000000000000)))
            (setf chi nhi clo nlo)))
        (setf (aref rem r) chi)))
    rem))

(defun %gcm-make-table (h)
  "Build the per-H 256-entry byte table: T[b] = f(b)*H, where f(b) sums
alpha^k over the set bits of b (bit 7 -> alpha^0 ... bit 0 -> alpha^7), matching
GCM's bit order.  Returns (values THI TLO), each (simple-array (unsigned-byte 64))."
  (declare (optimize (speed 3) (safety 0))
           (type (simple-array (unsigned-byte 8) (*)) h))
  (let ((thi (make-array 256 :element-type '(unsigned-byte 64) :initial-element 0))
        (tlo (make-array 256 :element-type '(unsigned-byte 64) :initial-element 0))
        (hh 0) (hl 0))
    (declare (type (simple-array (unsigned-byte 64) (256)) thi tlo)
             (type (unsigned-byte 64) hh hl))
    (dotimes (i 8) (setf hh (logior (ash hh 8) (aref h i))))
    (dotimes (i 8) (setf hl (logior (ash hl 8) (aref h (+ 8 i)))))
    ;; single-bit entries: index (128>>k) holds H*alpha^k
    (let ((chi hh) (clo hl))
      (declare (type (unsigned-byte 64) chi clo))
      (dotimes (k 8)
        (let ((idx (ash 128 (- k))))
          (setf (aref thi idx) chi (aref tlo idx) clo))
        (let* ((carry (logand clo 1))
               (nlo (logior (ash clo -1) (ash (logand chi 1) 63)))
               (nhi (ash chi -1)))
          (when (= carry 1) (setf nhi (logxor nhi #xe100000000000000)))
          (setf chi nhi clo nlo))))
    ;; fill the rest by XOR of already-computed sub-values (Shoup's trick)
    (loop for b of-type fixnum from 1 below 256 do
      (let ((lb (logand b (- b))))
        (unless (= lb b)
          (let ((rest (logxor b lb)))
            (setf (aref thi b) (logxor (aref thi lb) (aref thi rest))
                  (aref tlo b) (logxor (aref tlo lb) (aref tlo rest)))))))
    (values thi tlo)))

(defun gcm-ghash (h data)
  "GHASH over DATA (a multiple of 16 bytes) with hash subkey H.
Table-driven GF(2^128) multiply: per block, X = (Y ^ block); Y := X*H is
evaluated by Horner over the 16 bytes of X, one 256-entry table lookup plus a
multiply-by-alpha^8 (byte shift + reduction table) per byte."
  (declare (optimize (speed 3) (safety 0))
           (type (simple-array (unsigned-byte 8) (*)) data))
  (multiple-value-bind (thi tlo) (%gcm-make-table h)
    (declare (type (simple-array (unsigned-byte 64) (256)) thi tlo))
    (let ((yhi 0) (ylo 0) (rem +gcm-rem8+) (len (length data)))
      (declare (type (unsigned-byte 64) yhi ylo)
               (type (simple-array (unsigned-byte 64) (256)) rem)
               (type fixnum len))
      (do ((i 0 (+ i 16)))
          ((>= i len))
        (declare (type fixnum i))
        ;; X = Y xor block
        (let ((bh 0) (bl 0))
          (declare (type (unsigned-byte 64) bh bl))
          (dotimes (j 8) (setf bh (logior (ash bh 8) (aref data (+ i j)))))
          (dotimes (j 8) (setf bl (logior (ash bl 8) (aref data (+ i j 8)))))
          (setf yhi (logxor yhi bh) ylo (logxor ylo bl)))
        ;; acc := X * H  via Horner in base alpha^8, bytes 15 downto 0
        (let ((ah 0) (al 0))
          (declare (type (unsigned-byte 64) ah al))
          (loop for p of-type fixnum from 15 downto 0 do
            ;; acc := acc * alpha^8
            (let ((r (logand al #xff)))
              (declare (type (unsigned-byte 8) r))
              (setf al (logand (logior (ash al -8) (ash (logand ah #xff) 56))
                               #xffffffffffffffff)
                    ah (logxor (ash ah -8) (aref rem r))))
            ;; acc := acc xor T[byte p of X]
            (let ((xp (if (< p 8)
                          (logand (ash yhi (* -8 (- 7 p))) #xff)
                          (logand (ash ylo (* -8 (- 15 p))) #xff))))
              (declare (type (unsigned-byte 8) xp))
              (setf ah (logxor ah (aref thi xp))
                    al (logxor al (aref tlo xp)))))
          (setf yhi ah ylo al)))
      ;; serialise Y (hi||lo) big-endian to 16 bytes
      (let ((y (make-array 16 :element-type '(unsigned-byte 8))))
        (dotimes (i 8) (setf (aref y i) (logand (ash yhi (* -8 (- 7 i))) #xff)))
        (dotimes (i 8) (setf (aref y (+ 8 i)) (logand (ash ylo (* -8 (- 7 i))) #xff)))
        y))))

(defun gcm-inc32 (counter)
  "Increment the low 32-bit counter of a 16-byte counter block, in place."
  (let ((b (1+ (aref counter 15))))
    (if (< b 256)
        (setf (aref counter 15) b)
        (progn
          (setf (aref counter 15) 0
                b (1+ (aref counter 14)))
          (if (< b 256)
              (setf (aref counter 14) b)
              (progn
                (setf (aref counter 14) 0
                      b (1+ (aref counter 13)))
                (if (< b 256)
                    (setf (aref counter 13) b)
                    (progn
                      (setf (aref counter 13) 0
                            b (logand (1+ (aref counter 12)) #xff))
                      (setf (aref counter 12) b))))))))
  counter)

(defun %gcm-build-ghash-data (aad ciphertext)
  "Assemble AAD || pad || C || pad || len64(AAD) || len64(C)."
  (let* ((aad-len (length aad))
         (ct-len (length ciphertext))
         (aad-padded (* 16 (ceiling aad-len 16)))
         (ct-padded (* 16 (ceiling ct-len 16)))
         (data (make-array (+ aad-padded ct-padded 16)
                           :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i aad-len) (setf (aref data i) (aref aad i)))
    (dotimes (i ct-len) (setf (aref data (+ aad-padded i)) (aref ciphertext i)))
    (let ((off (+ aad-padded ct-padded))
          (aad-bits (* aad-len 8))
          (ct-bits (* ct-len 8)))
      (dotimes (i 8)
        (setf (aref data (+ off i)) (logand (ash aad-bits (* -8 (- 7 i))) #xff)))
      (dotimes (i 8)
        (setf (aref data (+ off 8 i)) (logand (ash ct-bits (* -8 (- 7 i))) #xff))))
    data))

(defun %gcm-ctr (expanded-key rounds j0 input)
  "AES counter-mode XOR of INPUT, starting from counter J0+1."
  (let ((out (make-array (length input) :element-type '(unsigned-byte 8)))
        (counter (make-array 16 :element-type '(unsigned-byte 8)))
        (in-len (length input)))
    (dotimes (i 16) (setf (aref counter i) (aref j0 i)))
    (do ((i 0 (+ i 16)))
        ((>= i in-len))
      (gcm-inc32 counter)
      (let ((ks (aes-encrypt-block counter expanded-key rounds)))
        (dotimes (j 16)
          (when (< (+ i j) in-len)
            (setf (aref out (+ i j)) (logxor (aref input (+ i j)) (aref ks j)))))))
    out))

;;; Key-schedule cache: TLS/DTLS reuse the same key across many records, so
;;; expanding it (and deriving the GHASH subkey H) once and reusing it avoids
;;; that per-record cost.  The cache holds an immutable snapshot list so a read
;;; always sees a consistent (key . expanded . rounds . H) tuple even under
;;; concurrent writers.
(defvar *gcm-key-cache* nil
  "Most recent (KEY-COPY EXPANDED ROUNDS H) tuple, or NIL.")

(defun %gcm-prepare-key (key)
  "Return (values EXPANDED ROUNDS H) for KEY, caching the last one used."
  (let ((c *gcm-key-cache*))
    (if (and c (equalp (the (simple-array (unsigned-byte 8) (*)) (first c)) key))
        (values (second c) (third c) (fourth c))
        (let* ((key-len (length key))
               (expanded (if (= key-len 16) (aes-expand-key-128 key) (aes-expand-key-256 key)))
               (rounds (if (= key-len 16) 10 14))
               (h (aes-encrypt-block
                   (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
                   expanded rounds)))
          (setf *gcm-key-cache* (list (copy-seq key) expanded rounds h))
          (values expanded rounds h)))))

(defun aes-gcm-encrypt (key nonce plaintext aad)
  "AES-GCM encrypt. KEY 16/32 bytes, NONCE 12 bytes. Returns (ciphertext . tag)."
  (multiple-value-bind (expanded-key rounds h) (%gcm-prepare-key key)
   (let* ((j0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i 12) (setf (aref j0 i) (aref nonce i)))
    (setf (aref j0 15) 1)
    (let* ((ciphertext (%gcm-ctr expanded-key rounds j0 plaintext))
           (s (gcm-ghash h (%gcm-build-ghash-data aad ciphertext)))
           (j0-enc (aes-encrypt-block j0 expanded-key rounds)))
      (dotimes (i 16) (setf (aref s i) (logxor (aref s i) (aref j0-enc i))))
      (cons ciphertext s)))))

(defun aes-gcm-decrypt (key nonce ciphertext aad tag)
  "AES-GCM decrypt. Returns plaintext, or NIL if the tag does not verify."
  (multiple-value-bind (expanded-key rounds h) (%gcm-prepare-key key)
   (let* ((j0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i 12) (setf (aref j0 i) (aref nonce i)))
    (setf (aref j0 15) 1)
    (let* ((s (gcm-ghash h (%gcm-build-ghash-data aad ciphertext)))
           (j0-enc (aes-encrypt-block j0 expanded-key rounds))
           (diff 0))
      (dotimes (i 16) (setf (aref s i) (logxor (aref s i) (aref j0-enc i))))
      ;; constant-time-ish tag comparison
      (dotimes (i 16) (setf diff (logior diff (logxor (aref s i) (aref tag i)))))
      (unless (zerop diff) (return-from aes-gcm-decrypt nil))
      (%gcm-ctr expanded-key rounds j0 ciphertext)))))
