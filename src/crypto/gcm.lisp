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

(defun %gcm-tables (h)
  "The multiplication tables GCM-GHASH builds from H, as a list: built once per key by
   %GCM-PREPARE-KEY rather than once per record."
  #+modus (multiple-value-list (%gcm-make-table-32 h))
  #-modus (multiple-value-list (%gcm-make-table h)))

(defun gcm-ghash (h data &optional tables)
  "GHASH over DATA (a multiple of 16 bytes) with hash subkey H.  On modus: %GCM-GHASH-32.
TABLES, if given, are (%GCM-TABLES H), so they are not rebuilt.
Table-driven GF(2^128) multiply: per block, X = (Y ^ block); Y := X*H is
evaluated by Horner over the 16 bytes of X, one 256-entry table lookup plus a
multiply-by-alpha^8 (byte shift + reduction table) per byte."
  (declare (optimize (speed 3) (safety 0))
           (type (simple-array (unsigned-byte 8) (*)) data))
  ;; modus: PCLMULQDQ where the runtime has it (it answers NIL where it does not), else the
  ;; 32-bit-limb GHASH, which stays in fixnums
  #+modus
  (when (fboundp 'modus.runtime::%ghash-update)
    (let ((state (make-array 48 :element-type '(unsigned-byte 8) :initial-element 0)))
      (replace state h)
      (dotimes (i 16) (setf (aref state (+ 32 i)) (- 15 i)))
      (when (modus.runtime::%ghash-update state data (length data))
        (return-from gcm-ghash (subseq state 16 32)))))
  #+modus (return-from gcm-ghash (%gcm-ghash-32 h data tables))
  (multiple-value-bind (thi tlo) (if tables (values-list tables) (%gcm-make-table h))
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

;;; ---- GHASH in 32-bit limbs, for a Lisp whose fixnums are narrower than 64 bits -------------
;;; The table-driven GHASH above keeps the 128-bit accumulator in two (UNSIGNED-BYTE 64) halves,
;;; free on SBCL and a BIGNUM per operation on modus, whose fixnums are 62 bits: measured on the
;;; Pi Zero, GHASH was 262 ms of every 1100-byte DTLS record (AES-CTR 4 ms), which capped a WebRTC
;;; data channel at ~4 KB/s.  The same algorithm on four 32-bit limbs (A3 most significant) stays
;;; in fixnums everywhere.  GCM-GHASH uses it on modus.

(defun %gcm-limbs-shr1 (a3 a2 a1 a0)
  "The 128-bit value A3:A2:A1:A0 times alpha (one right shift with GCM's reduction)."
  (let ((carry (logand a0 1)))
    (values (logxor (ash a3 -1) (if (= carry 1) #xe1000000 0))
            (logior (ash a2 -1) (ash (logand a3 1) 31))
            (logior (ash a1 -1) (ash (logand a2 1) 31))
            (logior (ash a0 -1) (ash (logand a1 1) 31)))))

(defparameter +gcm-rem8-32+
  ;; the top limb of r*alpha^8 for a byte r shifted out of the bottom: the reduction only ever
  ;; reaches the most significant 32 bits
  (let ((rem (make-array 256 :element-type '(unsigned-byte 32) :initial-element 0)))
    (dotimes (r 256 rem)
      (multiple-value-bind (a3 a2 a1 a0) (values 0 0 0 r)
        (dotimes (i 8) (multiple-value-setq (a3 a2 a1 a0) (%gcm-limbs-shr1 a3 a2 a1 a0)))
        (setf (aref rem r) a3)))))

(defun %gcm-make-table-32 (h)
  "As %GCM-MAKE-TABLE, in limbs: (values T3 T2 T1 T0), 256 (UNSIGNED-BYTE 32) entries each."
  (let ((t3 (make-array 256 :element-type '(unsigned-byte 32) :initial-element 0))
        (t2 (make-array 256 :element-type '(unsigned-byte 32) :initial-element 0))
        (t1 (make-array 256 :element-type '(unsigned-byte 32) :initial-element 0))
        (t0 (make-array 256 :element-type '(unsigned-byte 32) :initial-element 0)))
    (flet ((limb (k) (logior (ash (aref h k) 24) (ash (aref h (+ k 1)) 16)
                             (ash (aref h (+ k 2)) 8) (aref h (+ k 3)))))
      (let ((a3 (limb 0)) (a2 (limb 4)) (a1 (limb 8)) (a0 (limb 12)))
        (dotimes (k 8)
          (let ((idx (ash 128 (- k))))
            (setf (aref t3 idx) a3 (aref t2 idx) a2 (aref t1 idx) a1 (aref t0 idx) a0))
          (multiple-value-setq (a3 a2 a1 a0) (%gcm-limbs-shr1 a3 a2 a1 a0)))))
    (loop for b from 1 below 256 do
      (let ((lb (logand b (- b))))
        (unless (= lb b)
          (let ((rest (logxor b lb)))
            (setf (aref t3 b) (logxor (aref t3 lb) (aref t3 rest))
                  (aref t2 b) (logxor (aref t2 lb) (aref t2 rest))
                  (aref t1 b) (logxor (aref t1 lb) (aref t1 rest))
                  (aref t0 b) (logxor (aref t0 lb) (aref t0 rest)))))))
    (values t3 t2 t1 t0)))

(defun %gcm-ghash-32 (h data &optional tables)
  "GCM-GHASH on 32-bit limbs: the same bytes, no bignums.  Declared, and the 16 byte steps
   of each block unrolled so every shift is a constant."
  (declare (optimize (speed 3) (safety 0))
           (type (simple-array (unsigned-byte 8) (*)) data))
  (multiple-value-bind (t3 t2 t1 t0) (if tables (values-list tables) (%gcm-make-table-32 h))
    (declare (type (simple-array (unsigned-byte 32) (256)) t3 t2 t1 t0))
    (let ((y3 0) (y2 0) (y1 0) (y0 0) (rem +gcm-rem8-32+) (len (length data)) (i 0))
      (declare (type (unsigned-byte 32) y3 y2 y1 y0) (type fixnum len i)
               (type (simple-array (unsigned-byte 32) (256)) rem))
      (macrolet ((limb (k) `(logior (ash (aref data (+ i ,k)) 24) (ash (aref data (+ i ,(+ k 1))) 16)
                                    (ash (aref data (+ i ,(+ k 2))) 8) (aref data (+ i ,(+ k 3)))))
                 (byte-step (w sh)
                   ;; acc := acc * alpha^8, then acc ^= T[byte of W at SH]
                   `(let ((r (logand a0 #xff)) (xp (logand (ash ,w ,(- sh)) #xff)))
                      (declare (type (unsigned-byte 8) r xp))
                      (setf a0 (logxor (logior (ash a0 -8) (ash (logand a1 #xff) 24)) (aref t0 xp))
                            a1 (logxor (logior (ash a1 -8) (ash (logand a2 #xff) 24)) (aref t1 xp))
                            a2 (logxor (logior (ash a2 -8) (ash (logand a3 #xff) 24)) (aref t2 xp))
                            a3 (logxor (ash a3 -8) (aref rem r) (aref t3 xp))))))
        (loop
          (when (>= i len) (return))
          (setf y3 (logxor y3 (limb 0)) y2 (logxor y2 (limb 4))
                y1 (logxor y1 (limb 8)) y0 (logxor y0 (limb 12)))
          (let ((a3 0) (a2 0) (a1 0) (a0 0))
            (declare (type (unsigned-byte 32) a3 a2 a1 a0))
            (byte-step y0 0) (byte-step y0 8) (byte-step y0 16) (byte-step y0 24)
            (byte-step y1 0) (byte-step y1 8) (byte-step y1 16) (byte-step y1 24)
            (byte-step y2 0) (byte-step y2 8) (byte-step y2 16) (byte-step y2 24)
            (byte-step y3 0) (byte-step y3 8) (byte-step y3 16) (byte-step y3 24)
            (setf y3 a3 y2 a2 y1 a1 y0 a0))
          (setf i (+ i 16))))
      (let ((y (make-array 16 :element-type '(unsigned-byte 8))))
        (macrolet ((put (k w) `(setf (aref y ,k) (logand (ash ,w -24) #xff)
                                     (aref y ,(+ k 1)) (logand (ash ,w -16) #xff)
                                     (aref y ,(+ k 2)) (logand (ash ,w -8) #xff)
                                     (aref y ,(+ k 3)) (logand ,w #xff))))
          (put 0 y3) (put 4 y2) (put 8 y1) (put 12 y0))
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
  (let ((input (if (typep input '(simple-array (unsigned-byte 8) (*)))
                   input
                   (coerce input '(simple-array (unsigned-byte 8) (*))))))
    ;; modus: AES-NI where the runtime has it (it answers NIL where it does not)
    #+modus
    (when (fboundp 'modus.runtime::%aes-ctr-xor)
      (let ((out (make-array (length input) :element-type '(unsigned-byte 8))))
        (when (modus.runtime::%aes-ctr-xor
               (concatenate '(simple-array (unsigned-byte 8) (*)) j0 expanded-key)
               input out (length input) rounds)
          (return-from %gcm-ctr out))))
    (%gcm-ctr-octets expanded-key rounds j0 input)))

(defun %gcm-ctr-octets (expanded-key rounds j0 input)
  "%GCM-CTR of a simple octet vector: declared, one keystream block per 16 bytes."
  (declare (optimize (speed 3) (safety 0)) (type fixnum rounds)
           (type (simple-array (unsigned-byte 8) (*)) input j0))
  (let* ((in-len (length input))
         (out (make-array in-len :element-type '(unsigned-byte 8)))
         (counter (make-array 16 :element-type '(unsigned-byte 8)))
         (ks (make-array 16 :element-type '(unsigned-byte 8)))
         (i 0))
    (declare (type fixnum in-len i) (type (simple-array (unsigned-byte 8) (*)) out counter ks))
    (replace counter j0 :end2 16)
    (loop
      (when (>= i in-len) (return))
      (gcm-inc32 counter)
      (aes-encrypt-block counter expanded-key rounds ks)
      (let ((n (min 16 (- in-len i))) (j 0))
        (declare (type fixnum n j))
        (loop (when (>= j n) (return))
          (setf (aref out (+ i j)) (logxor (aref input (+ i j)) (aref ks j)))
          (setq j (+ j 1))))
      (setq i (+ i 16)))
    out))

(defconstant +gcm-key-cache-size+ 4)
(defvar *gcm-key-cache* nil
  "The most recently used (KEY-COPY EXPANDED ROUNDS H TABLES) tuples, newest first.")
#+modus ; per computation on modus: threads and actors share no state
(let ((reg (find-symbol "REGISTER-PER-COMPUTATION-SPECIAL" "COMMON-LISP-USER")))
  (when (and reg (fboundp reg)) (funcall reg '*gcm-key-cache*)))

(defun %gcm-prepare-key (key)
  "Return (values EXPANDED ROUNDS H TABLES) for KEY, from the cache of recent keys."
  (let ((c (find key *gcm-key-cache*
                 :test (lambda (k e) (equalp (the (simple-array (unsigned-byte 8) (*)) (first e)) k)))))
    (if c
        (values (second c) (third c) (fourth c) (fifth c))
        (let* ((key-len (length key))
               (expanded (if (= key-len 16) (aes-expand-key-128 key) (aes-expand-key-256 key)))
               (rounds (if (= key-len 16) 10 14))
               (h (aes-encrypt-block
                   (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
                   expanded rounds))
               (tables (%gcm-tables h))
               (old *gcm-key-cache*))
          (setf *gcm-key-cache*
                (cons (list (copy-seq key) expanded rounds h tables)
                      (subseq old 0 (min (length old) (1- +gcm-key-cache-size+)))))
          (values expanded rounds h tables)))))

(defun aes-gcm-encrypt (key nonce plaintext aad)
  "AES-GCM encrypt. KEY 16/32 bytes, NONCE 12 bytes. Returns (ciphertext . tag)."
  (multiple-value-bind (expanded-key rounds h tables) (%gcm-prepare-key key)
   (let* ((j0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i 12) (setf (aref j0 i) (aref nonce i)))
    (setf (aref j0 15) 1)
    (let* ((ciphertext (%gcm-ctr expanded-key rounds j0 plaintext))
           (s (gcm-ghash h (%gcm-build-ghash-data aad ciphertext) tables))
           (j0-enc (aes-encrypt-block j0 expanded-key rounds)))
      (dotimes (i 16) (setf (aref s i) (logxor (aref s i) (aref j0-enc i))))
      (cons ciphertext s)))))

(defun aes-gcm-decrypt (key nonce ciphertext aad tag)
  "AES-GCM decrypt. Returns plaintext, or NIL if the tag does not verify."
  (multiple-value-bind (expanded-key rounds h tables) (%gcm-prepare-key key)
   (let* ((j0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i 12) (setf (aref j0 i) (aref nonce i)))
    (setf (aref j0 15) 1)
    (let* ((s (gcm-ghash h (%gcm-build-ghash-data aad ciphertext) tables))
           (j0-enc (aes-encrypt-block j0 expanded-key rounds))
           (diff 0))
      (dotimes (i 16) (setf (aref s i) (logxor (aref s i) (aref j0-enc i))))
      ;; constant-time-ish tag comparison
      (dotimes (i 16) (setf diff (logior diff (logxor (aref s i) (aref tag i)))))
      (unless (zerop diff) (return-from aes-gcm-decrypt nil))
      (%gcm-ctr expanded-key rounds j0 ciphertext)))))
