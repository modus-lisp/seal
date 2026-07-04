;;;; aead.lisp — ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).

(in-package #:seal)

(defun %pad16 (n)
  "Number of zero bytes needed to pad N up to a 16-byte boundary."
  (mod (- 16 (mod n 16)) 16))

(defun %poly1305-key-gen (key nonce)
  "Derive the one-time Poly1305 key: first 32 bytes of ChaCha20 block 0."
  (subseq (chacha20-block key 0 nonce) 0 32))

(defun %chacha20-poly1305-tag (otk aad ciphertext)
  (let* ((aad-len (length aad))
         (ct-len (length ciphertext))
         (mac-data (make-array (+ aad-len (%pad16 aad-len)
                                  ct-len (%pad16 ct-len) 16)
                               :element-type '(unsigned-byte 8) :initial-element 0))
         (pos 0))
    (replace mac-data aad :start1 pos) (incf pos (+ aad-len (%pad16 aad-len)))
    (replace mac-data ciphertext :start1 pos) (incf pos (+ ct-len (%pad16 ct-len)))
    (dotimes (i 8) (setf (aref mac-data (+ pos i)) (logand (ash aad-len (* -8 i)) #xff)))
    (dotimes (i 8) (setf (aref mac-data (+ pos 8 i)) (logand (ash ct-len (* -8 i)) #xff)))
    (poly1305-mac otk mac-data)))

(defun chacha20-poly1305-encrypt (key nonce plaintext &optional aad)
  "AEAD encrypt. KEY 32B, NONCE 12B. Returns (ciphertext . tag)."
  (let* ((aad (or aad (make-array 0 :element-type '(unsigned-byte 8))))
         (otk (%poly1305-key-gen key nonce))
         (ciphertext (chacha20-xor key 1 nonce plaintext))
         (tag (%chacha20-poly1305-tag otk aad ciphertext)))
    (cons ciphertext tag)))

(defun chacha20-poly1305-decrypt (key nonce ciphertext tag &optional aad)
  "AEAD decrypt. Returns plaintext, or NIL if the tag does not verify."
  (let* ((aad (or aad (make-array 0 :element-type '(unsigned-byte 8))))
         (otk (%poly1305-key-gen key nonce))
         (expected (%chacha20-poly1305-tag otk aad ciphertext))
         (diff 0))
    (dotimes (i 16) (setf diff (logior diff (logxor (aref expected i) (aref tag i)))))
    (unless (zerop diff) (return-from chacha20-poly1305-decrypt nil))
    (chacha20-xor key 1 nonce ciphertext)))
