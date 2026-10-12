;;;; ehbp.lisp — EHBP framing checks. Key/nonce derivation is pinned to the
;;;; Python oracle (HKDF over the reference exporter secret); the chunked AEAD
;;;; is exercised as a round trip plus tamper/truncation negatives.
(in-package #:seal)

(defun %ehbp-seal-chunk (key nonce-base seq plaintext)
  "Server side: one framed chunk u32be(len) || ct || tag, nonce = base XOR seq."
  (let* ((nonce (%ehbp-nonce nonce-base seq))
         (ct+tag (aes-gcm-encrypt key nonce plaintext #()))
         (ct (%hpke-bytes (car ct+tag) (cdr ct+tag))))
    (%hpke-bytes (%u32be (length ct)) ct)))

(defun run-ehbp-checks ()
  (let ((p0 *pass*) (f0 *fail*))
    (let* ((*hpke-aead-id* 2) (*hpke-nk* 32)
           (pke (unhex "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"))
           (skr (unhex "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"))
           (pkr (unhex "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"))
           (nonce (unhex "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")))
      (format t "~&== EHBP ==~%")
      (let ((ctx (hpke-setup-recipient pke skr pkr (ascii "ehbp request"))))
        (multiple-value-bind (k nb) (ehbp-response-keys ctx pke nonce)
          (check "EHBP response key (oracle)" k
                 "5fc6dc6cd3c266a009f9d30de4deba5433b1e331d53d1e26c444f257bf26a28a")
          (check "EHBP response nonce base (oracle)" nb "c06f0a68d4c8dea1a51048c7")
          ;; Two chunks, one empty chunk between them (skipped), then decrypt.
          (let* ((framed (%hpke-bytes
                          (%ehbp-seal-chunk k nb 0 (ascii "hello "))
                          (%u32be 0)
                          (%ehbp-seal-chunk k nb 1 (ascii "world"))))
                 (pt (ehbp-open-response k nb framed)))
            (check "EHBP response round trip" pt (ascii "hello world"))
            ;; Tamper one ciphertext byte: must error.
            (let ((bad (copy-seq framed)))
              (setf (aref bad 6) (logxor (aref bad 6) 1))
              (check "EHBP tampered chunk rejected"
                     (handler-case (progn (ehbp-open-response k nb bad) "accepted")
                       (error () "rejected"))
                     "rejected"))
            ;; Truncate mid-chunk: must error.
            (check "EHBP truncated chunk rejected"
                   (handler-case (progn (ehbp-open-response k nb (subseq framed 0 10)) "accepted")
                     (error () "rejected"))
                   "rejected")))
        ;; Request side: sealing then the recipient decrypts the body.
        (let* ((req (ehbp-seal-request pkr (ascii "ping")))
               (rctx (hpke-setup-recipient (ehbp-request-enc req) skr pkr (ascii "ehbp request")))
               (body (ehbp-request-body req))
               (n (logior (ash (aref body 0) 24) (ash (aref body 1) 16)
                          (ash (aref body 2) 8) (aref body 3))))
          (check "EHBP request length prefix" (if (= n (- (length body) 4)) "ok" "bad") "ok")
          (check "EHBP request decrypts" (or (hpke-open rctx (subseq body 4)) #())
                 (ascii "ping")))))
    (format t "~&ehbp: ~a pass, ~a fail~%" (- *pass* p0) (- *fail* f0))
    (= f0 *fail*)))
