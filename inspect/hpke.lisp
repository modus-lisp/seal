;;;; hpke.lisp — RFC 9180 Appendix A.1.1 vectors:
;;;; DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, base mode.
;;;; Deterministic: the ephemeral and recipient keys are fixed by the vector.
(in-package #:seal)

(defun run-hpke-vectors ()
  "RFC 9180 A.1.1 (AES-128-GCM) vectors; the AES-256 suite is checked against the Python oracle in the test file."
  (let ((p0 *pass*) (f0 *fail*))
  (let* ((*hpke-aead-id* 1) (*hpke-nk* 16)   ; RFC A.1.1 is AES-128-GCM
         (info (unhex "4f6465206f6e2061204772656369616e2055726e"))
         (ske  (unhex "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"))
         (pke  (unhex "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"))
         (skr  (unhex "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"))
         (pkr  (unhex "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"))
         (pt   (unhex "4265617574792069732074727574682c20747275746820626561757479"))
         (ss   "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc")
         (key  "4531685d41d65f03dc48f6b8302c05b0")
         (nonce "56d890e5accaaf011cff4b7d"))
    (format t "~&== RFC 9180 A.1.1 (X25519 / HKDF-SHA256 / AES-128-GCM, base) ==~%")
    ;; The ephemeral public key derives from the fixed skE, so Encap is checkable.
    (check "pkEm = X25519(skEm)" (x25519-public-key ske) pke)
    ;; Shared secret: DH(skE, pkR), with the kem context enc || pkR.
    (let ((dh (x25519 ske pkr)))
      (check "shared_secret (encap side)"
             (%hpke-kem-shared-secret dh (%hpke-bytes pke pkr)) ss))
    ;; Decap must reach the same shared secret from enc and skR.
    (check "shared_secret (decap side)"
           (hpke-decap pke skr pkr) ss)
    ;; Full base key schedule from the recipient side.
    (let ((ctx (hpke-setup-recipient pke skr pkr info)))
      (check "key" (hpke-context-key ctx) key)   ; 16-byte AES-128 key
      (check "base_nonce" (hpke-context-base-nonce ctx) nonce)
      ;; Sequence number 0 (A.1.1.1): ciphertext || tag must match and open.
      (let ((sealed (hpke-seal (hpke-setup-recipient pke skr pkr info) pt
                               (unhex "436f756e742d30"))))
        (check "encrypt seq 0"
               sealed
               "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a")))
    ;; Sender side round-trips against the recipient, using a fresh ephemeral.
    (multiple-value-bind (sctx enc) (hpke-setup-sender pkr info)
      (let* ((ct (hpke-seal sctx pt (ascii "round-trip")))
             (rctx (hpke-setup-recipient enc skr pkr info))
             (back (hpke-open rctx ct (ascii "round-trip"))))
        (check "sender/recipient round-trip" (or back #()) pt)))
    ;; Tampered ciphertext must fail to open.
    (let* ((sctx (hpke-setup-sender pkr info))
           (ct nil))
      (declare (ignore sctx))
      (multiple-value-bind (sc enc) (hpke-setup-sender pkr info)
        (setf ct (hpke-seal sc pt))
        (let* ((bad (copy-seq ct))
               (rctx (hpke-setup-recipient enc skr pkr info)))
          (setf (aref bad 0) (logxor (aref bad 0) 1))
          (check "tampered ct rejected" (if (hpke-open rctx bad) "accepted" "rejected")
                 "rejected"))))
    ;; AES-256-GCM suite (what Tinfoil EHBP uses). No RFC 9180 vector exists for
    ;; X25519 + AES-256-GCM base mode, so these values come from an independent
    ;; Python oracle (cryptography 50.0.1) over the same RFC A.1.1 keys and info.
    (let* ((*hpke-aead-id* 2) (*hpke-nk* 32)
           (ctx (hpke-setup-recipient pke skr pkr info)))
      (format t "~&== AES-256-GCM suite, oracle-derived (RFC A.1.1 keys) ==~%")
      (check "AES-256 shared_secret" (hpke-decap pke skr pkr) ss)
      (check "AES-256 key" (hpke-context-key ctx)
             "a2863277956ec56c4f9f16b43665870daa2403d0d22baceff6551c4ff35b8528")
      (check "AES-256 base_nonce" (hpke-context-base-nonce ctx)
             "94fc3a5af015ec686da39ff8")
      (check "AES-256 encrypt seq 0"
             (hpke-seal (hpke-setup-recipient pke skr pkr info) pt (unhex "436f756e742d30"))
             "090b7dc225419f7da9e8b460becfbb96a26c7964d79b8010d397fa838530a32a397b14f5776db19ff5e57734e0"))
    (format t "~&hpke: ~a pass, ~a fail~%" (- *pass* p0) (- *fail* f0))
    (= f0 *fail*))))
