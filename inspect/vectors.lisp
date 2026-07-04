;;;; vectors.lisp — official test vectors for every seal crypto primitive.
;;;;
;;;; Sources: FIPS 197 (AES), NIST/McGrew-Viega GCM spec, FIPS 180-4 (SHA-2),
;;;; RFC 4231 (HMAC), RFC 5869 (HKDF), RFC 8439 (ChaCha20-Poly1305),
;;;; RFC 7748 §5.2 (X25519). Every check must match exactly.

(in-package #:seal)

(defun run-vectors ()
  "Run all crypto test vectors. Returns the number of failures."
  (setf *pass* 0 *fail* 0)

  (format t "~%== AES (FIPS 197) ==~%")
  (check "AES-128 encrypt"
         (aes-128-encrypt-block (unhex "000102030405060708090a0b0c0d0e0f")
                                (unhex "00112233445566778899aabbccddeeff"))
         "69c4e0d86a7b0430d8cdb78070b4c55a")
  (check "AES-128 decrypt"
         (aes-128-decrypt-block (unhex "000102030405060708090a0b0c0d0e0f")
                                (unhex "69c4e0d86a7b0430d8cdb78070b4c55a"))
         "00112233445566778899aabbccddeeff")
  (check "AES-256 encrypt"
         (aes-256-encrypt-block (unhex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                                (unhex "00112233445566778899aabbccddeeff"))
         "8ea2b7ca516745bfeafc49904b496089")

  (format t "~%== AES-GCM (McGrew-Viega Test Cases 3 & 4) ==~%")
  (let ((c (aes-gcm-encrypt (unhex "feffe9928665731c6d6a8f9467308308")
                            (unhex "cafebabefacedbaddecaf888")
                            (unhex "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
                            (unhex ""))))
    (check "GCM-128 case3 ciphertext" (car c)
           "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985")
    (check "GCM-128 case3 tag" (cdr c) "4d5c2af327cd64a62cf35abd2ba6fab4"))
  (let ((c (aes-gcm-encrypt (unhex "feffe9928665731c6d6a8f9467308308")
                            (unhex "cafebabefacedbaddecaf888")
                            (unhex "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
                            (unhex "feedfacedeadbeeffeedfacedeadbeefabaddad2"))))
    (check "GCM-128 case4 ciphertext" (car c)
           "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
    (check "GCM-128 case4 tag" (cdr c) "5bc94fbc3221a5db94fae95ae7121a47")
    (check "GCM-128 case4 decrypt"
           (aes-gcm-decrypt (unhex "feffe9928665731c6d6a8f9467308308")
                            (unhex "cafebabefacedbaddecaf888")
                            (car c)
                            (unhex "feedfacedeadbeeffeedfacedeadbeefabaddad2")
                            (cdr c))
           "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"))

  (format t "~%== SHA-2 (FIPS 180-4) ==~%")
  (check "SHA-256 empty" (sha256 (ascii ""))
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  (check "SHA-256 abc" (sha256 (ascii "abc"))
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  (check "SHA-384 abc" (sha384 (ascii "abc"))
         "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
  (check "SHA-512 abc" (sha512 (ascii "abc"))
         "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
  (check "SHA-512 empty" (sha512 (ascii ""))
         "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")

  (format t "~%== HMAC (RFC 4231 Test Case 2) ==~%")
  (check "HMAC-SHA256" (hmac-sha256 (ascii "Jefe") (ascii "what do ya want for nothing?"))
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
  (check "HMAC-SHA384" (hmac-sha384 (ascii "Jefe") (ascii "what do ya want for nothing?"))
         "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")

  (format t "~%== HKDF (RFC 5869 Test Case 1) ==~%")
  (let ((prk (hkdf-extract (unhex "000102030405060708090a0b0c")
                           (unhex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))))
    (check "HKDF-Extract PRK" prk
           "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    (check "HKDF-Expand OKM" (hkdf-expand prk (unhex "f0f1f2f3f4f5f6f7f8f9") 42)
           "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))

  (format t "~%== ChaCha20-Poly1305 (RFC 8439) ==~%")
  (check "Poly1305 §2.5.2"
         (poly1305-mac (unhex "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                       (ascii "Cryptographic Forum Research Group"))
         "a8061dc1305136c6c22b8baf0c0127a9")
  (let ((c (chacha20-poly1305-encrypt
            (unhex "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            (unhex "070000004041424344454647")
            (ascii "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
            (unhex "50515253c0c1c2c3c4c5c6c7"))))
    (check "AEAD §2.8.2 ciphertext" (car c)
           "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
    (check "AEAD §2.8.2 tag" (cdr c) "1ae10b594f09e26a7e902ecbd0600691")
    (check "AEAD §2.8.2 decrypt"
           (chacha20-poly1305-decrypt
            (unhex "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            (unhex "070000004041424344454647")
            (car c) (cdr c)
            (unhex "50515253c0c1c2c3c4c5c6c7"))
           (ascii "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")))

  (format t "~%== X25519 (RFC 7748 §5.2) ==~%")
  (check "X25519 vector 1"
         (x25519 (unhex "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                 (unhex "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
  (check "X25519 vector 2"
         (x25519 (unhex "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
                 (unhex "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"))
         "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
  (check "X25519 Alice public"
         (x25519-public-key (unhex "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
         "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
  (check "X25519 Bob public"
         (x25519-public-key (unhex "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
         "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
  (check "X25519 shared (Alice*Bob)"
         (x25519 (unhex "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                 (unhex "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
         "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

  (format t "~%==== crypto vectors: ~d passed, ~d failed ====~%" *pass* *fail*)
  *fail*)
