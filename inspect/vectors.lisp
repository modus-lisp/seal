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

  (format t "~%== SHA-1 (FIPS 180-4) ==~%")
  (check "SHA-1 abc" (sha1 (ascii "abc")) "a9993e364706816aba3e25717850c26c9cd0d89d")
  (check "SHA-1 empty" (sha1 (ascii "")) "da39a3ee5e6b4b0d3255bfef95601890afd80709")

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

  (run-signature-vectors)

  (format t "~%==== crypto vectors: ~d passed, ~d failed ====~%" *pass* *fail*)
  *fail*)

(defun check-true (name got)
  (if got (progn (incf *pass*) (format t "  PASS ~a~%" name))
      (progn (incf *fail*) (format t "  FAIL ~a  (expected accept)~%" name))))

(defun check-false (name got)
  (if (not got) (progn (incf *pass*) (format t "  PASS ~a~%" name))
      (progn (incf *fail*) (format t "  FAIL ~a  (expected reject)~%" name))))

;;; Fixed 2048-bit RSA key + PKCS#1-v1.5 and PSS signatures minted with OpenSSL
;;; 3.0 (as NIST CAVP vectors are minted). Message = "seal RSA test vector".
(defparameter *rsa-n*
  (parse-integer
   (concatenate 'string
     "a73a893d7b8d97299ff9c7946c655b9e7b7a9988d725fc995c723522189e019f"
     "fa515bfce1f255174884c3dc9d8c6a8df99e95f383016ec5d5927a5adbb36c2f"
     "5a753f487d3412b652f50005935416535a35602f8811051d8c64b1a3029a69ef"
     "0dc06400be42328eaf9a00d08a6d67e921746552cef168c2a696a33d1a7b9e7d"
     "a82368625f11416c9e46dfbcc69c1aa93f2717a66ba4fc2589bb814d2bcb1b02"
     "3a5d91d8c51e2e351d389171aaf3a7168635208a7c9d5ef29f5d05628199d8ce"
     "1a3ae6ab7d17d6702737c6d1a810cee68a9ae7495c83273f365c71e28b3b8e32"
     "1aa2b01ac8b72a98a093c2479b07d1098aa2c8f0aabbdfe8572240075ae2e5eb")
   :radix 16))

(defun rsa-key () (make-rsa-public-key :n *rsa-n* :e 65537))
(defparameter *rsa-msg* (ascii "seal RSA test vector"))

(defun run-signature-vectors ()
  (format t "~%== RSA PKCS#1-v1.5 (OpenSSL-minted KAT, 2048-bit) ==~%")
  (let ((k (rsa-key)))
    (check-true "PKCS1 SHA-256 verify"
      (rsa-pkcs1-verify k :sha256 *rsa-msg*
        (unhex (concatenate 'string
          "12f5eb0c88d7b797513f943c5d8829c9eb6a669ced63f7ad9f5855851b177f12"
          "d53ad0370af85d4878e1f10e9b15d8bf56df55df6538b3dd436ec9af7dc82cd1"
          "76a7b00f1192167b9da8985adfb5de41bf7888de3ea2d1742fe61687df5557c4"
          "b427cb7deb7e7362985e7295e3af144e3d443c2aa5d214796f14f8d70f947d78"
          "bb2e68b1c1bf2c66fcbbe7d5e9064071b7995745d229a24e7d748298adf246f2"
          "14c560db68104ad8dfe3cdcb24053fd7ccfa894fbf3b85e75df75e6d8193c022"
          "51b01ec7c4e58ac589320158d2cfbfbac6a4942c638b4953397d77e0b31b9162"
          "5cbd32c5d9beba99c62f327d941ecd29ffb9e5344773dd37830b01a4bc761222"))))
    (check-true "PKCS1 SHA-384 verify"
      (rsa-pkcs1-verify k :sha384 *rsa-msg*
        (unhex (concatenate 'string
          "5eb6f6eb5d79714d611a829e45900f218552f5ce96a39a6acd2c82ceb9bcc7db"
          "9ce4ab123e305dd94f44246b447761d99d0cafc76b8c6783f3dd2e6a94ed0bc1"
          "7f3ea54cbf0a85d00538505ed2a3ba4900a00447c6875b5075fc640635f9f5b6"
          "e3c09517e27ff30399c896b21950546f3887b5defc2bace9355bbbd5d52a7134"
          "360741d02a8440b707f276dc7d52f38ff7be323fa35cc9bcfc90a00bccaeb234"
          "ddf76766048b58db2a72ef08f80ccb08ca96fb674efcb7f6420682aede0d0f07"
          "54fb2f19b7a983cd194a4cd4b4901167c84f77a21991993ae59b9fa2b128f842"
          "934fe4751a41cd59efed5584678ba772a176d94eedc04a2d354737680d0b2ee1"))))
    (check-true "PKCS1 SHA-512 verify"
      (rsa-pkcs1-verify k :sha512 *rsa-msg*
        (unhex (concatenate 'string
          "0f1b8f2ccd6faaa18223dc5467efc1f819509bca2be320b8001220992630e054"
          "7649a06fbccaffbc0d6235c3581dd2ee9093d42e0e056a101d45a7c81a18a71e"
          "0d52e7fe7199e6ff8ccbb7a7adb632c910b47b7e2a7fe6a2d62236354b129971"
          "db517dc37ab695dde521b7f916443ab836759d0aae92f8b5c35a29eb5703ca63"
          "ddec858a9c6d004a31be3d2c7628ee18fe07db5c3f31bb91d70650a47a657a11"
          "3519f4dffe011f8bf8333e6603f632da16a5af2d0a4539cab1d9c5445f750a99"
          "113e73f2dbbe390f1477885f870fa290faab1f316b1955a2205b472bb06a7eaf"
          "60af35773d33da4406401c0679458b27dce7be636f61f39eb766f6b62409cff5"))))
    ;; Negative: a one-byte tamper of the message must be rejected.
    (check-false "PKCS1 SHA-256 tampered message rejected"
      (rsa-pkcs1-verify k :sha256 (ascii "seal RSA test vectoR")
        (unhex (concatenate 'string
          "12f5eb0c88d7b797513f943c5d8829c9eb6a669ced63f7ad9f5855851b177f12"
          "d53ad0370af85d4878e1f10e9b15d8bf56df55df6538b3dd436ec9af7dc82cd1"
          "76a7b00f1192167b9da8985adfb5de41bf7888de3ea2d1742fe61687df5557c4"
          "b427cb7deb7e7362985e7295e3af144e3d443c2aa5d214796f14f8d70f947d78"
          "bb2e68b1c1bf2c66fcbbe7d5e9064071b7995745d229a24e7d748298adf246f2"
          "14c560db68104ad8dfe3cdcb24053fd7ccfa894fbf3b85e75df75e6d8193c022"
          "51b01ec7c4e58ac589320158d2cfbfbac6a4942c638b4953397d77e0b31b9162"
          "5cbd32c5d9beba99c62f327d941ecd29ffb9e5344773dd37830b01a4bc761222")))))

  (format t "~%== RSA-PSS (OpenSSL-minted KAT, salt=hashlen) ==~%")
  (let ((k (rsa-key)))
    (check-true "PSS SHA-256 verify"
      (rsa-pss-verify k :sha256 *rsa-msg*
        (unhex (concatenate 'string
          "0e6fa1564f0d52bcb4b26cb5e43878613344bb58ad2a5cd9dc047d80d87fb51b"
          "14daa58cce7680ab30a53a34fb103f22523d8e4060e75186b6e1c66d33c24112"
          "a973d0cb0fb2eba46c7f0ec0a2df42a969beff5de27345539344648bd9763ab3"
          "6eb28d633c1cbaa1034f94a8663e669b81393a5a8f6cad7d45f006c69a9c2ffa"
          "50f34e941aca7a5ca9a0d94b9c55c02f54b4cf8320beef0e39d05781ecb5a9fd"
          "fa2911abd4354d0e28e4b81d6c120bb49e4b4e44765072b0ea8b6d2db321fdf3"
          "aa760d4380e900a529f11dbe8a58a5fc800c87afd788cc4b99f78af22a2f9520"
          "1f9e8af6f228195a941d4ccc4cc3830fc16e35f64f6d73bcab8c71082a913652"))))
    (check-true "PSS SHA-384 verify"
      (rsa-pss-verify k :sha384 *rsa-msg*
        (unhex (concatenate 'string
          "7328c078336cca13b7d4f1beec8dc2c7d8f18e7460328255057aa73a1ee57384"
          "12c11876bd5fe3f4af50684eed127aac9325d7473626116c5ea7f95c1471780f"
          "940b325e57bc7a78465004d898a370c7031b7e0b7190ef6db872e70d1f6355ab"
          "a070036e3b058f24f35946a355bca3666952b853b1fa75cfc68d74ca4800e79b"
          "b337927e0af3cbd42c4f7b1075534c3bf13b7fc6a5194e7ffd18003c0f4ed80e"
          "45c5353de7f58ed56d7d791eea49688501a1cc5d034366eabc9e86b52a2fdf17"
          "fd0858e0e0f29c5a3daa06d0a605a62091c5cf3248d349da233fdb440860f1a1"
          "7a06b59a7ca74b9b3df856a55fe77bf24887a0906b8c3866b178280cb636f2e1"))))
    (check-true "PSS SHA-512 verify"
      (rsa-pss-verify k :sha512 *rsa-msg*
        (unhex (concatenate 'string
          "87767bacecfc14c809f34d2320bda7eb78b8f0c160609a66cb75691ab2bb4b00"
          "67102538d06741cbd1ee5b5abb885a35f610f5c98a02ade63f83cbb695c526a3"
          "eb98cc65638232533b1cc32c208528ab826c84be743b1e855c09c5b99ffe7bad"
          "96a8846d3ad538da6518d7bf7963a431400da35b095c996f1c2d0b2f01493680"
          "4706a0fdcd58b443e022d63f9136b344bead78ef2d7aea23dcce6a84217cd751"
          "b2b3d6096f529c0135cd06a4bebe9153d4d0c401db63949ca7fbc5f9cbdd9bd4"
          "01e61ddce8717a9c406288982ef5e6165392d23087ba38362dd9aae1c48a4a00"
          "84f214c57be6cf7db5a98b286e52972f7156db035ebfb1a6f4083aaf1a013b8d"))))
    (check-false "PSS SHA-256 tampered signature rejected"
      (rsa-pss-verify k :sha256 *rsa-msg*
        (unhex (concatenate 'string
          "0e6fa1564f0d52bcb4b26cb5e43878613344bb58ad2a5cd9dc047d80d87fb51b"
          "14daa58cce7680ab30a53a34fb103f22523d8e4060e75186b6e1c66d33c24112"
          "a973d0cb0fb2eba46c7f0ec0a2df42a969beff5de27345539344648bd9763ab3"
          "6eb28d633c1cbaa1034f94a8663e669b81393a5a8f6cad7d45f006c69a9c2ffa"
          "50f34e941aca7a5ca9a0d94b9c55c02f54b4cf8320beef0e39d05781ecb5a9fd"
          "fa2911abd4354d0e28e4b81d6c120bb49e4b4e44765072b0ea8b6d2db321fdf3"
          "aa760d4380e900a529f11dbe8a58a5fc800c87afd788cc4b99f78af22a2f9520"
          "1f9e8af6f228195a941d4ccc4cc3830fc16e35f64f6d73bcab8c71082a913653")))))

  (format t "~%== ECDSA P-256 (RFC 6979 A.2.5, msg \"sample\") ==~%")
  (let ((q (cons (ec-hex "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")
                 (ec-hex "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")))
        (r (ec-hex "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"))
        (s (ec-hex "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")))
    (check-true "P-256 SHA-256 verify" (ecdsa-verify *p256* q (sha256 (ascii "sample")) r s))
    (check-false "P-256 tampered r rejected" (ecdsa-verify *p256* q (sha256 (ascii "sample")) (1+ r) s))
    (check-false "P-256 wrong message rejected" (ecdsa-verify *p256* q (sha256 (ascii "samplf")) r s)))

  (format t "~%== ECDSA P-384 (RFC 6979 A.2.6, msg \"sample\") ==~%")
  (let ((q (cons (ec-hex "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13")
                 (ec-hex "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720")))
        (r (ec-hex "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46"))
        (s (ec-hex "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8")))
    (check-true "P-384 SHA-384 verify" (ecdsa-verify *p384* q (sha384 (ascii "sample")) r s))
    (check-false "P-384 tampered s rejected" (ecdsa-verify *p384* q (sha384 (ascii "sample")) r (1+ s))))

  (format t "~%== Ed25519 (RFC 8032 §7.1) ==~%")
  (check-true "Ed25519 TEST 1 (empty msg)"
    (ed25519-verify
     (unhex "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
     (unhex (concatenate 'string
       "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
       "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"))
     (unhex "")))
  (check-true "Ed25519 TEST 2 (1-byte msg)"
    (ed25519-verify
     (unhex "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
     (unhex (concatenate 'string
       "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
       "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"))
     (unhex "72")))
  (check-false "Ed25519 tampered signature rejected"
    (ed25519-verify
     (unhex "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
     (unhex (concatenate 'string
       "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
       "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c01"))
     (unhex "72"))))
