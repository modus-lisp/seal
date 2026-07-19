;;;; packages.lisp — seal package definitions

(defpackage #:seal
  (:use #:cl)
  (:export
   ;; hashes
   #:sha1 #:sha256 #:sha384 #:sha512
   #:sha1-init #:sha1-update #:sha1-final    ; streaming SHA-1
   ;; hmac
   #:hmac-sha256 #:hmac-sha384
   ;; hkdf
   #:hkdf-extract #:hkdf-expand #:hkdf
   #:tls13-hkdf-expand-label #:tls13-derive-secret
   ;; block cipher / aead
   #:des-key-schedule #:des-encrypt-block   ; legacy DES (VNC auth)
   #:aes-128-encrypt-block #:aes-256-encrypt-block
   #:aes-128-decrypt-block #:aes-256-decrypt-block
   #:aes-gcm-encrypt #:aes-gcm-decrypt
   #:chacha20-poly1305-encrypt #:chacha20-poly1305-decrypt
   ;; key agreement
   #:x25519 #:x25519-public-key
   ;; signature verification
   #:rsa-public-key #:make-rsa-public-key #:rsa-n #:rsa-e
   #:rsa-pkcs1-verify #:rsa-pss-verify
   #:ecdsa-verify #:ecdsa-sign #:ec-generate-key #:ec-encode-point #:ec-decode-point
   #:ec-field-len #:*p256* #:*p384*
   #:ed25519-verify
   ;; entropy
   #:secure-random-bytes
   ;; x509
   #:parse-certificate #:certificate-subject #:certificate-issuer
   #:certificate-not-before #:certificate-not-after
   #:certificate-subject-alt-names #:certificate-public-key-info
   #:certificate-raw #:certificate-ca-p #:certificate-spki
   #:certificate-sig-scheme #:certificate-sig-hash
   ;; certificate chain verification + trust store
   #:validate-chain #:build-ordered-chain #:verify-cert-signature #:verify-signature
   #:trust-store #:trust-store-p #:make-trust-store-from-pem
   #:load-system-trust-store #:resolve-trust-store #:pem-certificates #:base64-decode
   ;; transport
   #:make-socket-transport #:transport-send #:transport-recv #:transport-close
   ;; tls connection + public API
   #:connect #:tls-send #:tls-recv #:tls-close #:*progress*
   #:tls-connection #:tls-connection-p
   #:tls-connection-cipher #:tls-connection-alpn
   #:tls-connection-peer-certificates
   #:with-connection
   ;; dtls 1.2 (webrtc)
   #:make-dtls-session #:dtls-session #:dtls-session-p
   #:dtls-client-handshake #:dtls-send-app #:dtls-handle-datagram
   #:+sig-rsa-pkcs1-sha256+ #:+sig-ecdsa-secp256r1-sha256+
   #:dtls-fingerprint #:dtls-done #:dtls-cipher
   #:dtls-peer-fingerprint #:dtls-peer-cert #:dtls-expected-peer-fingerprint
   ;; gray stream
   #:tls-stream #:make-tls-stream #:tls-stream-connection
   ;; conditions
   #:tls-error #:tls-alert #:tls-verify-error
   #:tls-certificate-error #:tls-certificate-untrusted-error
   #:tls-certificate-expired-error #:tls-certificate-hostname-error
   #:tls-certificate-bad-signature-error))
