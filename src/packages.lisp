;;;; packages.lisp — seal package definitions

(defpackage #:seal
  (:use #:cl)
  (:export
   ;; hashes
   #:sha256 #:sha384 #:sha512
   ;; hmac
   #:hmac-sha256 #:hmac-sha384
   ;; hkdf
   #:hkdf-extract #:hkdf-expand #:hkdf
   #:tls13-hkdf-expand-label #:tls13-derive-secret
   ;; block cipher / aead
   #:aes-128-encrypt-block #:aes-256-encrypt-block
   #:aes-128-decrypt-block #:aes-256-decrypt-block
   #:aes-gcm-encrypt #:aes-gcm-decrypt
   #:chacha20-poly1305-encrypt #:chacha20-poly1305-decrypt
   ;; key agreement
   #:x25519 #:x25519-public-key
   ;; entropy
   #:secure-random-bytes
   ;; x509
   #:parse-certificate #:certificate-subject #:certificate-issuer
   #:certificate-not-before #:certificate-not-after
   #:certificate-subject-alt-names #:certificate-public-key-info
   #:certificate-raw
   ;; transport
   #:make-socket-transport #:transport-send #:transport-recv #:transport-close
   ;; tls connection + public API
   #:connect #:tls-send #:tls-recv #:tls-close
   #:tls-connection #:tls-connection-p
   #:tls-connection-cipher #:tls-connection-alpn
   #:tls-connection-peer-certificates
   #:with-connection
   ;; gray stream
   #:tls-stream #:make-tls-stream #:tls-stream-connection
   ;; conditions
   #:tls-error #:tls-alert #:tls-verify-error))
