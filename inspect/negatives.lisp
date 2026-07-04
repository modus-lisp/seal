;;;; negatives.lisp — the acceptance bar: bad certificates MUST be rejected.
;;;;
;;;; A validator that accepts a bad certificate is worse than none, so these
;;;; tests assert that every malformed/untrusted/expired/misnamed/tampered case
;;;; raises the appropriate TLS-CERTIFICATE-ERROR under full validation. The
;;;; certificates are an offline mini-PKI minted with OpenSSL / pyca (root ->
;;;; intermediate -> leaf, plus a self-signed expired leaf), so the suite is
;;;; deterministic and needs no network.

(in-package #:seal)

(defparameter *neg-root-pem*
  "-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIUdTbKi1V9E/RHZh4SAbYh+QiUrMMwDQYJKoZIhvcNAQEL
BQAwKzEaMBgGA1UEAwwRc2VhbCBUZXN0IFJvb3QgQ0ExDTALBgNVBAoMBHNlYWww
HhcNMjYwNzA0MTM0NjQyWhcNMzYwNzAxMTM0NjQyWjArMRowGAYDVQQDDBFzZWFs
IFRlc3QgUm9vdCBDQTENMAsGA1UECgwEc2VhbDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALvms+MgYe6A/CpRhiffgt803sC3ssPFxGSSyY5V907K0D7L
rfWjbNipaN2eVgxuMYa4hcaFGOrH4MhPvX7dkoOPy9BBPwTVCacnJbvh2kRNDfTt
abYIkM/Y41CHDnYze+KmWukMQZ0KOM3NZsDuBjcIpM6s1dVU7vU6tcb0cCoCgUaP
6czbcIleBGlsVhIGdy9v+/GyFmcW2r1gr9aKYwUk+MNBpLz0MkpgwB2669lKJA2m
XgjIkBa+lCpk74o/YntDNMsoY6ZclOVIcRPvidPlwaq0fMc2lVNLz0Sr5uqoTsH9
WmmN+qNvPe32zCe6S3gA3/MUIEABvBsUo1D8zysCAwEAAaNjMGEwHQYDVR0OBBYE
FH1kswkJyvfzuBRXmTSPiKoyV/vrMB8GA1UdIwQYMBaAFH1kswkJyvfzuBRXmTSP
iKoyV/vrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQA0qmRViQNAV+spFCrwfUbdvMeiWwmTBH2XVa+rJdn5egtvegZZ
qk8tr7eWOfuNOpKVXPs0OOFxElI+WYUsY6BbGdUbwJCcVnLfgGLqNG2noPSvNTeY
Jzr2PqnLSBUNtcxgp7XVIw68HwaxqkM9vNIySNL3zO26XWNPmkNHFLCh193cvvH2
Jgp1sYGKfSF3wdiYhnzlV4RRQXgedhFYfEXDTC5J0z0nCZhlC6NuFXoMvepwCoLD
AmY/nGnt6OkocTI9vAybVLJphFPho2Il+ZGv1i2Hf5gQWHBYN7Y+YLfl93mPBhRt
UB/QavzyL7d+Tsh4MRVLSgN+KZxO2EiXlupE
-----END CERTIFICATE-----")

(defparameter *neg-int-pem*
  "-----BEGIN CERTIFICATE-----
MIIDTzCCAjegAwIBAgIUIYLZaEQuCnB6f9bXHHBSqjW+qXEwDQYJKoZIhvcNAQEL
BQAwKzEaMBgGA1UEAwwRc2VhbCBUZXN0IFJvb3QgQ0ExDTALBgNVBAoMBHNlYWww
HhcNMjYwNzA0MTM0NjQyWhcNMzEwNzAzMTM0NjQyWjAzMSIwIAYDVQQDDBlzZWFs
IFRlc3QgSW50ZXJtZWRpYXRlIENBMQ0wCwYDVQQKDARzZWFsMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIGsOZSUi/b3Nbn1woVnq+8CPA3zB6kynJVp
iev5Vi8OEoVQOJBd54+i3+4rteOwv2z0fBqqVRBEBIHMvSl+3Sxq/HLz1EDMhNgN
/lLN5R8n1V7xX/IpCz1hDpJnQBfKterIUb2EbmWNHaAOaXmd3U29YTbY9r9p+xeh
ITvNhq7y3YGG3pzzvhgB1bTQ4SkoWjm3iq0f44Ns4arpQfA+AfnH9GzclxRnUj5k
mI7KM3CxWcrzuSuOrERF+FwQAjGKOKiPIUIjA9brvrcSBtQoSwsjvF9zYg5k1GJV
nBqcP1/rvrfYknTwY0CR1TN/f2p5+gdx1mvHg8TzHU/Ip/ZdmQIDAQABo2MwYTAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUYOFiX/+w
VE5pcDo+TUlRGPdGveAwHwYDVR0jBBgwFoAUfWSzCQnK9/O4FFeZNI+IqjJX++sw
DQYJKoZIhvcNAQELBQADggEBADR2RnIM5M7EL07SZ6olipnFnsPllZUWmk1bfBI/
7Ob09fK+QTKm1FG/f3Ic4S65fdAUxkeTrYHzHsYn7I+oEPWk7QFw9/rnk+iIMMO4
ob2n/PB192gSZSDMpXo7ndvDdlBhzRGZrQiUle3dmYT9ueMGOFxRYkMjcWkHz198
fNZh6ydtnflbziKv78eHiB1yzDT3AVk08KPtkbH8Zr+sT7jNg6qbSxPJm26pTvvE
XI1F99/vRG6TwM0DzAIQNf5GAKzuGjce3G7MNm49FLI2mfWbjOObCGxIJqH+gZET
C1PY5KKzbEs9D2APt8Vm8gFwgG3sChf6j6IakkTn7m5xIeA=
-----END CERTIFICATE-----")

(defparameter *neg-leaf-pem*
  "-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIUXXZ1FmFc33IIjDOAicNFXcSxjvMwDQYJKoZIhvcNAQEL
BQAwMzEiMCAGA1UEAwwZc2VhbCBUZXN0IEludGVybWVkaWF0ZSBDQTENMAsGA1UE
CgwEc2VhbDAeFw0yNjA3MDQxMzQ2NDNaFw0yNzA3MDQxMzQ2NDNaMBwxGjAYBgNV
BAMMEXRlc3Quc2VhbC5leGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA3ObIzJcCw000Pi29wAUWpVX1h3NE8nVOpAvM38mSQeU3F/VogIYSWrmf
1gAV03SemAyxY27dvv6a/tAFnR9OYgjUZi0vlCIDG7M/PPTp9CmSzZNBbtWknUZi
h5KYJrRGnJEvDZWXPsgTOKWE8dx3LF7AMRun8HBE0Gc+hMsp8BsDJRD9nVrhVUPv
6FBCtWj7yMcgECchMT7cFGzt/lYO0uoXb1+fN8dwGSxPcvxn8lpzTu6ZLPk+xtCG
sEbu2WZnewyaSDHi+Z3HYgOv89noP31Os1VoZdSuIxxIlS88YtPYZD6eYYbhA/i4
497fke8/B+nULqby8DR5VdtXtDV99QIDAQABo24wbDAMBgNVHRMBAf8EAjAAMBwG
A1UdEQQVMBOCEXRlc3Quc2VhbC5leGFtcGxlMB0GA1UdDgQWBBRuDdSxW4YpmrxQ
8NUIRrfD2sBZcTAfBgNVHSMEGDAWgBRg4WJf/7BUTmlwOj5NSVEY90a94DANBgkq
hkiG9w0BAQsFAAOCAQEAFtUn6Ny37+DlYFin5znTF/9wDr3rEQqZGymTFjit14xS
ae/cnvll41BPsBk5oh0V89QCq+J4t9ugylbyIDUX5GEuZSh0AKXXDp+gKFA4nLG/
aXUUj+bDKtNBt6zHrzbOySOkW49+cufFi/hecHbLsAb82rPs4XJtq3PtppPH+/3c
/dono83AVxqCPQ6vtl1/YBYkJWUd1BJEqiTijFEFv+NBl8y1l7hGsEy1vZBlWluv
BLBeL2yS0+pSH5tldbduHnUnQvJBM6IWtwrFyOuo/K0iU8G8KE7eA6CH6ESQpGvK
lb4H1p4CvwV19GxqGgZLHtkQb0Zct9krhX6D5t/Q0A==
-----END CERTIFICATE-----")

(defparameter *neg-expired-pem*
  "-----BEGIN CERTIFICATE-----
MIIC5jCCAc6gAwIBAgIUc+1qaNh/LAD/doPuqGgWc0GaxfMwDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRdGVzdC5zZWFsLmV4YW1wbGUwHhcNMjAwMTAxMDAwMDAw
WhcNMjAwMjAxMDAwMDAwWjAcMRowGAYDVQQDDBF0ZXN0LnNlYWwuZXhhbXBsZTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALcegKIXaQpxAI87BdQhjciJ
e8hSxqMzaSkDVT75R8TZ2n73/MWrzLqN5JYiSS5V7ilniQBoPKGTLvOAiIaB2wrA
c2RfnaC0MJYgtr6KUyKWMduj5cmyfJAmFk5iDrXr50AnJ+pDf+LZEI/MxnU4Tum+
4GYOtSzh/6vGNDqymn9Stxsr9e+r8ZXT+ceM6N7lPBTYzW1GFQ5wq1JDa0FFrDwU
pPVYB8PpKtCYErLYrod8zh7/Mi3/xAqgwB/fwJrp4U3v7qrBVf4C/byaQem1UYDm
7NVHZHKTBD3jRrqw9/4YSxNU5fYoh41qP0vofq1QJch115SZNk/Pdhidzh2+NrEC
AwEAAaMgMB4wHAYDVR0RBBUwE4IRdGVzdC5zZWFsLmV4YW1wbGUwDQYJKoZIhvcN
AQELBQADggEBAHkrYlQNajQbajYTrMfZji0XlZk3lOda9QKd/rMh/4Nggwia4Ul6
jfq92Ln5gMLN+Jk/q9dwcy6D1tcHmCywa3T/YoRyoJE1EqfliH2q4oJMEwQVHvHR
mYM43GldxToMYss+MKXiz0IjtRMr264BH67nfGOLg/JdCLHwIWfc1XC8Q+yPPMbb
CCw5dNnW4FGVH6wawz7C/w1T398yf1nJ7wbPfb9cIVEXrg9KmYVoss76bmU7nkjz
0SJlfs9C0gnV5EjfkKPwCxD1inSgJ/b9i0j+kVxCyxxUVWdzH9N84EqnZchGcrHF
ygQlFSiiQMXi5vdKb2ZOh9Xe745nVhWA6Rg=
-----END CERTIFICATE-----")


;;; ---- helpers ----------------------------------------------------------------

(defun neg-cert (pem) (parse-certificate (first (pem-certificates pem))))

(defun expect-reject (name expected-condition thunk)
  "Assert THUNK signals EXPECTED-CONDITION (fail closed). Accepting = failure."
  (handler-case
      (progn (funcall thunk)
             (incf *fail*)
             (format t "  FAIL ~a  (ACCEPTED a bad certificate!)~%" name))
    (error (e)
      (if (typep e expected-condition)
          (progn (incf *pass*)
                 (format t "  PASS ~a  -> ~a~%" name (type-of e)))
          (progn (incf *fail*)
                 (format t "  FAIL ~a  wrong condition: ~a~%" name (type-of e)))))))

;;; ---- the acceptance bar -----------------------------------------------------

(defun run-negative-tests ()
  "Every case here MUST be rejected under full validation. Returns #failures."
  (setf *pass* 0 *fail* 0)
  (format t "~%== Certificate validation: NEGATIVE cases (must all be REJECTED) ==~%")
  (let* ((root (neg-cert *neg-root-pem*))
         (int (neg-cert *neg-int-pem*))
         (leaf (neg-cert *neg-leaf-pem*))
         (expired (neg-cert *neg-expired-pem*))
         (store (make-trust-store-from-pem *neg-root-pem*))   ; trusts only our root
         (empty (make-trust-store))
         (host "test.seal.example"))
    ;; Positive control: the good chain to our trusted root must SUCCEED.
    (handler-case
        (progn (validate-chain (list leaf int) store host)
               (incf *pass*) (format t "  PASS (control) good chain accepted~%"))
      (error (e) (incf *fail*)
        (format t "  FAIL (control) good chain rejected: ~a~%" e)))

    ;; 1. Self-signed / untrusted root: chains to nothing in the store.
    (expect-reject "self-signed cert rejected (untrusted)"
                   'tls-certificate-untrusted-error
                   (lambda () (validate-chain (list root) empty "seal Test Root CA")))

    ;; 2. Chain not terminating at any trusted root (good chain, empty store).
    (expect-reject "chain to unknown root rejected (untrusted)"
                   'tls-certificate-untrusted-error
                   (lambda () (validate-chain (list leaf int) empty host)))

    ;; 3. Expired certificate.
    (expect-reject "expired cert rejected"
                   'tls-certificate-expired-error
                   (lambda () (validate-chain (list expired) empty host)))

    ;; 4. Wrong hostname (valid chain, wrong name requested).
    (expect-reject "wrong-hostname rejected"
                   'tls-certificate-hostname-error
                   (lambda () (validate-chain (list leaf int) store "evil.example")))

    ;; 5. Tampered signature: flip a byte in the leaf's signature.
    (let* ((bad-der (copy-seq (certificate-raw leaf)))
           (tampered nil))
      ;; flip the last byte of the DER (inside the signatureValue BIT STRING)
      (setf (aref bad-der (1- (length bad-der)))
            (logxor (aref bad-der (1- (length bad-der))) 1))
      (setf tampered (parse-certificate bad-der))
      (expect-reject "tampered leaf signature rejected (bad-signature)"
                     'tls-certificate-bad-signature-error
                     (lambda () (validate-chain (list tampered int) store host)))
      ;; and the low-level check must also reject it
      (if (verify-cert-signature tampered int)
          (progn (incf *fail*)
                 (format t "  FAIL tampered sig accepted by verify-cert-signature~%"))
          (progn (incf *pass*)
                 (format t "  PASS tampered sig rejected by verify-cert-signature~%"))))

    ;; 6. An issuer not marked CA must not be usable to sign a child: take the
    ;;    good chain but strip the intermediate's basicConstraints CA:TRUE.
    (expect-reject "non-CA issuer rejected"
                   'tls-certificate-error
                   (lambda ()
                     (let ((int* (neg-cert *neg-int-pem*)))
                       (setf (certificate-ca-p int*) nil)
                       (validate-chain (list leaf int*) store host)))))

  (format t "==== negative cases: ~d passed, ~d failed ====~%" *pass* *fail*)
  *fail*)
