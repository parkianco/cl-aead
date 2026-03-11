;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; Package definition for cl-aead

(defpackage #:cl-aead
  (:use #:cl)
  (:export
   ;; Constants
   #:+chacha20-block-size+
   #:+chacha20-key-size+
   #:+chacha20-nonce-size+
   #:+xchacha20-nonce-size+
   #:+poly1305-tag-size+
   #:+aes-gcm-nonce-size+
   #:+aes-gcm-tag-size+

   ;; ChaCha20-Poly1305 AEAD
   #:chacha20-poly1305-encrypt
   #:chacha20-poly1305-decrypt

   ;; XChaCha20-Poly1305 AEAD
   #:xchacha20-poly1305-encrypt
   #:xchacha20-poly1305-decrypt

   ;; AES-256-GCM AEAD
   #:aes256-gcm-encrypt
   #:aes256-gcm-decrypt

   ;; High-level API
   #:aead-encrypt
   #:aead-decrypt

   ;; Nonce generation
   #:generate-random-nonce

   ;; Constant-time operations
   #:ct-bytes=

   ;; Utilities
   #:hex-to-bytes
   #:bytes-to-hex
   #:string-to-octets
   #:ensure-byte-vector))

(defpackage #:cl-aead-test
  (:use #:cl)
  (:export #:run-all-tests))
